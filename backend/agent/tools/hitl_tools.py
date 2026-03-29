"""HITL (Human-in-the-Loop) tools for the agent orchestrator.

These tools allow the agent to:
  1. Check what approval level an action requires before attempting it
  2. Request human approval and wait for the decision
  3. Check the status of an outstanding approval request

The agent MUST call ``request_approval`` before executing any action that
has an approval level > L0_AUTO. The orchestrator enforces this by checking
the approval gate at the tool-call boundary via the HITL engine.
"""
from __future__ import annotations

import logging
from typing import Any

from backend.agent.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


def register_tools(registry: ToolRegistry) -> None:
    """Register all HITL tools."""

    registry.register(
        name="check_approval_requirement",
        description=(
            "Check what approval level is required before executing an action. "
            "Call this BEFORE attempting any potentially sensitive operation. "
            "Returns the approval level (0=auto, 1=soft prompt, 2=explicit approval, "
            "3=multi-party approval) and whether a human needs to be notified."
        ),
        parameters={
            "type": "object",
            "properties": {
                "action_type": {
                    "type": "string",
                    "description": (
                        "The action you want to perform. Known types: "
                        "generate_attack_logs, run_attack_chain, push_logs_to_siem, "
                        "push_rule_to_siem, sync_rules_from_siem, research_threat_actor, "
                        "import_detection_rules, delete_detection_rules, "
                        "create_environment, delete_environment, save_to_knowledge_base."
                    ),
                },
            },
            "required": ["action_type"],
        },
        handler=_check_approval_requirement,
    )

    registry.register(
        name="request_approval",
        description=(
            "Request human approval for a sensitive action. The system will notify "
            "the configured reviewers via Slack/email/PagerDuty and generate a "
            "Magic Link for one-click approval/rejection. "
            "Returns immediately with a pending request ID. "
            "For L0 (auto) actions, approval is granted immediately. "
            "For L1 (soft prompt), returns pending but will auto-approve after a short grace period. "
            "For L2/L3, the action MUST wait for human approval via wait_for_approval."
        ),
        parameters={
            "type": "object",
            "properties": {
                "action_type": {
                    "type": "string",
                    "description": "The action type requiring approval (same values as check_approval_requirement).",
                },
                "action_summary": {
                    "type": "string",
                    "description": "Human-readable description of exactly what you intend to do. Be specific.",
                },
                "action_payload": {
                    "type": "object",
                    "description": "Key details about the action (e.g., SIEM connection ID, rule name, environment ID).",
                },
            },
            "required": ["action_type", "action_summary"],
        },
        handler=_request_approval,
    )

    registry.register(
        name="wait_for_approval",
        description=(
            "Wait for a pending approval request to be resolved. "
            "Blocks until the human approves, rejects, or the request times out. "
            "Use this after request_approval when the approval level is L2 or L3. "
            "For L0/L1, calling this is optional (the request is often already resolved). "
            "Returns 'approved', 'rejected', or 'expired' with reviewer notes."
        ),
        parameters={
            "type": "object",
            "properties": {
                "request_id": {
                    "type": "string",
                    "description": "The approval request ID returned by request_approval.",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Maximum seconds to wait (default: use the action's configured timeout). Max: 3600.",
                    "minimum": 10,
                    "maximum": 3600,
                },
            },
            "required": ["request_id"],
        },
        handler=_wait_for_approval,
    )

    registry.register(
        name="get_approval_status",
        description=(
            "Get the current status of an approval request without blocking. "
            "Useful for checking if a previously submitted request has been resolved."
        ),
        parameters={
            "type": "object",
            "properties": {
                "request_id": {
                    "type": "string",
                    "description": "The approval request ID to check.",
                },
            },
            "required": ["request_id"],
        },
        handler=_get_approval_status,
    )

    registry.register(
        name="list_pending_approvals",
        description=(
            "List all currently pending approval requests across all action types. "
            "Useful when the user asks 'what is waiting for approval?' or "
            "'what needs my review?'"
        ),
        parameters={
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of requests to return (default: 20).",
                    "minimum": 1,
                    "maximum": 100,
                },
            },
            "required": [],
        },
        handler=_list_pending_approvals,
    )


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

async def _check_approval_requirement(action_type: str) -> dict[str, Any]:
    """Check the HITL level configured for an action type."""
    try:
        from backend.hitl.engine import get_hitl_engine
        from backend.hitl.models import HITLLevel

        engine = get_hitl_engine()
        config = engine.get_config(action_type)

        level_names = {
            HITLLevel.L0_AUTO: "L0_AUTO — action proceeds automatically, no human review needed",
            HITLLevel.L1_SOFT: "L1_SOFT — agent will notify reviewers; proceeds automatically after grace period unless objected",
            HITLLevel.L2_EXPLICIT: "L2_EXPLICIT — explicit human approval is REQUIRED before proceeding",
            HITLLevel.L3_MULTI_PARTY: "L3_MULTI_PARTY — multiple approvers are REQUIRED before proceeding",
        }

        level = config.level
        requires_wait = level >= HITLLevel.L2_EXPLICIT

        result: dict[str, Any] = {
            "action_type": action_type,
            "level": int(level),
            "level_name": level.name,
            "description": level_names.get(level, level.name),
            "requires_explicit_approval": requires_wait,
            "auto_approve_after_seconds": config.auto_approve_after_seconds,
            "required_approvals": config.required_approvals,
            "timeout_seconds": config.timeout_seconds,
            "notification_channels": config.notifications.to_dict(),
        }

        if level == HITLLevel.L0_AUTO:
            result["recommendation"] = "No approval needed. You may proceed directly."
        elif level == HITLLevel.L1_SOFT:
            result["recommendation"] = (
                f"Call request_approval to notify reviewers. "
                f"The action will auto-proceed after {config.auto_approve_after_seconds}s "
                f"unless a reviewer rejects it."
            )
        elif level == HITLLevel.L2_EXPLICIT:
            result["recommendation"] = (
                "Call request_approval, then wait_for_approval. "
                "Do NOT proceed until you receive an 'approved' status."
            )
        else:
            result["recommendation"] = (
                f"Call request_approval, then wait_for_approval. "
                f"Requires {config.required_approvals} approvals from different reviewers."
            )

        return result
    except Exception as exc:
        logger.exception("check_approval_requirement failed")
        return {"error": f"Failed to check approval requirement: {exc}"}


async def _request_approval(
    action_type: str,
    action_summary: str,
    action_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a HITL approval request."""
    try:
        from backend.hitl.engine import get_hitl_engine
        from backend.hitl.models import HITLLevel

        engine = get_hitl_engine()
        payload = action_payload or {}
        payload["summary"] = action_summary

        req = await engine.request(
            action_type=action_type,
            payload=payload,
            requested_by="agent",
        )

        result = req.to_dict()

        # Add guidance for the agent
        if req.level == HITLLevel.L0_AUTO:
            result["agent_instruction"] = (
                "Auto-approved. You may proceed with the action immediately."
            )
        elif req.level == HITLLevel.L1_SOFT:
            result["agent_instruction"] = (
                f"Soft approval requested. Reviewers notified. "
                f"You may call wait_for_approval (request_id={req.id}) or proceed "
                f"after {engine.get_config(action_type).auto_approve_after_seconds}s "
                f"if no rejection arrives. Inform the user that approval is pending."
            )
        else:
            result["agent_instruction"] = (
                f"Approval required. Call wait_for_approval(request_id='{req.id}') "
                f"and DO NOT proceed until status is 'approved'. "
                f"Inform the user that their approval is needed (Magic Link sent if configured)."
            )

        if req.magic_link_url:
            result["user_message"] = (
                f"I need your approval to proceed with **{action_type}**: {action_summary}\n\n"
                f"You can approve or reject using this link: {req.magic_link_url}"
            )

        return result
    except Exception as exc:
        logger.exception("request_approval failed")
        return {"error": f"Failed to create approval request: {exc}"}


async def _wait_for_approval(
    request_id: str,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """Wait for an approval request to be resolved."""
    try:
        from backend.hitl.engine import get_hitl_engine

        engine = get_hitl_engine()
        req = await engine.wait_for_approval(request_id, timeout_seconds)

        if not req:
            return {
                "status": "not_found",
                "request_id": request_id,
                "error": f"Request '{request_id}' not found.",
            }

        result = req.to_dict()
        result["request_id"] = request_id

        if req.is_approved:
            result["agent_instruction"] = "Approved. You may now proceed with the action."
        elif req.status == "rejected":
            result["agent_instruction"] = (
                f"Rejected by {req.reviewed_by}. "
                f"Reason: {req.review_note or 'No reason provided'}. "
                f"Do NOT proceed. Inform the user and ask if they want to adjust the action."
            )
        elif req.status == "expired":
            result["agent_instruction"] = (
                "Request expired before it was reviewed. "
                "Do NOT proceed. Inform the user and ask if they want to retry."
            )

        return result
    except TimeoutError:
        return {
            "status": "timeout",
            "request_id": request_id,
            "agent_instruction": (
                "Wait timed out. The approval request is still pending. "
                "Do NOT proceed. Inform the user that approval is still outstanding."
            ),
        }
    except Exception as exc:
        logger.exception("wait_for_approval failed")
        return {"error": f"Failed to wait for approval: {exc}"}


async def _get_approval_status(request_id: str) -> dict[str, Any]:
    """Get the current status of an approval request."""
    try:
        from backend.hitl.engine import get_hitl_engine

        engine = get_hitl_engine()
        req = await engine._load_from_db(request_id)

        if not req:
            return {
                "status": "not_found",
                "request_id": request_id,
            }

        return req.to_dict()
    except Exception as exc:
        logger.exception("get_approval_status failed")
        return {"error": f"Failed to get approval status: {exc}"}


async def _list_pending_approvals(limit: int = 20) -> dict[str, Any]:
    """List all pending approval requests."""
    try:
        from backend.hitl.engine import get_hitl_engine

        engine = get_hitl_engine()
        pending = await engine.list_pending(limit)

        return {
            "status": "success",
            "count": len(pending),
            "requests": pending,
            "message": (
                f"There are {len(pending)} pending approval request(s)."
                if pending
                else "No pending approval requests."
            ),
        }
    except Exception as exc:
        logger.exception("list_pending_approvals failed")
        return {"error": f"Failed to list pending approvals: {exc}"}
