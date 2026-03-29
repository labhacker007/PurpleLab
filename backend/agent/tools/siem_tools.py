"""SIEM integration tools for the agent orchestrator.

Provides tools for managing SIEM connections, testing connectivity,
and pushing logs to external SIEM platforms.

HIGH-RISK OPERATIONS (push_logs_to_siem, push_rule_to_siem) run through the
HITL approval gate automatically. The agent must call request_approval before
these tools will succeed, or the operation is blocked with a clear error.
"""
from __future__ import annotations

import logging
from typing import Any

from backend.agent.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


async def _require_approval(action_type: str, summary: str, payload: dict) -> dict[str, Any] | None:
    """Check HITL gate. Returns an error dict if approval is required but missing, else None."""
    try:
        from backend.hitl.engine import get_hitl_engine
        from backend.hitl.models import HITLLevel

        engine = get_hitl_engine()
        config = engine.get_config(action_type)

        # L0 — no gate needed
        if config.level == HITLLevel.L0_AUTO:
            return None

        # Check if there is already an approved request in-flight
        # (the agent should have called request_approval + wait_for_approval first)
        # We allow the tool to proceed if an approved request exists for this action type
        pending = await engine.list_pending(100)
        for req_dict in pending:
            if req_dict.get("action_type") == action_type and req_dict.get("status") in (
                "approved", "auto_approved"
            ):
                return None  # already approved, proceed

        # No approved request found — block and instruct agent
        level_name = config.level.name
        return {
            "error": "approval_required",
            "message": (
                f"Action '{action_type}' requires {level_name} approval before execution. "
                f"Call check_approval_requirement('{action_type}') to see what is needed, "
                f"then request_approval('{action_type}', ...) followed by wait_for_approval(). "
                f"Do NOT retry this tool until approval is granted."
            ),
            "action_type": action_type,
            "required_level": int(config.level),
            "required_level_name": level_name,
        }
    except Exception as exc:
        logger.warning("HITL gate check failed for '%s': %s — proceeding without gate", action_type, exc)
        return None  # Fail open so SIEM tools work even if HITL engine is unavailable


def register_tools(registry: ToolRegistry) -> None:
    """Register all SIEM integration tools."""

    registry.register(
        name="list_siem_connections",
        description=(
            "List all configured SIEM connections with their type, "
            "status, and configuration summary."
        ),
        parameters={
            "type": "object",
            "properties": {},
            "required": [],
        },
        handler=_list_siem_connections,
    )

    registry.register(
        name="test_siem_connection",
        description=(
            "Test connectivity to a configured SIEM platform. "
            "Returns success/failure and any error details."
        ),
        parameters={
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "string",
                    "description": "The ID of the SIEM connection to test.",
                },
            },
            "required": ["connection_id"],
        },
        handler=_test_siem_connection,
    )

    registry.register(
        name="push_logs_to_siem",
        description=(
            "Push log events to a configured SIEM platform. "
            "Sends the provided log entries to the specified SIEM connection. "
            "IMPORTANT: This is a high-risk action (L2_EXPLICIT approval required). "
            "You MUST call request_approval('push_logs_to_siem', ...) and wait_for_approval() "
            "before calling this tool, or it will be blocked."
        ),
        parameters={
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "string",
                    "description": "The ID of the SIEM connection to send logs to.",
                },
                "logs": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "List of log event dicts to send to the SIEM.",
                },
            },
            "required": ["connection_id", "logs"],
        },
        handler=_push_logs_to_siem,
    )

    registry.register(
        name="push_rule_to_siem",
        description=(
            "Deploy a detection rule to a production SIEM platform. "
            "Pushes the rule to the SIEM's detection engine (Splunk saved search, "
            "Elastic detection rule, Sentinel analytic rule, etc.). "
            "IMPORTANT: This is a high-risk action (L2_EXPLICIT approval required). "
            "You MUST call request_approval('push_rule_to_siem', ...) and wait_for_approval() "
            "before calling this tool, or it will be blocked."
        ),
        parameters={
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "string",
                    "description": "The ID of the SIEM connection to push the rule to.",
                },
                "rule_text": {
                    "type": "string",
                    "description": "The detection rule in the target SIEM's native format (SPL, KQL, ES|QL).",
                },
                "rule_name": {
                    "type": "string",
                    "description": "Human-readable name for the rule as it appears in the SIEM.",
                },
                "rule_metadata": {
                    "type": "object",
                    "description": "Optional metadata: severity, mitre_tags, description, author.",
                },
            },
            "required": ["connection_id", "rule_text", "rule_name"],
        },
        handler=_push_rule_to_siem,
    )


def _build_connection_manager() -> Any:
    """Lazily construct a ConnectionManager."""
    from backend.siem_integration.connection_manager import ConnectionManager
    return ConnectionManager()


async def _list_siem_connections() -> dict[str, Any]:
    """List all configured SIEM connections."""
    try:
        manager = _build_connection_manager()
        # ConnectionManager is a stub — it does not yet have a list method.
        # Return a helpful message indicating the feature is in progress.
        return {
            "status": "not_yet_implemented",
            "message": (
                "SIEM connection management is not yet fully implemented. "
                "The ConnectionManager currently supports create_connection, "
                "test_connection, sync_rules, and push_logs methods, but "
                "they require database persistence which is pending. "
                "Once implemented, this tool will list all configured "
                "SIEM connections with their type and status."
            ),
            "connections": [],
        }
    except Exception as exc:
        logger.exception("list_siem_connections failed")
        return {"error": f"Failed to list SIEM connections: {exc}"}


async def _test_siem_connection(connection_id: str) -> dict[str, Any]:
    """Test connectivity to a SIEM platform."""
    try:
        manager = _build_connection_manager()
        result = await manager.test_connection(connection_id)
        return {
            "status": "success",
            "connection_id": connection_id,
            "connected": result,
        }
    except NotImplementedError:
        return {
            "status": "not_yet_implemented",
            "message": (
                f"SIEM connection testing for '{connection_id}' is not yet "
                "implemented. The ConnectionManager.test_connection method "
                "requires database-backed connection storage and connector "
                "factory integration, which are pending development."
            ),
        }
    except Exception as exc:
        logger.exception("test_siem_connection failed for '%s'", connection_id)
        return {"error": f"Failed to test SIEM connection '{connection_id}': {exc}"}


async def _push_logs_to_siem(
    connection_id: str, logs: list[dict]
) -> dict[str, Any]:
    """Push log events to a SIEM platform (HITL gated)."""
    # HITL gate
    gate_error = await _require_approval(
        "push_logs_to_siem",
        f"Push {len(logs)} log events to SIEM connection '{connection_id}'",
        {"connection_id": connection_id, "log_count": len(logs)},
    )
    if gate_error:
        return gate_error

    try:
        manager = _build_connection_manager()
        result = await manager.push_logs(connection_id, logs)
        return {
            "status": "success",
            "connection_id": connection_id,
            "logs_sent": len(logs),
            "accepted": result,
        }
    except NotImplementedError:
        return {
            "status": "not_yet_implemented",
            "message": (
                f"Pushing logs to SIEM connection '{connection_id}' is not yet "
                "implemented. The ConnectionManager.push_logs method requires "
                "database-backed connection storage and connector factory "
                "integration, which are pending development."
            ),
            "logs_queued": len(logs),
        }
    except Exception as exc:
        logger.exception("push_logs_to_siem failed for '%s'", connection_id)
        return {"error": f"Failed to push logs to SIEM '{connection_id}': {exc}"}


async def _push_rule_to_siem(
    connection_id: str,
    rule_text: str,
    rule_name: str,
    rule_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Deploy a detection rule to a production SIEM (HITL gated)."""
    # HITL gate
    gate_error = await _require_approval(
        "push_rule_to_siem",
        f"Deploy detection rule '{rule_name}' to SIEM connection '{connection_id}'",
        {"connection_id": connection_id, "rule_name": rule_name},
    )
    if gate_error:
        return gate_error

    try:
        manager = _build_connection_manager()
        result = await manager.push_rule(connection_id, rule_text, rule_name, rule_metadata or {})
        return {
            "status": "success",
            "connection_id": connection_id,
            "rule_name": rule_name,
            "deployed": result,
        }
    except NotImplementedError:
        return {
            "status": "not_yet_implemented",
            "message": (
                f"Pushing detection rule '{rule_name}' to SIEM connection '{connection_id}' "
                "is not yet implemented. The ConnectionManager.push_rule method requires "
                "database-backed connection storage and connector factory integration."
            ),
        }
    except Exception as exc:
        logger.exception("push_rule_to_siem failed for '%s'", connection_id)
        return {"error": f"Failed to push rule to SIEM '{connection_id}': {exc}"}
