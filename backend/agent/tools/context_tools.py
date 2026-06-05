"""Context tools — agent-callable tools for updating sticky conversation context.

The agent calls ``save_context`` after significant actions to:
  - Record what environment / session / rules it's working with
  - Set suggested_followups so the UI can show actionable next-step chips
  - Update the goal label shown in the context bar

conv_id and conversation_manager are injected via a ContextVar set by
the orchestrator before each agentic loop iteration.
"""
from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from backend.agent.conversation import ConversationManager

log = logging.getLogger(__name__)

# Set by orchestrator before each run; tools read from here
_conv_id_var: ContextVar[str | None] = ContextVar("conv_id", default=None)
_conv_manager_var: ContextVar["ConversationManager | None"] = ContextVar(
    "conv_manager", default=None
)


def set_conversation_context(conv_id: str, manager: "ConversationManager") -> None:
    """Called by orchestrator before starting a new agentic turn."""
    _conv_id_var.set(conv_id)
    _conv_manager_var.set(manager)


async def _save_context(
    goal: str | None = None,
    environment_id: str | None = None,
    environment_name: str | None = None,
    active_session_id: str | None = None,
    session_ids: list[str] | None = None,
    rule_ids: list[str] | None = None,
    use_case_ids: list[str] | None = None,
    technique_ids: list[str] | None = None,
    suggested_followups: list[str] | None = None,
    **_,
) -> dict[str, Any]:
    """Save context state and suggested follow-up actions for the analyst."""
    conv_id = _conv_id_var.get()
    manager = _conv_manager_var.get()

    if not conv_id or not manager:
        return {"status": "skipped", "reason": "no_conversation_context"}

    patch: dict[str, Any] = {}
    if environment_id:
        patch["environment_id"] = environment_id
    if environment_name:
        patch["environment_name"] = environment_name
    if active_session_id:
        patch["active_session_id"] = active_session_id
    if suggested_followups is not None:
        patch["suggested_followups"] = suggested_followups

    # Build working_set patch
    ws: dict[str, list[str]] = {}
    if session_ids:
        ws["session_ids"] = session_ids
    if rule_ids:
        ws["rule_ids"] = rule_ids
    if use_case_ids:
        ws["use_case_ids"] = use_case_ids
    if technique_ids:
        ws["technique_ids"] = technique_ids
    if ws:
        patch["working_set"] = ws

    await manager.update_context(conv_id, patch, goal=goal)
    log.info("save_context: patched conv=%s keys=%s", conv_id, list(patch.keys()))
    return {"status": "saved", "keys_updated": list(patch.keys())}


def register_tools(registry) -> None:
    registry.register(
        name="save_context",
        description=(
            "Save your current working context and suggest follow-up actions for the analyst. "
            "Call this after completing significant actions (environment set up, scenario run, "
            "rule imported, etc.) to: persist environment/session/rule IDs across turns, "
            "and show the analyst 2-4 actionable next-step buttons. "
            "All parameters are optional — only pass what changed."
        ),
        parameters={
            "type": "object",
            "properties": {
                "goal": {
                    "type": "string",
                    "description": "Current workflow goal: red_team, detection_validation, tabletop, coverage, or free",
                    "enum": ["red_team", "detection_validation", "tabletop", "coverage", "free"]
                },
                "environment_id": {
                    "type": "string",
                    "description": "UUID of the active simulation environment"
                },
                "environment_name": {
                    "type": "string",
                    "description": "Human-readable name of the active environment"
                },
                "active_session_id": {
                    "type": "string",
                    "description": "UUID of the most recently run simulation session"
                },
                "session_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Session IDs to add to the working set"
                },
                "rule_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Detection rule IDs to add to the working set"
                },
                "use_case_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Detection use case IDs to add to the working set"
                },
                "technique_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "MITRE technique IDs (e.g. T1059.001) to add to the working set"
                },
                "suggested_followups": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "2-4 short follow-up action labels to show as clickable chips, e.g. ['Review alert gaps', 'Deploy to Splunk', 'Run tabletop for T1059']"
                }
            }
        },
        handler=_save_context,
    )
