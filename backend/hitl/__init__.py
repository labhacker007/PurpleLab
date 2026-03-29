"""Human-in-the-Loop (HITL) approval engine.

Every significant platform action can require human review before execution.
Admins configure the approval level per action type:

  L0 — Auto-approve (no human needed; optional grace-period countdown)
  L1 — Soft prompt (agent asks in-chat, engineer can type 'approve' or click)
  L2 — Explicit approval (Magic Link email + Slack DM; blocks until approved)
  L3 — Multi-party (requires N≥2 approvals from different reviewers)

Flow:
  1. Action requested (by agent or API)
  2. HITLEngine.request(action_type, payload) → HITLRequest
  3. If L0 → auto-approve immediately (or after grace period)
  4. If L1-L3 → send notifications, return pending request
  5. Reviewer clicks Magic Link / types in Slack / calls approve API
  6. HITLEngine marks approved/rejected, action proceeds or is cancelled
  7. Waiting caller is unblocked via asyncio.Event
"""
from backend.hitl.engine import HITLEngine, get_hitl_engine
from backend.hitl.models import (
    HITLRequest,
    HITLLevel,
    HITLStatus,
    ActionConfig,
    DEFAULT_ACTION_CONFIGS,
)

__all__ = [
    "HITLEngine",
    "get_hitl_engine",
    "HITLRequest",
    "HITLLevel",
    "HITLStatus",
    "ActionConfig",
    "DEFAULT_ACTION_CONFIGS",
]
