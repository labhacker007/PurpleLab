"""HITL (Human-in-the-Loop) approval API — v2.

Endpoints for managing approval requests, responding to them,
and configuring per-action approval levels.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/hitl", tags=["hitl"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ApprovalConfigRequest(BaseModel):
    action_type: str
    level: int = Field(..., ge=0, le=3, description="0=auto, 1=soft, 2=explicit, 3=multi-party")
    description: str = ""
    auto_approve_after_seconds: int | None = None
    required_approvals: int = Field(1, ge=1, le=10)
    timeout_seconds: int = Field(3600, ge=60)
    slack_channel: str = ""
    slack_user_ids: list[str] = Field(default_factory=list)
    email_addresses: list[str] = Field(default_factory=list)
    pagerduty_routing_key: str = ""
    webhook_url: str = ""


class ReviewRequest(BaseModel):
    reviewed_by: str = Field("reviewer", description="Reviewer identifier/email")
    note: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/pending")
async def list_pending_requests(limit: int = Query(50, ge=1, le=200)):
    """List all pending HITL approval requests."""
    from backend.hitl.engine import get_hitl_engine
    engine = get_hitl_engine()
    return {"requests": await engine.list_pending(limit)}


@router.post("/request")
async def create_approval_request(
    action_type: str,
    requested_by: str = "api",
    payload: dict = None,
):
    """Manually create an approval request (for testing)."""
    from backend.hitl.engine import get_hitl_engine
    engine = get_hitl_engine()
    req = await engine.request(
        action_type=action_type,
        payload=payload or {},
        requested_by=requested_by,
    )
    return req.to_dict()


@router.get("/requests/{request_id}")
async def get_request(request_id: str):
    """Get the status of an approval request."""
    from backend.hitl.engine import get_hitl_engine
    engine = get_hitl_engine()
    req = await engine._load_from_db(request_id)
    if not req:
        raise HTTPException(404, detail=f"Request '{request_id}' not found.")
    return req.to_dict()


@router.post("/requests/{request_id}/approve")
async def approve_request(request_id: str, body: ReviewRequest):
    """Approve a pending HITL request."""
    from backend.hitl.engine import get_hitl_engine
    engine = get_hitl_engine()
    req = await engine.approve(request_id, body.reviewed_by, body.note)
    if not req:
        raise HTTPException(404, detail=f"Request '{request_id}' not found.")
    return req.to_dict()


@router.post("/requests/{request_id}/reject")
async def reject_request(request_id: str, body: ReviewRequest):
    """Reject a pending HITL request."""
    from backend.hitl.engine import get_hitl_engine
    engine = get_hitl_engine()
    req = await engine.reject(request_id, body.reviewed_by, body.note)
    if not req:
        raise HTTPException(404, detail=f"Request '{request_id}' not found.")
    return req.to_dict()


@router.get("/approve/{token}")
async def approve_via_magic_link(token: str):
    """Magic Link approval endpoint — validate token and approve."""
    from backend.hitl.engine import get_hitl_engine
    from fastapi.responses import HTMLResponse
    engine = get_hitl_engine()
    req = await engine.approve_via_magic_link(token)
    if not req:
        return HTMLResponse(
            content=_html_page("Invalid or Expired Link",
                               "This approval link is invalid, expired, or already used.",
                               success=False),
            status_code=400,
        )
    return HTMLResponse(
        content=_html_page(
            "Approved",
            f"Action '{req.action_type}' has been approved. You can close this tab.",
            success=True,
        )
    )


@router.get("/reject/{token}")
async def reject_via_magic_link(token: str, note: str = ""):
    """Magic Link rejection endpoint."""
    from backend.hitl.engine import get_hitl_engine
    from fastapi.responses import HTMLResponse
    engine = get_hitl_engine()
    request_id = await engine._lookup_magic_link(token)
    if not request_id:
        return HTMLResponse(
            content=_html_page("Invalid Link", "This link is invalid or expired.", success=False),
            status_code=400,
        )
    req = await engine.reject(request_id, "magic_link", note or "Rejected via Magic Link")
    return HTMLResponse(
        content=_html_page(
            "Rejected",
            f"Action '{req.action_type}' has been rejected.",
            success=False,
        )
    )


# ---------------------------------------------------------------------------
# Config management
# ---------------------------------------------------------------------------

@router.get("/config")
async def list_action_configs():
    """List HITL configuration for all action types."""
    from backend.hitl.engine import get_hitl_engine
    engine = get_hitl_engine()
    configs = engine.list_configs()
    return {
        "configs": [c.to_dict() for c in configs],
        "levels": {
            0: {"name": "L0_AUTO", "description": "Auto-approve — no human needed"},
            1: {"name": "L1_SOFT", "description": "Soft prompt — proceed unless objected"},
            2: {"name": "L2_EXPLICIT", "description": "Explicit approval required via Magic Link/Slack"},
            3: {"name": "L3_MULTI_PARTY", "description": "Multiple approvals from different reviewers"},
        },
    }


@router.put("/config/{action_type}")
async def update_action_config(action_type: str, body: ApprovalConfigRequest):
    """Update HITL level and notification config for an action type."""
    from backend.hitl.engine import get_hitl_engine
    from backend.hitl.models import HITLLevel, ActionConfig, NotificationChannels
    engine = get_hitl_engine()

    config = ActionConfig(
        action_type=action_type,
        level=HITLLevel(body.level),
        description=body.description,
        notifications=NotificationChannels(
            slack_channel=body.slack_channel,
            slack_user_ids=body.slack_user_ids,
            email_addresses=body.email_addresses,
            pagerduty_routing_key=body.pagerduty_routing_key,
            webhook_url=body.webhook_url,
        ),
        auto_approve_after_seconds=body.auto_approve_after_seconds,
        required_approvals=body.required_approvals,
        timeout_seconds=body.timeout_seconds,
    )
    result = await engine.set_config(config)
    return result.to_dict()


# ---------------------------------------------------------------------------
# HTML helper for Magic Link pages
# ---------------------------------------------------------------------------

def _html_page(title: str, message: str, success: bool) -> str:
    color = "#22c55e" if success else "#ef4444"
    icon = "✅" if success else "❌"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PurpleLab — {title}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #0f172a; color: #e2e8f0;
      min-height: 100vh; display: flex; align-items: center; justify-content: center;
    }}
    .card {{
      background: #1e293b; border: 1px solid #334155;
      border-radius: 12px; padding: 48px; max-width: 480px; text-align: center;
    }}
    .icon {{ font-size: 48px; margin-bottom: 16px; }}
    h1 {{ font-size: 24px; color: {color}; margin-bottom: 12px; }}
    p {{ color: #94a3b8; line-height: 1.6; }}
    .brand {{ margin-top: 32px; font-size: 12px; color: #475569; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">{icon}</div>
    <h1>{title}</h1>
    <p>{message}</p>
    <div class="brand">PurpleLab · Purple Team Simulation Platform</div>
  </div>
</body>
</html>"""
