"""Okta Identity Cloud API emulation.

Mimics the Okta REST API so Joti's Okta connector can execute
SOAR identity actions against the simulation.

Key endpoints:
  POST /oauth2/v1/token            OAuth2 Client Credentials grant
  GET  /api/v1/users               list/search users
  GET  /api/v1/users/{id}          get user
  POST /api/v1/users/{id}/lifecycle/deactivate
  POST /api/v1/users/{id}/lifecycle/activate
  POST /api/v1/users/{id}/lifecycle/resetPassword
  POST /api/v1/users/{id}/sessions/me/lifecycle/delete  (revoke all sessions)
  DELETE /api/v1/users/{id}/factors/{factorId}          clear MFA factor
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Header, Query

from backend.engine.action_executor import execute_action

router = APIRouter(prefix="/api/vendor/okta", tags=["vendor:okta"])

_FAKE_TOKEN = "okta-sim-" + uuid.uuid4().hex[:20]

_SIMULATED_USERS = [
    {"id": "00u1a2b3c4d5e6f7g001", "login": "jsmith@corp.local", "email": "jsmith@corp.local",
     "firstName": "John", "lastName": "Smith", "status": "ACTIVE",
     "department": "Engineering", "title": "Senior Engineer"},
    {"id": "00u1a2b3c4d5e6f7g002", "login": "agarcia@corp.local", "email": "agarcia@corp.local",
     "firstName": "Ana", "lastName": "Garcia", "status": "ACTIVE",
     "department": "Security", "title": "SOC Analyst"},
    {"id": "00u1a2b3c4d5e6f7g003", "login": "svc_backup@corp.local", "email": "svc_backup@corp.local",
     "firstName": "Service", "lastName": "Backup", "status": "ACTIVE",
     "department": "IT", "title": "Service Account"},
    {"id": "00u1a2b3c4d5e6f7g004", "login": "admin@corp.local", "email": "admin@corp.local",
     "firstName": "Domain", "lastName": "Admin", "status": "ACTIVE",
     "department": "IT", "title": "Domain Administrator"},
]

# In-memory user state overrides (status changes from SOAR actions)
_user_states: dict[str, str] = {}


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _enrich(user: dict) -> dict:
    u = dict(user)
    u["status"] = _user_states.get(u["id"], u["status"])
    u["created"] = "2024-01-15T08:00:00.000Z"
    u["lastLogin"] = "2026-06-04T08:30:00.000Z"
    u["profile"] = {
        "login": u.pop("login"), "email": u.pop("email"),
        "firstName": u.pop("firstName"), "lastName": u.pop("lastName"),
        "department": u.pop("department", ""), "title": u.pop("title", ""),
    }
    return u


@router.post("/oauth2/v1/token")
async def get_token():
    return {
        "access_token": _FAKE_TOKEN,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "okta.users.manage okta.sessions.manage",
    }


@router.get("/api/v1/users")
async def list_users(
    q: Optional[str] = Query(None, description="Search by name or email"),
    filter: Optional[str] = Query(None),
    limit: int = Query(50),
    session_id: Optional[str] = Query(None),
):
    users = _SIMULATED_USERS
    if q:
        q_lower = q.lower()
        users = [u for u in users if q_lower in u["login"].lower() or
                 q_lower in u["firstName"].lower() or q_lower in u["lastName"].lower()]
    return [_enrich(u) for u in users[:limit]]


@router.get("/api/v1/users/{user_id}")
async def get_user(user_id: str):
    for u in _SIMULATED_USERS:
        if u["id"] == user_id or u["login"].split("@")[0] == user_id:
            return _enrich(u)
    return {"errorCode": "E0000007", "errorSummary": "Not found: Resource not found.", "id": user_id}


@router.post("/api/v1/users/{user_id}/lifecycle/deactivate")
async def deactivate_user(user_id: str, session_id: Optional[str] = Query(None)):
    _user_states[user_id] = "DEPROVISIONED"
    if session_id:
        await execute_action(session_id, "disable_account",
                             {"username": user_id, "actor": "okta_api"})
    return {}  # Okta returns 200 empty on success


@router.post("/api/v1/users/{user_id}/lifecycle/activate")
async def activate_user(user_id: str, session_id: Optional[str] = Query(None)):
    _user_states[user_id] = "ACTIVE"
    if session_id:
        await execute_action(session_id, "enable_account",
                             {"username": user_id, "actor": "okta_api"})
    return {"activationToken": uuid.uuid4().hex}


@router.post("/api/v1/users/{user_id}/lifecycle/suspend")
async def suspend_user(user_id: str, session_id: Optional[str] = Query(None)):
    _user_states[user_id] = "SUSPENDED"
    if session_id:
        await execute_action(session_id, "disable_account",
                             {"username": user_id, "actor": "okta_api"})
    return {}


@router.post("/api/v1/users/{user_id}/lifecycle/unsuspend")
async def unsuspend_user(user_id: str, session_id: Optional[str] = Query(None)):
    _user_states[user_id] = "ACTIVE"
    if session_id:
        await execute_action(session_id, "enable_account",
                             {"username": user_id, "actor": "okta_api"})
    return {}


@router.post("/api/v1/users/{user_id}/lifecycle/resetPassword")
async def reset_password(user_id: str, session_id: Optional[str] = Query(None)):
    if session_id:
        await execute_action(session_id, "reset_password",
                             {"username": user_id, "actor": "okta_api"})
    return {
        "resetPasswordUrl": f"https://corp.okta.com/reset/{uuid.uuid4().hex}",
        "expiresAt": "2026-06-05T23:26:25.000Z",
    }


@router.delete("/api/v1/users/{user_id}/sessions")
async def clear_sessions(user_id: str, session_id: Optional[str] = Query(None)):
    """Revoke all active sessions for a user."""
    return {}


@router.get("/api/v1/users/{user_id}/factors")
async def list_factors(user_id: str):
    return [
        {"id": f"fct{uuid.uuid4().hex[:10]}", "factorType": "token:software:totp",
         "provider": "GOOGLE", "status": "ACTIVE",
         "created": "2024-02-01T10:00:00.000Z"},
    ]


@router.delete("/api/v1/users/{user_id}/factors/{factor_id}")
async def delete_factor(user_id: str, factor_id: str):
    return {}
