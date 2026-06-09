"""Microsoft Entra ID (Azure AD) API emulation.

Mimics the Microsoft Graph API + Entra ID OIDC token endpoint so
Joti's Entra / Azure AD connector can execute identity SOAR actions.

Key endpoints:
  POST /{tenant}/oauth2/v2.0/token    OAuth2 Client Credentials
  GET  /v1.0/users                    list/search users
  GET  /v1.0/users/{id}               get user
  PATCH /v1.0/users/{id}              update (accountEnabled)
  POST /v1.0/users/{id}/revokeSignInSessions
  POST /v1.0/users/{id}/authentication/methods/{id}/disable
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Query

from backend.engine.action_executor import execute_action

router = APIRouter(prefix="/api/vendor/entra", tags=["vendor:entra_id"])

_FAKE_TOKEN = "ent-sim-" + uuid.uuid4().hex[:20]

_SIMULATED_USERS = [
    {"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567801",
     "userPrincipalName": "jsmith@corp.onmicrosoft.com",
     "displayName": "John Smith", "givenName": "John", "surname": "Smith",
     "accountEnabled": True, "department": "Engineering",
     "jobTitle": "Senior Engineer", "mail": "jsmith@corp.local"},
    {"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567802",
     "userPrincipalName": "agarcia@corp.onmicrosoft.com",
     "displayName": "Ana Garcia", "givenName": "Ana", "surname": "Garcia",
     "accountEnabled": True, "department": "Security",
     "jobTitle": "SOC Analyst", "mail": "agarcia@corp.local"},
    {"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567803",
     "userPrincipalName": "svc_backup@corp.onmicrosoft.com",
     "displayName": "Service Backup", "givenName": "Service", "surname": "Backup",
     "accountEnabled": True, "department": "IT",
     "jobTitle": "Service Account", "mail": "svc_backup@corp.local"},
]

_user_states: dict[str, bool] = {}  # id -> accountEnabled override


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _enrich(u: dict) -> dict:
    out = dict(u)
    if u["id"] in _user_states:
        out["accountEnabled"] = _user_states[u["id"]]
    out["createdDateTime"] = "2024-01-15T08:00:00Z"
    out["lastSignInDateTime"] = "2026-06-04T08:30:00Z"
    return out


# ── Auth ──────────────────────────────────────────────────────────────────────

@router.post("/{tenant_id}/oauth2/v2.0/token")
async def get_token(tenant_id: str):
    return {
        "token_type": "Bearer",
        "access_token": _FAKE_TOKEN,
        "expires_in": 3599,
        "scope": "https://graph.microsoft.com/.default",
    }


# ── Users ─────────────────────────────────────────────────────────────────────

@router.get("/v1.0/users")
async def list_users(
    search: Optional[str] = Query(None, alias="$search"),
    filter: Optional[str] = Query(None, alias="$filter"),
    top: int = Query(50, alias="$top"),
    session_id: Optional[str] = Query(None),
):
    users = _SIMULATED_USERS
    if search:
        s = search.strip('"').lower()
        users = [u for u in users if s in u["displayName"].lower() or s in u["userPrincipalName"].lower()]
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
            "value": [_enrich(u) for u in users[:top]]}


@router.get("/v1.0/users/{user_id}")
async def get_user(user_id: str):
    for u in _SIMULATED_USERS:
        if u["id"] == user_id or u["userPrincipalName"].split("@")[0] == user_id:
            return _enrich(u)
    return {"error": {"code": "Request_ResourceNotFound",
                      "message": f"Resource '{user_id}' does not exist."}}


@router.patch("/v1.0/users/{user_id}")
async def update_user(
    user_id: str,
    body: dict = Body(default={}),
    session_id: Optional[str] = Query(None),
):
    """Patch user properties — used to disable/enable account (accountEnabled)."""
    if "accountEnabled" in body:
        _user_states[user_id] = bool(body["accountEnabled"])
        if session_id:
            action = "enable_account" if body["accountEnabled"] else "disable_account"
            await execute_action(session_id, action, {"username": user_id, "actor": "entra_api"})
    return {}  # Graph PATCH returns 204 No Content


@router.post("/v1.0/users/{user_id}/revokeSignInSessions")
async def revoke_sessions(user_id: str, session_id: Optional[str] = Query(None)):
    """Revoke all active sign-in sessions and refresh tokens."""
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#Edm.Boolean",
            "value": True}


@router.post("/v1.0/users/{user_id}/authentication/methods/{method_id}/disable")
async def disable_auth_method(user_id: str, method_id: str):
    return {}


# ── Conditional Access (read-only emulation) ──────────────────────────────────

@router.get("/v1.0/identity/conditionalAccess/policies")
async def list_ca_policies():
    return {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies",
        "value": [
            {"id": str(uuid.uuid4()), "displayName": "Require MFA for All Users",
             "state": "enabled", "createdDateTime": "2024-01-01T00:00:00Z"},
        ],
    }


# ── Sign-in risk (read-only) ───────────────────────────────────────────────────

@router.get("/v1.0/identityProtection/riskyUsers")
async def get_risky_users(top: int = Query(20, alias="$top")):
    return {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#riskyUsers",
        "value": [
            {"id": u["id"], "userPrincipalName": u["userPrincipalName"],
             "riskLevel": "high", "riskState": "atRisk",
             "riskLastUpdatedDateTime": _ts()}
            for u in _SIMULATED_USERS[:1]
        ],
    }
