"""Identity Simulation API — v2.

Emulates Okta / Microsoft Entra ID / Active Directory user management APIs.
Supports account lockout, disable, session revocation, MFA reset,
and password reset — all logged to containment_actions for audit.
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, or_

from backend.db.session import async_session
from backend.db.models import SimulatedUser, ContainmentAction

router = APIRouter(prefix="/identity", tags=["identity"])


# ── Request schemas ───────────────────────────────────────────────────────────

class UserActionRequest(BaseModel):
    reason: str = ""
    requester: str = "api"


class CreateUserRequest(BaseModel):
    username: str
    email: str
    display_name: Optional[str] = None
    department: Optional[str] = None
    title: Optional[str] = None
    identity_vendor: str = "okta"
    environment_id: Optional[str] = None


# ── Seed helpers ──────────────────────────────────────────────────────────────

_SEED_USERS = [
    ("jdoe", "john.doe@corp.local", "John Doe", "Finance", "CFO", "okta"),
    ("asmith", "alice.smith@corp.local", "Alice Smith", "Engineering", "Senior Engineer", "okta"),
    ("bjones", "bob.jones@corp.local", "Bob Jones", "IT", "Sysadmin", "entra"),
    ("cmiller", "carol.miller@corp.local", "Carol Miller", "Executive", "CEO", "okta"),
    ("dwilson", "dave.wilson@corp.local", "Dave Wilson", "Security", "SOC Analyst", "entra"),
    ("etaylor", "emily.taylor@corp.local", "Emily Taylor", "HR", "HR Manager", "okta"),
    ("fanderson", "frank.anderson@corp.local", "Frank Anderson", "Engineering", "DevOps Engineer", "entra"),
    ("gmartin", "grace.martin@corp.local", "Grace Martin", "Finance", "Accountant", "okta"),
    ("hthompson", "henry.thompson@corp.local", "Henry Thompson", "IT", "IT Director", "entra"),
    ("iwhite", "iris.white@corp.local", "Iris White", "Security", "CISO", "okta"),
    ("jharris", "james.harris@corp.local", "James Harris", "Engineering", "Intern", "okta"),
    ("svc-backup", "svc-backup@corp.local", "Backup Service Account", "IT", "Service Account", "entra"),
    ("svc-webapp", "svc-webapp@corp.local", "Web App Service Account", "Engineering", "Service Account", "entra"),
]


async def _ensure_seed_users(environment_id: Optional[uuid.UUID] = None):
    async with async_session() as session:
        q = select(func.count()).select_from(SimulatedUser)
        if environment_id:
            q = q.where(SimulatedUser.environment_id == environment_id)
        count = (await session.execute(q)).scalar() or 0

        if count == 0:
            for username, email, display_name, dept, title, vendor in _SEED_USERS:
                user = SimulatedUser(
                    id=uuid.uuid4(),
                    environment_id=environment_id,
                    username=username,
                    email=email,
                    display_name=display_name,
                    department=dept,
                    title=title,
                    identity_vendor=vendor,
                    status="active",
                    mfa_enrolled=True,
                    risk_level="low" if "svc-" not in username else "medium",
                    last_login=datetime.utcnow() - timedelta(hours=random.randint(1, 72)),
                    attributes={"samAccountName": username, "userPrincipalName": email},
                )
                session.add(user)
            await session.commit()


def _user_to_dict(u: SimulatedUser) -> dict[str, Any]:
    return {
        "id": str(u.id),
        "username": u.username,
        "email": u.email,
        "display_name": u.display_name,
        "department": u.department,
        "title": u.title,
        "identity_vendor": u.identity_vendor,
        "status": u.status,
        "mfa_enrolled": u.mfa_enrolled,
        "risk_level": u.risk_level,
        "last_login": u.last_login.isoformat() if u.last_login else None,
        "attributes": u.attributes or {},
        "environment_id": str(u.environment_id) if u.environment_id else None,
        "updated_at": u.updated_at.isoformat() if u.updated_at else None,
    }


def _log_action(
    action_type: str, user: SimulatedUser, requester: str, reason: str,
    detail: Optional[dict] = None,
) -> ContainmentAction:
    return ContainmentAction(
        id=uuid.uuid4(),
        environment_id=user.environment_id,
        action_type=action_type,
        target_type="user",
        target_value=user.email,
        target_id=str(user.id),
        requester=requester,
        reason=reason,
        status="success",
        result_detail=detail or {},
    )


async def _get_user(session, user_id: str) -> SimulatedUser:
    try:
        uid = uuid.UUID(user_id)
        q = select(SimulatedUser).where(SimulatedUser.id == uid)
    except ValueError:
        q = select(SimulatedUser).where(
            or_(
                SimulatedUser.username.ilike(f"%{user_id}%"),
                SimulatedUser.email.ilike(f"%{user_id}%"),
            )
        )
    user = (await session.execute(q)).scalar_one_or_none()
    if not user:
        raise HTTPException(404, f"User '{user_id}' not found")
    return user


# ── List / Get users ──────────────────────────────────────────────────────────

@router.get("/users")
async def list_users(
    status: Optional[str] = None,
    identity_vendor: Optional[str] = None,
    department: Optional[str] = None,
    risk_level: Optional[str] = None,
    environment_id: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = 0,
):
    """List all simulated directory users."""
    await _ensure_seed_users()

    async with async_session() as session:
        q = select(SimulatedUser).order_by(SimulatedUser.username)
        if status:
            q = q.where(SimulatedUser.status == status)
        if identity_vendor:
            q = q.where(SimulatedUser.identity_vendor == identity_vendor)
        if department:
            q = q.where(SimulatedUser.department.ilike(f"%{department}%"))
        if risk_level:
            q = q.where(SimulatedUser.risk_level == risk_level)
        if environment_id:
            try:
                q = q.where(SimulatedUser.environment_id == uuid.UUID(environment_id))
            except ValueError:
                raise HTTPException(400, "Invalid environment_id UUID")
        if search:
            q = q.where(or_(
                SimulatedUser.username.ilike(f"%{search}%"),
                SimulatedUser.email.ilike(f"%{search}%"),
                SimulatedUser.display_name.ilike(f"%{search}%"),
            ))
        total = (await session.execute(
            select(func.count()).select_from(q.subquery())
        )).scalar() or 0
        users = (await session.execute(q.offset(offset).limit(limit))).scalars().all()

    return {"users": [_user_to_dict(u) for u in users], "total": total, "offset": offset, "limit": limit}


@router.get("/users/{user_id}")
async def get_user(user_id: str):
    """Get details for a specific simulated user."""
    await _ensure_seed_users()
    async with async_session() as session:
        user = await _get_user(session, user_id)
        return _user_to_dict(user)


# ── Containment actions ───────────────────────────────────────────────────────

@router.post("/users/{user_id}/lock")
async def lock_user(user_id: str, req: UserActionRequest):
    """Lock a user account (Okta lock / AD account lockout).

    Prevents the user from authenticating. Simulates account lockout
    as seen in response to credential-based attacks.
    """
    await _ensure_seed_users()
    async with async_session() as session:
        user = await _get_user(session, user_id)
        if user.status == "locked":
            raise HTTPException(409, f"User '{user.username}' is already locked")
        if user.status == "disabled":
            raise HTTPException(409, f"User '{user.username}' is disabled (use enable first)")

        prev_status = user.status
        user.status = "locked"
        user.updated_at = datetime.utcnow()

        action = _log_action(
            "lock_user", user, req.requester, req.reason or "Account locked by security response",
            {"previous_status": prev_status, "username": user.username},
        )
        session.add(action)
        await session.commit()

    return {
        "success": True, "action_id": str(action.id),
        "user_id": str(user.id), "username": user.username,
        "email": user.email, "previous_status": prev_status, "current_status": "locked",
        "message": f"Account {user.username} locked successfully",
        "timestamp": action.executed_at.isoformat(),
    }


@router.delete("/users/{user_id}/lock")
async def unlock_user(user_id: str, requester: str = "api", reason: str = ""):
    """Unlock a user account."""
    await _ensure_seed_users()
    async with async_session() as session:
        user = await _get_user(session, user_id)
        if user.status != "locked":
            raise HTTPException(409, f"User '{user.username}' is not locked (status: {user.status})")
        user.status = "active"
        user.updated_at = datetime.utcnow()
        action = _log_action("unlock_user", user, requester, reason or "Account unlocked", {"username": user.username})
        session.add(action)
        await session.commit()
    return {"success": True, "action_id": str(action.id), "username": user.username, "current_status": "active"}


@router.post("/users/{user_id}/disable")
async def disable_user(user_id: str, req: UserActionRequest):
    """Disable a user account (full deactivation, stronger than lock)."""
    await _ensure_seed_users()
    async with async_session() as session:
        user = await _get_user(session, user_id)
        if user.status == "disabled":
            raise HTTPException(409, f"User '{user.username}' is already disabled")
        prev_status = user.status
        user.status = "disabled"
        user.updated_at = datetime.utcnow()
        action = _log_action(
            "disable_user", user, req.requester, req.reason or "Account disabled",
            {"previous_status": prev_status},
        )
        session.add(action)
        await session.commit()
    return {
        "success": True, "action_id": str(action.id),
        "username": user.username, "previous_status": prev_status, "current_status": "disabled",
    }


@router.post("/users/{user_id}/enable")
async def enable_user(user_id: str, req: UserActionRequest):
    """Re-enable a disabled or suspended user account."""
    await _ensure_seed_users()
    async with async_session() as session:
        user = await _get_user(session, user_id)
        if user.status == "active":
            raise HTTPException(409, f"User '{user.username}' is already active")
        prev_status = user.status
        user.status = "active"
        user.updated_at = datetime.utcnow()
        action = _log_action("enable_user", user, req.requester, req.reason or "Account re-enabled", {"previous_status": prev_status})
        session.add(action)
        await session.commit()
    return {"success": True, "action_id": str(action.id), "username": user.username, "current_status": "active"}


@router.post("/users/{user_id}/revoke-sessions")
async def revoke_sessions(user_id: str, req: UserActionRequest):
    """Revoke all active sessions for a user (Okta session clear / Entra token revocation).

    Forces re-authentication on next access. Does not change account status.
    """
    await _ensure_seed_users()
    async with async_session() as session:
        user = await _get_user(session, user_id)
        sessions_revoked = random.randint(1, 8)

        action = _log_action(
            "revoke_sessions", user, req.requester, req.reason or "Sessions revoked",
            {"sessions_revoked": sessions_revoked, "username": user.username, "email": user.email},
        )
        session.add(action)
        await session.commit()

    return {
        "success": True, "action_id": str(action.id),
        "username": user.username, "sessions_revoked": sessions_revoked,
        "message": f"{sessions_revoked} active session(s) revoked for {user.username}",
        "timestamp": action.executed_at.isoformat(),
    }


@router.post("/users/{user_id}/force-mfa-reset")
async def force_mfa_reset(user_id: str, req: UserActionRequest):
    """Force re-enrollment of MFA for a user (unenrol all MFA factors)."""
    await _ensure_seed_users()
    async with async_session() as session:
        user = await _get_user(session, user_id)
        user.mfa_enrolled = False
        user.updated_at = datetime.utcnow()
        action = _log_action(
            "force_mfa", user, req.requester, req.reason or "MFA reset forced",
            {"username": user.username, "previous_mfa_status": True},
        )
        session.add(action)
        await session.commit()
    return {
        "success": True, "action_id": str(action.id),
        "username": user.username, "mfa_enrolled": False,
        "message": f"MFA factors cleared for {user.username} — re-enrollment required",
    }


@router.post("/users/{user_id}/force-password-reset")
async def force_password_reset(user_id: str, req: UserActionRequest):
    """Force a password reset on next login."""
    await _ensure_seed_users()
    async with async_session() as session:
        user = await _get_user(session, user_id)
        attrs = user.attributes or {}
        attrs["password_reset_required"] = True
        user.attributes = attrs
        user.updated_at = datetime.utcnow()
        action = _log_action(
            "force_pw_reset", user, req.requester, req.reason or "Password reset forced",
            {"username": user.username},
        )
        session.add(action)
        await session.commit()
    return {
        "success": True, "action_id": str(action.id),
        "username": user.username, "password_reset_required": True,
        "message": f"Password reset enforced for {user.username}",
    }
