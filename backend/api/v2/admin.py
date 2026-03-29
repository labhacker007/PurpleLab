"""Admin API — v2.

Endpoints for audit log access, user administration, platform statistics,
and system-wide broadcasts. All routes require the "admin" role.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy import func, select

from backend.auth.dependencies import get_current_active_user, require_role
from backend.db import models
from backend.db.session import async_session
from backend.dependencies import get_redis

router = APIRouter(prefix="/admin", tags=["admin"])

_VALID_ROLES = {"viewer", "analyst", "engineer", "admin"}


# ---------------------------------------------------------------------------
# GET /admin/users
# ---------------------------------------------------------------------------

@router.get("/users", dependencies=[Depends(require_role("admin"))])
async def list_users_admin(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    current_user: models.User = Depends(get_current_active_user),
) -> dict:
    """List all users with id, email, full_name, role, is_active, created_at, last_login."""
    offset = (page - 1) * per_page

    async with async_session() as db:
        base = select(models.User)
        count_base = select(func.count()).select_from(models.User)

        if not current_user.is_superadmin:
            base = base.where(models.User.org_id == current_user.org_id)
            count_base = count_base.where(models.User.org_id == current_user.org_id)

        total = await db.scalar(count_base) or 0
        result = await db.execute(
            base.order_by(models.User.created_at.desc()).offset(offset).limit(per_page)
        )
        users = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "users": [
            {
                "id": str(u.id),
                "email": u.email,
                "full_name": u.full_name,
                "role": u.role,
                "is_active": u.is_active,
                "is_superadmin": u.is_superadmin,
                "org_id": str(u.org_id) if u.org_id else None,
                "last_login": u.last_login_at.isoformat() if u.last_login_at else None,
                "created_at": u.created_at.isoformat(),
            }
            for u in users
        ],
    }


# ---------------------------------------------------------------------------
# PUT /admin/users/{user_id}/role
# ---------------------------------------------------------------------------

@router.put("/users/{user_id}/role", dependencies=[Depends(require_role("admin"))])
async def update_user_role(
    user_id: uuid.UUID,
    body: dict = Body(...),
    current_user: models.User = Depends(get_current_active_user),
) -> dict:
    """Change the role of a user. Cannot demote the last admin."""
    role = body.get("role")
    if role not in _VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"role must be one of: {', '.join(sorted(_VALID_ROLES))}",
        )

    async with async_session() as db:
        user = await db.get(models.User, user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        if not current_user.is_superadmin and user.org_id != current_user.org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot modify users outside your org",
            )

        # Guard: cannot demote the last admin in this org
        if user.role == "admin" and role != "admin":
            scope = select(func.count()).select_from(models.User).where(
                models.User.role == "admin",
                models.User.is_active.is_(True),
            )
            if not current_user.is_superadmin:
                scope = scope.where(models.User.org_id == current_user.org_id)
            admin_count = await db.scalar(scope) or 0
            if admin_count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Cannot demote the last admin",
                )

        old_role = user.role
        user.role = role
        log = models.AuditLog(
            user_id=current_user.id,
            action="change_user_role",
            resource_type="user",
            resource_id=str(user_id),
            payload={"old_role": old_role, "new_role": role},
        )
        db.add(log)
        await db.commit()

    return {"ok": True, "user_id": str(user_id), "role": role}


# ---------------------------------------------------------------------------
# PUT /admin/users/{user_id}/active
# ---------------------------------------------------------------------------

@router.put("/users/{user_id}/active", dependencies=[Depends(require_role("admin"))])
async def set_user_active(
    user_id: uuid.UUID,
    body: dict = Body(...),
    current_user: models.User = Depends(get_current_active_user),
) -> dict:
    """Activate or deactivate a user account."""
    is_active = body.get("is_active")
    if not isinstance(is_active, bool):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="is_active must be a boolean",
        )

    async with async_session() as db:
        user = await db.get(models.User, user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        if not current_user.is_superadmin and user.org_id != current_user.org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot modify users outside your org",
            )

        user.is_active = is_active
        action = "activate_user" if is_active else "deactivate_user"
        log = models.AuditLog(
            user_id=current_user.id,
            action=action,
            resource_type="user",
            resource_id=str(user_id),
        )
        db.add(log)
        await db.commit()

    return {"ok": True, "user_id": str(user_id), "is_active": is_active}


# ---------------------------------------------------------------------------
# DELETE /admin/users/{user_id}
# ---------------------------------------------------------------------------

@router.delete("/users/{user_id}", dependencies=[Depends(require_role("admin"))])
async def delete_user(
    user_id: uuid.UUID,
    current_user: models.User = Depends(get_current_active_user),
) -> dict:
    """Soft-delete a user (set is_active=False). Cannot delete self."""
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete yourself",
        )

    async with async_session() as db:
        user = await db.get(models.User, user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        if not current_user.is_superadmin and user.org_id != current_user.org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot modify users outside your org",
            )

        user.is_active = False
        log = models.AuditLog(
            user_id=current_user.id,
            action="delete_user",
            resource_type="user",
            resource_id=str(user_id),
        )
        db.add(log)
        await db.commit()

    return {"ok": True, "user_id": str(user_id)}


# ---------------------------------------------------------------------------
# GET /admin/audit-log
# ---------------------------------------------------------------------------

@router.get("/audit-log", dependencies=[Depends(require_role("admin"))])
async def get_audit_log(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    user_id: Optional[uuid.UUID] = Query(None, description="Filter by user UUID"),
    action: Optional[str] = Query(None, description="Filter by action string (exact)"),
    current_user: models.User = Depends(get_current_active_user),
) -> dict:
    """Paginated audit log with optional filters."""
    offset = (page - 1) * per_page

    async with async_session() as db:
        base_query = select(models.AuditLog)

        if not current_user.is_superadmin:
            org_user_ids_result = await db.scalars(
                select(models.User.id).where(models.User.org_id == current_user.org_id)
            )
            org_user_id_list = list(org_user_ids_result)
            base_query = base_query.where(models.AuditLog.user_id.in_(org_user_id_list))

        if user_id is not None:
            base_query = base_query.where(models.AuditLog.user_id == user_id)
        if action is not None:
            base_query = base_query.where(models.AuditLog.action == action)

        count_query = select(func.count()).select_from(base_query.subquery())
        total = await db.scalar(count_query) or 0

        rows_query = (
            base_query.order_by(models.AuditLog.created_at.desc())
            .offset(offset)
            .limit(per_page)
        )
        result = await db.execute(rows_query)
        entries = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "entries": [
            {
                "id": str(e.id),
                "user_id": str(e.user_id) if e.user_id else None,
                "action": e.action,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
                "ip_address": e.ip_address,
                "payload": e.payload,
                "created_at": e.created_at.isoformat(),
            }
            for e in entries
        ],
    }


# ---------------------------------------------------------------------------
# GET /admin/stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(require_role("admin"))])
async def get_platform_stats(
    redis: Any = Depends(get_redis),
) -> dict:
    """Platform-wide statistics for the admin dashboard."""
    today_start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    stats: dict = {
        "total_users": 0,
        "active_users": 0,
        "total_sessions": 0,
        "sessions_today": 0,
        "total_use_cases": 0,
        "use_cases_passing": 0,
        "total_rules": 0,
        "llm_calls_today": 0,
        "storage_mb": 0.0,
    }

    async with async_session() as db:
        # Users
        try:
            stats["total_users"] = await db.scalar(
                select(func.count()).select_from(models.User)
            ) or 0
        except Exception:
            pass

        try:
            stats["active_users"] = await db.scalar(
                select(func.count()).select_from(models.User).where(
                    models.User.is_active.is_(True)
                )
            ) or 0
        except Exception:
            pass

        # Simulation sessions
        try:
            stats["total_sessions"] = await db.scalar(
                select(func.count()).select_from(models.SimulationSession)
            ) or 0
        except Exception:
            pass

        try:
            stats["sessions_today"] = await db.scalar(
                select(func.count()).select_from(models.SimulationSession).where(
                    models.SimulationSession.created_at >= today_start
                )
            ) or 0
        except Exception:
            pass

        # Use cases
        try:
            stats["total_use_cases"] = await db.scalar(
                select(func.count()).select_from(models.UseCase)
            ) or 0
        except Exception:
            pass

        try:
            stats["use_cases_passing"] = await db.scalar(
                select(func.count()).select_from(models.UseCaseRun).where(
                    models.UseCaseRun.status == "passed"
                )
            ) or 0
        except Exception:
            pass

        # Detection rules
        try:
            stats["total_rules"] = await db.scalar(
                select(func.count()).select_from(models.ImportedRule)
            ) or 0
        except Exception:
            pass

        # Approximate storage from row counts across major tables
        try:
            tables = [
                models.GeneratedEvent,
                models.AuditLog,
                models.Message,
                models.RuleTestResult,
                models.UseCaseRun,
                models.PipelineRun,
            ]
            total_rows = 0
            for tbl in tables:
                n = await db.scalar(select(func.count()).select_from(tbl)) or 0
                total_rows += n
            # rough estimate: ~2 KB per row average
            stats["storage_mb"] = round(total_rows * 2 / 1024, 2)
        except Exception:
            pass

    # LLM calls today from Redis keys llm:stats:*
    if redis is not None:
        try:
            keys = await redis.keys("llm:stats:*")
            total_calls = 0
            for key in keys:
                raw = await redis.get(key)
                if raw is not None:
                    try:
                        data = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
                        if isinstance(data, dict):
                            total_calls += int(data.get("calls_today", 0))
                        elif isinstance(data, (int, float)):
                            total_calls += int(data)
                    except Exception:
                        pass
            stats["llm_calls_today"] = total_calls
        except Exception:
            pass

    return stats


# ---------------------------------------------------------------------------
# POST /admin/broadcast
# ---------------------------------------------------------------------------

@router.post("/broadcast", dependencies=[Depends(require_role("admin"))])
async def broadcast_message(
    body: dict = Body(...),
    current_user: models.User = Depends(get_current_active_user),
    redis: Any = Depends(get_redis),
) -> dict:
    """Store a system-wide broadcast message in Redis with a 24-hour TTL.

    Body: {"message": str, "type": "info"|"warning"|"error"}
    Frontend can poll GET /admin/broadcast (or a websocket) to display it.
    """
    message = body.get("message", "").strip()
    msg_type = body.get("type", "info")

    if not message:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="message must be a non-empty string",
        )
    if msg_type not in {"info", "warning", "error"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="type must be one of: info, warning, error",
        )

    payload = {
        "message": message,
        "type": msg_type,
        "created_by": str(current_user.id),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    if redis is not None:
        try:
            await redis.set("pl:broadcast", json.dumps(payload), ex=86400)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Redis unavailable: {exc}",
            ) from exc
    else:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Redis is not configured; broadcast is unavailable",
        )

    # Audit
    async with async_session() as db:
        log = models.AuditLog(
            user_id=current_user.id,
            action="broadcast",
            resource_type="system",
            payload={"type": msg_type, "message": message},
        )
        db.add(log)
        await db.commit()

    return {"ok": True, "broadcast": payload}


# ---------------------------------------------------------------------------
# POST /admin/users/{user_id}/activate  (legacy — kept for backwards compat)
# ---------------------------------------------------------------------------

@router.post("/users/{user_id}/activate", dependencies=[Depends(require_role("admin"))])
async def activate_user_legacy(
    user_id: uuid.UUID,
    current_user: models.User = Depends(get_current_active_user),
) -> dict:
    """Activate a user account (legacy endpoint)."""
    async with async_session() as db:
        user = await db.get(models.User, user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        if not current_user.is_superadmin and user.org_id != current_user.org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot modify users outside your org",
            )
        user.is_active = True
        log = models.AuditLog(
            user_id=current_user.id,
            action="activate_user",
            resource_type="user",
            resource_id=str(user_id),
        )
        db.add(log)
        await db.commit()

    return {"ok": True, "user_id": str(user_id), "is_active": True}


# ---------------------------------------------------------------------------
# POST /admin/users/{user_id}/deactivate  (legacy — kept for backwards compat)
# ---------------------------------------------------------------------------

@router.post("/users/{user_id}/deactivate", dependencies=[Depends(require_role("admin"))])
async def deactivate_user_legacy(
    user_id: uuid.UUID,
    current_user: models.User = Depends(get_current_active_user),
) -> dict:
    """Deactivate a user account (legacy endpoint)."""
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate yourself",
        )

    async with async_session() as db:
        user = await db.get(models.User, user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        if not current_user.is_superadmin and user.org_id != current_user.org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot modify users outside your org",
            )
        user.is_active = False
        log = models.AuditLog(
            user_id=current_user.id,
            action="deactivate_user",
            resource_type="user",
            resource_id=str(user_id),
        )
        db.add(log)
        await db.commit()

    return {"ok": True, "user_id": str(user_id), "is_active": False}
