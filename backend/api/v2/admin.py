"""Admin API — v2.

Endpoints for audit log access and user administration.
All routes require the "admin" role or superadmin status.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select

from backend.auth.dependencies import get_current_active_user, require_role
from backend.db import models
from backend.db.session import async_session

router = APIRouter(prefix="/admin", tags=["admin"])


# ---------------------------------------------------------------------------
# GET /admin/audit-log
# ---------------------------------------------------------------------------

@router.get("/audit-log", dependencies=[Depends(require_role("admin"))])
async def get_audit_log(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    user_id: Optional[uuid.UUID] = Query(None, description="Filter by user UUID"),
    action: Optional[str] = Query(None, description="Filter by action string (exact)"),
    date_from: Optional[datetime] = Query(None, description="ISO datetime lower bound"),
    date_to: Optional[datetime] = Query(None, description="ISO datetime upper bound"),
    current_user: models.User = Depends(get_current_active_user),
):
    """Paginated audit log with optional filters.

    Superadmins see all records; org admins see only records belonging to
    users in their organisation.
    """
    offset = (page - 1) * page_size

    async with async_session() as db:
        base_query = select(models.AuditLog)

        if not current_user.is_superadmin:
            # Restrict to users in the same org
            org_user_ids = await db.scalars(
                select(models.User.id).where(models.User.org_id == current_user.org_id)
            )
            org_user_id_list = list(org_user_ids)
            base_query = base_query.where(models.AuditLog.user_id.in_(org_user_id_list))

        if user_id is not None:
            base_query = base_query.where(models.AuditLog.user_id == user_id)
        if action is not None:
            base_query = base_query.where(models.AuditLog.action == action)
        if date_from is not None:
            base_query = base_query.where(models.AuditLog.created_at >= date_from)
        if date_to is not None:
            base_query = base_query.where(models.AuditLog.created_at <= date_to)

        count_query = select(func.count()).select_from(base_query.subquery())
        total = await db.scalar(count_query) or 0

        rows_query = base_query.order_by(models.AuditLog.created_at.desc()).offset(offset).limit(page_size)
        result = await db.execute(rows_query)
        entries = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
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
# GET /admin/users
# ---------------------------------------------------------------------------

@router.get("/users", dependencies=[Depends(require_role("admin"))])
async def list_users_admin(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    current_user: models.User = Depends(get_current_active_user),
):
    """Paginated list of users scoped to the current admin's organisation."""
    offset = (page - 1) * page_size

    async with async_session() as db:
        query = select(models.User)
        count_query = select(func.count()).select_from(models.User)

        if not current_user.is_superadmin:
            query = query.where(models.User.org_id == current_user.org_id)
            count_query = count_query.where(models.User.org_id == current_user.org_id)

        total = await db.scalar(count_query) or 0
        result = await db.execute(
            query.order_by(models.User.created_at.desc()).offset(offset).limit(page_size)
        )
        users = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "users": [
            {
                "id": str(u.id),
                "email": u.email,
                "full_name": u.full_name,
                "role": u.role,
                "org_id": str(u.org_id) if u.org_id else None,
                "is_active": u.is_active,
                "is_superadmin": u.is_superadmin,
                "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
                "created_at": u.created_at.isoformat(),
            }
            for u in users
        ],
    }


# ---------------------------------------------------------------------------
# POST /admin/users/{user_id}/activate
# ---------------------------------------------------------------------------

@router.post("/users/{user_id}/activate", dependencies=[Depends(require_role("admin"))])
async def activate_user(
    user_id: uuid.UUID,
    current_user: models.User = Depends(get_current_active_user),
):
    """Set is_active = True for the target user."""
    async with async_session() as db:
        user = await db.get(models.User, user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        if not current_user.is_superadmin and user.org_id != current_user.org_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot modify users outside your org")

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
# POST /admin/users/{user_id}/deactivate
# ---------------------------------------------------------------------------

@router.post("/users/{user_id}/deactivate", dependencies=[Depends(require_role("admin"))])
async def deactivate_user(
    user_id: uuid.UUID,
    current_user: models.User = Depends(get_current_active_user),
):
    """Set is_active = False for the target user."""
    if user_id == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot deactivate yourself")

    async with async_session() as db:
        user = await db.get(models.User, user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        if not current_user.is_superadmin and user.org_id != current_user.org_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot modify users outside your org")

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
