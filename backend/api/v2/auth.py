"""Authentication API — v2.

Endpoints for user registration, login, token refresh, profile management,
API key rotation, and user administration (admin/superadmin only).
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import func, select

from backend.auth.dependencies import get_current_active_user, require_role
from backend.auth.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_api_key,
    hash_password,
    verify_password,
)
from backend.db import models
from backend.db.session import async_session

router = APIRouter(prefix="/auth", tags=["auth"])

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class RegisterRequest(BaseModel):
    email: str
    password: str = Field(..., min_length=8)
    full_name: str = ""
    org_name: Optional[str] = None

    @field_validator("email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        if not _EMAIL_RE.match(v):
            raise ValueError("Invalid email address")
        return v.lower().strip()

    @field_validator("password")
    @classmethod
    def _validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: dict


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class UpdateMeRequest(BaseModel):
    full_name: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None

    @field_validator("new_password")
    @classmethod
    def _validate_new_password(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) < 8:
            raise ValueError("New password must be at least 8 characters")
        return v


class ChangeRoleRequest(BaseModel):
    role: str = Field(..., pattern="^(admin|engineer|analyst|viewer)$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _user_summary(user: models.User, org_name: Optional[str] = None) -> dict:
    return {
        "id": str(user.id),
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "org_id": str(user.org_id) if user.org_id else None,
        "org_name": org_name,
        "is_superadmin": user.is_superadmin,
    }


def _slugify(name: str) -> str:
    slug = re.sub(r"[^\w\s-]", "", name.lower()).strip()
    slug = re.sub(r"[\s_-]+", "-", slug)
    slug = slug[:90]
    return slug or "org"


async def _write_audit(
    db,
    user_id: Optional[uuid.UUID],
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    payload: Optional[dict] = None,
) -> None:
    log = models.AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        payload=payload or {},
    )
    db.add(log)


# ---------------------------------------------------------------------------
# POST /auth/register
# ---------------------------------------------------------------------------

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest):
    """Register a new user, optionally creating an organisation."""
    async with async_session() as db:
        existing = await db.scalar(select(models.User).where(models.User.email == body.email))
        if existing:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

        org: Optional[models.Organization] = None
        if body.org_name:
            slug = _slugify(body.org_name)
            # ensure unique slug
            count = await db.scalar(
                select(func.count()).select_from(models.Organization).where(
                    models.Organization.slug == slug
                )
            )
            if count:
                slug = f"{slug}-{uuid.uuid4().hex[:6]}"
            org = models.Organization(name=body.org_name, slug=slug)
            db.add(org)
            await db.flush()

        user = models.User(
            email=body.email,
            hashed_password=hash_password(body.password),
            full_name=body.full_name,
            role="admin" if org else "analyst",
            org_id=org.id if org else None,
            is_active=True,
            is_superadmin=False,
        )
        db.add(user)
        await db.flush()
        await _write_audit(db, user.id, "register")
        await db.commit()

    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token = create_refresh_token(str(user.id))
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": _user_summary(user, body.org_name),
    }


# ---------------------------------------------------------------------------
# POST /auth/login  (OAuth2PasswordRequestForm — username=email)
# ---------------------------------------------------------------------------

@router.post("/login", response_model=TokenResponse)
async def login(request: Request, form: OAuth2PasswordRequestForm = Depends()):
    """Authenticate with email + password and receive JWT tokens."""
    email = form.username.lower().strip()
    ip = request.client.host if request.client else None

    async with async_session() as db:
        user = await db.scalar(select(models.User).where(models.User.email == email))
        if user is None or not verify_password(form.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account disabled")

        user.last_login_at = datetime.now(timezone.utc)
        db.add(user)
        await _write_audit(db, user.id, "login", ip_address=ip)
        await db.commit()

        org_name: Optional[str] = None
        if user.org_id:
            org = await db.get(models.Organization, user.org_id)
            org_name = org.name if org else None

    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token = create_refresh_token(str(user.id))
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": _user_summary(user, org_name),
    }


# ---------------------------------------------------------------------------
# POST /auth/refresh
# ---------------------------------------------------------------------------

@router.post("/refresh", response_model=AccessTokenResponse)
async def refresh_token(body: RefreshRequest):
    """Exchange a valid refresh token for a new access token."""
    payload = decode_token(body.refresh_token)
    if payload is None or payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    async with async_session() as db:
        user = await db.scalar(select(models.User).where(models.User.id == user_id))

    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or disabled")

    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    return {"access_token": access_token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# GET /auth/me
# ---------------------------------------------------------------------------

@router.get("/me")
async def get_me(current_user: models.User = Depends(get_current_active_user)):
    """Return the current user's full profile."""
    org_name: Optional[str] = None
    if current_user.org_id:
        async with async_session() as db:
            org = await db.get(models.Organization, current_user.org_id)
            org_name = org.name if org else None

    api_key_hint = current_user.api_key[-8:] if current_user.api_key else None

    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "org_id": str(current_user.org_id) if current_user.org_id else None,
        "org_name": org_name,
        "is_superadmin": current_user.is_superadmin,
        "api_key_hint": api_key_hint,
        "last_login_at": current_user.last_login_at.isoformat() if current_user.last_login_at else None,
        "created_at": current_user.created_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# PUT /auth/me
# ---------------------------------------------------------------------------

@router.put("/me")
async def update_me(
    body: UpdateMeRequest,
    current_user: models.User = Depends(get_current_active_user),
):
    """Update the current user's full_name or password."""
    if body.new_password and not body.current_password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="current_password is required when changing password",
        )
    if body.current_password and not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    async with async_session() as db:
        user = await db.get(models.User, current_user.id)
        if body.full_name is not None:
            user.full_name = body.full_name
        if body.new_password:
            user.hashed_password = hash_password(body.new_password)
        await _write_audit(db, user.id, "update_profile")
        await db.commit()

    return {"ok": True, "message": "Profile updated"}


# ---------------------------------------------------------------------------
# POST /auth/logout
# ---------------------------------------------------------------------------

@router.post("/logout")
async def logout(current_user: models.User = Depends(get_current_active_user)):
    """Record logout in audit log. Token invalidation is client-side."""
    async with async_session() as db:
        await _write_audit(db, current_user.id, "logout")
        await db.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# POST /auth/api-key/rotate
# ---------------------------------------------------------------------------

@router.post("/api-key/rotate")
async def rotate_api_key(current_user: models.User = Depends(get_current_active_user)):
    """Generate a new API key. The plaintext is returned exactly once."""
    new_key = generate_api_key()

    async with async_session() as db:
        user = await db.get(models.User, current_user.id)
        user.api_key = new_key
        await _write_audit(db, user.id, "rotate_api_key")
        await db.commit()

    return {"api_key": new_key, "hint": new_key[-8:]}


# ---------------------------------------------------------------------------
# GET /auth/users  (admin/superadmin)
# ---------------------------------------------------------------------------

@router.get("/users")
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    current_user: models.User = Depends(require_role("admin")),
):
    """Paginated list of users within the current user's organisation."""
    offset = (page - 1) * page_size

    async with async_session() as db:
        query = select(models.User)
        if not current_user.is_superadmin:
            query = query.where(models.User.org_id == current_user.org_id)
        query = query.order_by(models.User.created_at.desc()).offset(offset).limit(page_size)
        result = await db.execute(query)
        users = result.scalars().all()

        count_query = select(func.count()).select_from(models.User)
        if not current_user.is_superadmin:
            count_query = count_query.where(models.User.org_id == current_user.org_id)
        total = await db.scalar(count_query)

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
# PUT /auth/users/{user_id}/role  (admin/superadmin)
# ---------------------------------------------------------------------------

@router.put("/users/{user_id}/role")
async def change_user_role(
    user_id: uuid.UUID,
    body: ChangeRoleRequest,
    current_user: models.User = Depends(require_role("admin")),
):
    """Change the role of a user within the current organisation."""
    async with async_session() as db:
        target = await db.get(models.User, user_id)
        if target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        if not current_user.is_superadmin and target.org_id != current_user.org_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot modify users outside your org")

        target.role = body.role
        await _write_audit(
            db, current_user.id, "change_role",
            resource_type="user", resource_id=str(user_id),
            payload={"new_role": body.role},
        )
        await db.commit()

    return {"ok": True, "user_id": str(user_id), "new_role": body.role}
