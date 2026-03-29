"""FastAPI authentication dependencies.

Provides get_current_user, get_current_active_user, require_role, and
get_optional_user for use with Depends() in route handlers.
"""
from __future__ import annotations

from typing import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select

from backend.auth.security import decode_token
from backend.db import models
from backend.db.session import async_session

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v2/auth/login", auto_error=False)


async def get_current_user(
    token: str | None = Depends(oauth2_scheme),
) -> models.User:
    """Decode the Bearer token and return the matching User from the DB.

    Raises HTTP 401 if the token is missing, invalid, or the user does not exist
    or is inactive.
    """
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exc

    payload = decode_token(token)
    if payload is None or payload.get("type") != "access":
        raise credentials_exc

    user_id: str | None = payload.get("sub")
    if not user_id:
        raise credentials_exc

    async with async_session() as db:
        user = await db.scalar(
            select(models.User).where(models.User.id == user_id)
        )

    if user is None:
        raise credentials_exc
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled",
        )
    return user


async def get_current_active_user(
    user: models.User = Depends(get_current_user),
) -> models.User:
    """Same as get_current_user — explicit alias that also asserts is_active."""
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled",
        )
    return user


def require_role(*roles: str) -> Callable:
    """Factory that returns a FastAPI dependency checking user.role.

    Usage:
        @router.get("/admin-only", dependencies=[Depends(require_role("admin"))])
    """
    async def _check(user: models.User = Depends(get_current_active_user)) -> models.User:
        if user.is_superadmin:
            return user
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required role(s): {', '.join(roles)}",
            )
        return user

    return _check


async def get_optional_user(
    token: str | None = Depends(oauth2_scheme),
) -> models.User | None:
    """Like get_current_user but returns None instead of raising 401.

    Useful for endpoints that work both authenticated and unauthenticated.
    """
    if not token:
        return None

    payload = decode_token(token)
    if payload is None or payload.get("type") != "access":
        return None

    user_id: str | None = payload.get("sub")
    if not user_id:
        return None

    try:
        async with async_session() as db:
            user = await db.scalar(
                select(models.User).where(models.User.id == user_id)
            )
        if user and user.is_active:
            return user
    except Exception:
        pass

    return None
