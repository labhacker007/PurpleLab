"""Environment service — CRUD and lifecycle management for simulated environments.

Implements database CRUD via the Environment ORM model using SQLAlchemy async sessions.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from backend.db.session import async_session
from backend.db.models import Environment


def _env_to_dict(env: Environment) -> dict[str, Any]:
    """Convert an Environment ORM object to a plain dict."""
    return {
        "id": str(env.id),
        "name": env.name,
        "description": env.description,
        "siem_platform": env.siem_platform,
        "log_sources": env.log_sources or {},
        "settings": env.settings or {},
        "created_at": env.created_at.isoformat() if env.created_at else None,
        "updated_at": env.updated_at.isoformat() if env.updated_at else None,
    }


class EnvironmentService:
    """Manages simulated SOC environments."""

    async def create(
        self,
        name: str,
        description: str = "",
        user_id: str | None = None,
        org_id: str | None = None,
        siem_platform: str = "splunk",
        log_sources: dict[str, Any] | None = None,
        settings: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new environment and persist it to the database."""
        now = datetime.now(timezone.utc)
        async with async_session() as session:
            env = Environment(
                id=uuid.uuid4(),
                name=name,
                description=description,
                siem_platform=siem_platform,
                log_sources=log_sources or {},
                settings=settings or {},
                created_at=now,
                updated_at=now,
            )
            session.add(env)
            await session.commit()
            await session.refresh(env)
            return _env_to_dict(env)

    async def get(self, environment_id: str) -> dict[str, Any] | None:
        """Return an environment by ID, or None if not found."""
        try:
            uid = uuid.UUID(environment_id)
        except ValueError:
            return None

        async with async_session() as session:
            result = await session.execute(
                select(Environment).where(Environment.id == uid)
            )
            env = result.scalar_one_or_none()
            if env is None:
                return None
            return _env_to_dict(env)

    async def list_all(
        self,
        user_id: str | None = None,
        org_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return all environments. user_id / org_id reserved for future filtering."""
        async with async_session() as session:
            result = await session.execute(select(Environment))
            envs = result.scalars().all()
            return [_env_to_dict(e) for e in envs]

    async def update(
        self, environment_id: str, **fields: Any
    ) -> dict[str, Any] | None:
        """Update an environment's fields. Returns updated dict or None if not found."""
        try:
            uid = uuid.UUID(environment_id)
        except ValueError:
            return None

        # Fields that map directly to Environment columns
        allowed = {"name", "description", "siem_platform", "log_sources", "settings"}

        async with async_session() as session:
            result = await session.execute(
                select(Environment).where(Environment.id == uid)
            )
            env = result.scalar_one_or_none()
            if env is None:
                return None

            for key, value in fields.items():
                if key in allowed and value is not None:
                    setattr(env, key, value)

            env.updated_at = datetime.now(timezone.utc)
            await session.commit()
            await session.refresh(env)
            return _env_to_dict(env)

    async def delete(self, environment_id: str) -> bool:
        """Delete an environment by ID. Returns True on success, False if not found."""
        try:
            uid = uuid.UUID(environment_id)
        except ValueError:
            return False

        async with async_session() as session:
            result = await session.execute(
                select(Environment).where(Environment.id == uid)
            )
            env = result.scalar_one_or_none()
            if env is None:
                return False

            await session.delete(env)
            await session.commit()
            return True

    async def save_canvas_topology(
        self, environment_id: str, topology: dict[str, Any]
    ) -> bool:
        """Merge canvas topology into the environment's settings JSON column.

        Merges ``{"canvas_topology": topology}`` with any existing settings,
        preserving other keys. Returns True on success, False if not found.
        """
        try:
            uid = uuid.UUID(environment_id)
        except ValueError:
            return False

        async with async_session() as session:
            result = await session.execute(
                select(Environment).where(Environment.id == uid)
            )
            env = result.scalar_one_or_none()
            if env is None:
                return False

            existing = dict(env.settings or {})
            existing["canvas_topology"] = topology
            env.settings = existing
            env.updated_at = datetime.now(timezone.utc)
            await session.commit()
            return True
