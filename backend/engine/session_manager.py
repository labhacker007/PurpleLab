"""Session manager — DB-backed persistence with in-memory write-through cache.

Handles CRUD operations for simulation sessions and coordinates
with the scheduler and dispatcher for event generation.

The in-memory `_sessions` dict acts as a write-through cache for running
sessions. On `get_session`, memory is checked first; DB is the source of
truth for stopped/persisted sessions.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select

from backend.db.models import GeneratedEvent, SimulationSession
from backend.db.session import async_session
from backend.engine.generators import GENERATOR_REGISTRY
from backend.engine.generators.base import BaseGenerator

log = logging.getLogger(__name__)


def _session_row_to_dict(row: SimulationSession) -> dict[str, Any]:
    """Convert a SimulationSession ORM row to a plain dict."""
    return {
        "session_id": str(row.id),
        "name": row.name,
        "status": row.status,
        "config": row.config or {},
        "events_sent": row.events_sent,
        "errors": row.errors,
        "last_event_at": row.last_event_at.isoformat() if row.last_event_at else None,
        "stopped_at": row.stopped_at.isoformat() if row.stopped_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


class SessionManager:
    """Manages the lifecycle of simulation sessions.

    Uses PostgreSQL (via SQLAlchemy async) as the source of truth with an
    in-memory write-through cache for running sessions.
    """

    def __init__(self) -> None:
        # In-memory cache: session_id (str) -> dict
        self._sessions: dict[str, dict[str, Any]] = {}
        # Generator registry: session_id -> {product_id -> generator}
        self.generators: dict[str, dict[str, BaseGenerator]] = {}

    # ── Session CRUD ─────────────────────────────────────────────────────

    async def create_session(self, config: Any) -> dict[str, Any]:
        """Create a new simulation session, persisting it to the DB.

        Args:
            config: A SessionConfig-like object with at minimum
                    `session_id`, `name`, `products`, and `targets`.

        Returns:
            Session dict with all persisted fields.
        """
        # Derive a stable UUID from the provided session_id if available
        session_uuid: uuid.UUID
        sid = getattr(config, "session_id", None)
        if sid:
            try:
                session_uuid = uuid.UUID(str(sid))
            except ValueError:
                session_uuid = uuid.uuid4()
        else:
            session_uuid = uuid.uuid4()

        config_dict: dict[str, Any] = {}
        if hasattr(config, "dict"):
            try:
                config_dict = config.dict()
            except Exception:
                pass
        elif hasattr(config, "__dict__"):
            config_dict = {k: v for k, v in config.__dict__.items() if not k.startswith("_")}

        async with async_session() as db:
            row = SimulationSession(
                id=session_uuid,
                name=getattr(config, "name", "Untitled Session"),
                config=config_dict,
                status="running",
                events_sent=0,
                errors=0,
            )
            db.add(row)
            await db.commit()
            await db.refresh(row)
            session_dict = _session_row_to_dict(row)

        # Populate cache with the original config object for generator access
        self._sessions[session_dict["session_id"]] = session_dict
        # Keep original config object under a private key so build_generators works
        self._sessions[session_dict["session_id"]]["_config"] = config
        log.info("Session created: %s (%s)", session_dict["session_id"], row.name)
        return session_dict

    async def get_session(self, session_id: str) -> Optional[dict[str, Any]]:
        """Retrieve a session by ID — checks cache first, then DB.

        Args:
            session_id: UUID string of the session.

        Returns:
            Session dict or None if not found.
        """
        # Check in-memory cache first
        cached = self._sessions.get(session_id)
        if cached is not None:
            return cached

        # Fall back to DB
        try:
            session_uuid = uuid.UUID(session_id)
        except ValueError:
            return None

        async with async_session() as db:
            row = await db.get(SimulationSession, session_uuid)
            if row is None:
                return None
            return _session_row_to_dict(row)

    async def list_sessions(
        self, status: Optional[str] = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """List sessions, optionally filtered by status.

        Args:
            status: If provided, only return sessions with this status.
            limit: Maximum number of sessions to return (default 50).

        Returns:
            List of session dicts ordered by created_at DESC.
        """
        async with async_session() as db:
            query = (
                select(SimulationSession)
                .order_by(SimulationSession.created_at.desc())
                .limit(limit)
            )
            if status is not None:
                query = query.where(SimulationSession.status == status)
            result = await db.execute(query)
            rows = result.scalars().all()
            return [_session_row_to_dict(r) for r in rows]

    async def update_session(
        self, session_id: str, **fields: Any
    ) -> Optional[dict[str, Any]]:
        """Update arbitrary fields on a session row.

        Supported field names match SimulationSession columns:
        name, config, status, events_sent, errors, last_event_at, stopped_at.

        Args:
            session_id: UUID string of the session.
            **fields: Column-name/value pairs to update.

        Returns:
            Updated session dict or None if not found.
        """
        try:
            session_uuid = uuid.UUID(session_id)
        except ValueError:
            return None

        allowed = {
            "name", "config", "status", "events_sent",
            "errors", "last_event_at", "stopped_at",
        }
        update_kwargs = {k: v for k, v in fields.items() if k in allowed}
        if not update_kwargs:
            return await self.get_session(session_id)

        async with async_session() as db:
            row = await db.get(SimulationSession, session_uuid)
            if row is None:
                return None
            for key, value in update_kwargs.items():
                setattr(row, key, value)
            await db.commit()
            await db.refresh(row)
            session_dict = _session_row_to_dict(row)

        # Update cache if present
        if session_id in self._sessions:
            cfg = self._sessions[session_id].get("_config")
            self._sessions[session_id] = session_dict
            if cfg is not None:
                self._sessions[session_id]["_config"] = cfg

        return session_dict

    async def stop_session(self, session_id: str) -> Optional[dict[str, Any]]:
        """Stop a session — sets status="stopped" and records stopped_at.

        Args:
            session_id: UUID string of the session.

        Returns:
            Updated session dict or None if not found.
        """
        now = datetime.now(timezone.utc)
        result = await self.update_session(
            session_id, status="stopped", stopped_at=now
        )
        # Remove from active cache once stopped
        self._sessions.pop(session_id, None)
        self.generators.pop(session_id, None)
        return result

    async def store_event(
        self, session_id: str, event_data: dict[str, Any]
    ) -> Optional[dict[str, Any]]:
        """Persist a generated event to the DB and update session counters.

        Args:
            session_id: UUID string of the owning session.
            event_data: Dict containing at minimum product_type, severity,
                        title, payload, target_url, status_code, success.

        Returns:
            Dict representation of the inserted event row, or None on failure.
        """
        try:
            session_uuid = uuid.UUID(session_id)
        except ValueError:
            log.warning("store_event: invalid session_id %s", session_id)
            return None

        async with async_session() as db:
            event = GeneratedEvent(
                session_id=session_uuid,
                product_type=event_data.get("product_type", "unknown"),
                severity=event_data.get("severity", "medium"),
                title=event_data.get("title", ""),
                payload=event_data.get("payload"),
                target_url=event_data.get("target_url", ""),
                status_code=int(event_data.get("status_code", 0)),
                success=bool(event_data.get("success", False)),
            )
            db.add(event)

            # Increment session counters in the same transaction
            row = await db.get(SimulationSession, session_uuid)
            if row is not None:
                row.events_sent = (row.events_sent or 0) + 1
                if not event.success:
                    row.errors = (row.errors or 0) + 1
                row.last_event_at = datetime.now(timezone.utc)

            await db.commit()
            await db.refresh(event)

            event_dict = {
                "id": str(event.id),
                "session_id": str(event.session_id),
                "product_type": event.product_type,
                "severity": event.severity,
                "title": event.title,
                "payload": event.payload,
                "target_url": event.target_url,
                "status_code": event.status_code,
                "success": event.success,
                "created_at": event.created_at.isoformat() if event.created_at else None,
            }

        # Refresh cache counters
        if session_id in self._sessions and row is not None:
            self._sessions[session_id]["events_sent"] = row.events_sent
            self._sessions[session_id]["errors"] = row.errors
            self._sessions[session_id]["last_event_at"] = (
                row.last_event_at.isoformat() if row.last_event_at else None
            )

        return event_dict

    async def get_events(
        self,
        session_id: str,
        since_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Retrieve generated events for a session.

        Args:
            session_id: UUID string of the session.
            since_id: If provided, return only events created after this event ID.
            limit: Maximum events to return.

        Returns:
            List of event dicts ordered by created_at ASC.
        """
        try:
            session_uuid = uuid.UUID(session_id)
        except ValueError:
            return []

        async with async_session() as db:
            query = (
                select(GeneratedEvent)
                .where(GeneratedEvent.session_id == session_uuid)
                .order_by(GeneratedEvent.created_at.asc())
                .limit(limit)
            )

            if since_id is not None:
                try:
                    since_uuid = uuid.UUID(since_id)
                    # Fetch the reference event's created_at for cursor pagination
                    ref = await db.get(GeneratedEvent, since_uuid)
                    if ref is not None:
                        query = query.where(
                            GeneratedEvent.created_at > ref.created_at
                        )
                except ValueError:
                    pass

            result = await db.execute(query)
            rows = result.scalars().all()

        return [
            {
                "id": str(r.id),
                "session_id": str(r.session_id),
                "product_type": r.product_type,
                "severity": r.severity,
                "title": r.title,
                "payload": r.payload,
                "target_url": r.target_url,
                "status_code": r.status_code,
                "success": r.success,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]

    # ── Generator management ─────────────────────────────────────────────

    def build_generators(self, session_id: str) -> dict[str, BaseGenerator]:
        """Instantiate generators for all products in a session.

        Reads the original config object stored in the cache under _config.

        Args:
            session_id: UUID string of the session.

        Returns:
            Dict mapping product_id -> generator instance.
        """
        cached = self._sessions.get(session_id)
        if not cached:
            return {}
        config = cached.get("_config")
        if config is None:
            return {}

        gens: dict[str, BaseGenerator] = {}
        for product in getattr(config, "products", []):
            gen_cls = GENERATOR_REGISTRY.get(product.product_type)
            if gen_cls:
                gens[product.id] = gen_cls(product.config)
        self.generators[session_id] = gens
        return gens
