"""Simulation session CRUD + start/stop endpoints — v2 API.

Fully wired to the PostgreSQL database via SQLAlchemy async sessions.
Sessions track attack chain runs, event generation counts, and lifecycle.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc
from sqlalchemy.orm import selectinload

from backend.db.session import async_session
from backend.db.models import SimulationSession, GeneratedEvent

router = APIRouter(prefix="/sessions", tags=["sessions"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SessionCreateRequest(BaseModel):
    name: str = Field("Untitled Session", max_length=255)
    config: dict[str, Any] = Field(default_factory=dict)


class SessionUpdateRequest(BaseModel):
    name: str | None = None
    config: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("")
async def list_sessions(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=200),
    status: str | None = Query(None),
):
    """List all simulation sessions with status and event counts."""
    async with async_session() as session:
        query = select(SimulationSession).order_by(desc(SimulationSession.created_at))
        if status:
            query = query.where(SimulationSession.status == status)
        query = query.offset(skip).limit(limit)

        result = await session.execute(query)
        sessions = result.scalars().all()

        count_result = await session.execute(
            select(func.count()).select_from(SimulationSession)
        )
        total = count_result.scalar() or 0

    return {
        "sessions": [_session_to_dict(s) for s in sessions],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.post("")
async def create_session(req: SessionCreateRequest):
    """Create a new simulation session."""
    async with async_session() as session:
        new_session = SimulationSession(
            name=req.name,
            config=req.config,
            status="stopped",
            events_sent=0,
            errors=0,
        )
        session.add(new_session)
        await session.commit()
        await session.refresh(new_session)
    return _session_to_dict(new_session)


@router.get("/{session_id}")
async def get_session(session_id: str):
    """Get full session details including event count."""
    s = await _get_or_404(session_id)
    d = _session_to_dict(s)

    # Get recent events
    async with async_session() as session:
        result = await session.execute(
            select(GeneratedEvent)
            .where(GeneratedEvent.session_id == uuid.UUID(session_id))
            .order_by(desc(GeneratedEvent.created_at))
            .limit(10)
        )
        recent_events = result.scalars().all()
        d["recent_events"] = [_event_to_dict(e) for e in recent_events]

    return d


@router.put("/{session_id}")
async def update_session(session_id: str, req: SessionUpdateRequest):
    """Update session name or config."""
    async with async_session() as session:
        result = await session.execute(
            select(SimulationSession).where(
                SimulationSession.id == uuid.UUID(session_id)
            )
        )
        s = result.scalar_one_or_none()
        if not s:
            raise HTTPException(404, detail=f"Session '{session_id}' not found.")
        if req.name is not None:
            s.name = req.name
        if req.config is not None:
            s.config = req.config
        s.updated_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(s)
    return _session_to_dict(s)


@router.delete("/{session_id}")
async def delete_session(session_id: str):
    """Delete a session and all its generated events."""
    async with async_session() as session:
        result = await session.execute(
            select(SimulationSession).where(
                SimulationSession.id == uuid.UUID(session_id)
            )
        )
        s = result.scalar_one_or_none()
        if not s:
            raise HTTPException(404, detail=f"Session '{session_id}' not found.")
        if s.status == "running":
            # Stop it first
            await _do_stop(session_id)
        await session.delete(s)
        await session.commit()
    return {"status": "deleted", "id": session_id}


@router.post("/{session_id}/start")
async def start_session(session_id: str):
    """Start event generation for a session."""
    s = await _get_or_404(session_id)
    if s.status == "running":
        return {"status": "already_running", "id": session_id}

    async with async_session() as session:
        result = await session.execute(
            select(SimulationSession).where(
                SimulationSession.id == uuid.UUID(session_id)
            )
        )
        s = result.scalar_one_or_none()
        if s:
            s.status = "running"
            s.updated_at = datetime.now(timezone.utc)
            await session.commit()

    # Wire engine scheduler
    try:
        from backend.engine.session_manager import get_session_manager
        mgr = get_session_manager()
        await mgr.start_session(session_id, s.config or {})
    except Exception as exc:
        # Non-fatal: session is marked running but scheduler may not be active
        pass

    return {"status": "started", "id": session_id}


@router.post("/{session_id}/stop")
async def stop_session(session_id: str):
    """Stop event generation for a session."""
    await _do_stop(session_id)
    return {"status": "stopped", "id": session_id}


@router.get("/{session_id}/events/stream")
async def stream_session_events(
    session_id: str,
    since_id: str | None = Query(None),
):
    """SSE stream of events for a session. Polls DB every 1.5s for new events.

    Client sends ?since_id=<last_event_id> to get only new events.
    Streams until session status is not 'running' and no new events for 5s.

    Event format:
    data: {"id": "...", "source_type": "...", "technique_id": "...",
           "severity": "...", "payload": {...}, "created_at": "..."}
    """
    from fastapi.responses import StreamingResponse
    import asyncio
    import json

    async def event_generator():
        last_id = since_id
        idle_count = 0

        while True:
            async with async_session() as db:
                # Query new events
                query = (
                    select(GeneratedEvent)
                    .where(GeneratedEvent.session_id == uuid.UUID(session_id))
                    .order_by(GeneratedEvent.created_at)
                )

                if last_id:
                    # Get events after the last seen one (UUID-based cursor via created_at)
                    subq = select(GeneratedEvent.created_at).where(
                        GeneratedEvent.id == uuid.UUID(last_id)
                    ).scalar_subquery()
                    query = query.where(GeneratedEvent.created_at > subq)

                query = query.limit(50)
                result = await db.execute(query)
                events = result.scalars().all()

                if events:
                    idle_count = 0
                    for event in events:
                        data = {
                            "id": str(event.id),
                            "source_type": event.product_type or "",
                            "technique_id": event.title or "",
                            "severity": event.severity or "info",
                            "payload": event.payload or {},
                            "created_at": event.created_at.isoformat() if event.created_at else "",
                        }
                        last_id = str(event.id)
                        yield f"data: {json.dumps(data)}\n\n"
                else:
                    idle_count += 1
                    # Check session status
                    session_q = await db.execute(
                        select(SimulationSession).where(
                            SimulationSession.id == uuid.UUID(session_id)
                        )
                    )
                    sess = session_q.scalar_one_or_none()
                    if not sess or (sess.status != "running" and idle_count > 3):
                        yield 'data: {"type": "done"}\n\n'
                        break

            # Send heartbeat every 5 polls
            if idle_count > 0 and idle_count % 5 == 0:
                yield ": heartbeat\n\n"

            await asyncio.sleep(1.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.get("/{session_id}/stats")
async def get_session_stats(session_id: str):
    """Returns event counts, severity breakdown, top techniques, top sources."""
    await _get_or_404(session_id)

    async with async_session() as db:
        # Total events
        total_result = await db.execute(
            select(func.count()).select_from(GeneratedEvent).where(
                GeneratedEvent.session_id == uuid.UUID(session_id)
            )
        )
        total_events = total_result.scalar() or 0

        # By severity
        sev_result = await db.execute(
            select(GeneratedEvent.severity, func.count().label("cnt"))
            .where(GeneratedEvent.session_id == uuid.UUID(session_id))
            .group_by(GeneratedEvent.severity)
        )
        by_severity = {row.severity: row.cnt for row in sev_result}

        # By source (product_type)
        src_result = await db.execute(
            select(GeneratedEvent.product_type, func.count().label("cnt"))
            .where(GeneratedEvent.session_id == uuid.UUID(session_id))
            .group_by(GeneratedEvent.product_type)
            .order_by(desc(func.count()))
            .limit(10)
        )
        by_source = {row.product_type: row.cnt for row in src_result}

        # Top techniques (derived from title)
        tech_result = await db.execute(
            select(GeneratedEvent.title, func.count().label("cnt"))
            .where(GeneratedEvent.session_id == uuid.UUID(session_id))
            .group_by(GeneratedEvent.title)
            .order_by(desc(func.count()))
            .limit(10)
        )
        top_techniques = [
            {"technique_id": row.title, "count": row.cnt} for row in tech_result
        ]

        # Events per minute: based on created_at range
        range_result = await db.execute(
            select(
                func.min(GeneratedEvent.created_at).label("first"),
                func.max(GeneratedEvent.created_at).label("last"),
            ).where(GeneratedEvent.session_id == uuid.UUID(session_id))
        )
        range_row = range_result.one_or_none()
        events_per_minute = 0.0
        if range_row and range_row.first and range_row.last and total_events > 1:
            elapsed_seconds = (range_row.last - range_row.first).total_seconds()
            if elapsed_seconds > 0:
                events_per_minute = round(total_events / (elapsed_seconds / 60), 2)

    return {
        "session_id": session_id,
        "total_events": total_events,
        "by_severity": by_severity,
        "by_source": by_source,
        "top_techniques": top_techniques,
        "events_per_minute": events_per_minute,
    }


@router.get("/{session_id}/events")
async def get_session_events(
    session_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    severity: str | None = Query(None),
):
    """Get generated events for a session with pagination."""
    await _get_or_404(session_id)
    async with async_session() as session:
        query = (
            select(GeneratedEvent)
            .where(GeneratedEvent.session_id == uuid.UUID(session_id))
            .order_by(desc(GeneratedEvent.created_at))
        )
        if severity:
            query = query.where(GeneratedEvent.severity == severity)
        query = query.offset(skip).limit(limit)

        result = await session.execute(query)
        events = result.scalars().all()

        count_result = await session.execute(
            select(func.count()).select_from(GeneratedEvent).where(
                GeneratedEvent.session_id == uuid.UUID(session_id)
            )
        )
        total = count_result.scalar() or 0

    return {
        "session_id": session_id,
        "events": [_event_to_dict(e) for e in events],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_or_404(session_id: str) -> SimulationSession:
    try:
        uid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(400, detail="Invalid session ID format.")
    async with async_session() as session:
        result = await session.execute(
            select(SimulationSession).where(SimulationSession.id == uid)
        )
        s = result.scalar_one_or_none()
    if not s:
        raise HTTPException(404, detail=f"Session '{session_id}' not found.")
    return s


async def _do_stop(session_id: str) -> None:
    async with async_session() as session:
        result = await session.execute(
            select(SimulationSession).where(
                SimulationSession.id == uuid.UUID(session_id)
            )
        )
        s = result.scalar_one_or_none()
        if s and s.status == "running":
            s.status = "stopped"
            s.updated_at = datetime.now(timezone.utc)
            await session.commit()
    try:
        from backend.engine.session_manager import get_session_manager
        mgr = get_session_manager()
        await mgr.stop_session(session_id)
    except Exception:
        pass


def _session_to_dict(s: SimulationSession) -> dict[str, Any]:
    return {
        "id": str(s.id),
        "name": s.name,
        "status": s.status,
        "config": s.config or {},
        "events_sent": s.events_sent,
        "errors": s.errors,
        "last_event_at": s.last_event_at.isoformat() if s.last_event_at else None,
        "created_at": s.created_at.isoformat(),
        "updated_at": s.updated_at.isoformat(),
    }


def _event_to_dict(e: GeneratedEvent) -> dict[str, Any]:
    return {
        "id": str(e.id),
        "session_id": str(e.session_id),
        "product_type": e.product_type,
        "severity": e.severity,
        "title": e.title,
        "success": e.success,
        "status_code": e.status_code,
        "created_at": e.created_at.isoformat(),
    }
