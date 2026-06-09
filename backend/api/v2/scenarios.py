"""Simulation Library — scenario and TTP template CRUD endpoints.

Endpoints:
  GET/POST     /v2/scenarios
  GET/PUT/DEL  /v2/scenarios/{id}
  POST         /v2/scenarios/{id}/replay
  POST         /v2/sessions/{session_id}/save-as-scenario
  GET/POST     /v2/ttp-library
  DELETE       /v2/ttp-library/{id}
"""
from __future__ import annotations

import uuid
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select

from backend.db.session import async_session
from backend.db.models import (
    SimulationScenario,
    TTPEventTemplate,
    SimulationSession,
    GeneratedEvent,
)

router = APIRouter(tags=["scenarios"])
log = logging.getLogger(__name__)


# ── Request / Response models ─────────────────────────────────────────────────

class ScenarioCreateRequest(BaseModel):
    name: str = Field(..., max_length=255)
    description: Optional[str] = None
    threat_actor_name: Optional[str] = None
    technique_ids: list[str] = Field(default_factory=list)
    events: list[dict[str, Any]] = Field(default_factory=list)
    asset_snapshot: Optional[dict[str, Any]] = None
    ioc_snapshot: Optional[list[dict[str, Any]]] = None
    source_session_id: Optional[str] = None
    environment_id: Optional[str] = None


class ScenarioUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None


class SaveAsScenarioRequest(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    threat_actor_name: Optional[str] = None
    technique_ids: list[str] = Field(default_factory=list)
    asset_snapshot: Optional[dict[str, Any]] = None
    ioc_snapshot: Optional[list[dict[str, Any]]] = None
    environment_id: Optional[str] = None


class TTPTemplateCreateRequest(BaseModel):
    technique_id: str = Field(..., max_length=20)
    tactic: Optional[str] = Field(None, max_length=50)
    log_source: str = Field(..., max_length=50)
    severity: str = Field("medium", max_length=20)
    title_template: str = Field(..., max_length=500)
    payload_template: dict[str, Any] = Field(default_factory=dict)
    variables: Optional[dict[str, str]] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _scenario_summary(row: SimulationScenario) -> dict[str, Any]:
    """Return a list-safe dict (no full events array)."""
    return {
        "id": str(row.id),
        "name": row.name,
        "description": row.description,
        "threat_actor_name": row.threat_actor_name,
        "technique_ids": row.technique_ids or [],
        "use_count": row.use_count,
        "event_count": len(row.events) if row.events else 0,
        "source_session_id": str(row.source_session_id) if row.source_session_id else None,
        "environment_id": str(row.environment_id) if row.environment_id else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def _scenario_full(row: SimulationScenario) -> dict[str, Any]:
    d = _scenario_summary(row)
    d["events"] = row.events or []
    d["asset_snapshot"] = row.asset_snapshot
    d["ioc_snapshot"] = row.ioc_snapshot
    return d


def _template_dict(row: TTPEventTemplate) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "technique_id": row.technique_id,
        "tactic": row.tactic,
        "log_source": row.log_source,
        "severity": row.severity,
        "title_template": row.title_template,
        "payload_template": row.payload_template,
        "variables": row.variables,
        "is_builtin": row.is_builtin,
        "hit_count": row.hit_count,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


# ── Scenario endpoints ────────────────────────────────────────────────────────

@router.get("/scenarios")
async def list_scenarios(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """List all scenarios, newest first."""
    async with async_session() as db:
        result = await db.execute(
            select(SimulationScenario)
            .order_by(SimulationScenario.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        rows = result.scalars().all()
    return {"scenarios": [_scenario_summary(r) for r in rows], "total": len(rows)}


@router.post("/scenarios", status_code=201)
async def create_scenario(body: ScenarioCreateRequest) -> dict[str, Any]:
    """Create a new scenario."""
    source_uuid: Optional[uuid.UUID] = None
    if body.source_session_id:
        try:
            source_uuid = uuid.UUID(body.source_session_id)
        except ValueError:
            pass

    env_uuid: Optional[uuid.UUID] = None
    if body.environment_id:
        try:
            env_uuid = uuid.UUID(body.environment_id)
        except ValueError:
            pass

    async with async_session() as db:
        row = SimulationScenario(
            name=body.name,
            description=body.description,
            threat_actor_name=body.threat_actor_name,
            technique_ids=body.technique_ids,
            events=body.events,
            asset_snapshot=body.asset_snapshot,
            ioc_snapshot=body.ioc_snapshot,
            source_session_id=source_uuid,
            environment_id=env_uuid,
            use_count=0,
        )
        db.add(row)
        await db.commit()
        await db.refresh(row)
        return _scenario_full(row)


@router.get("/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str) -> dict[str, Any]:
    """Get full scenario including events array."""
    try:
        sid = uuid.UUID(scenario_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Scenario not found")

    async with async_session() as db:
        row = await db.get(SimulationScenario, sid)
        if row is None:
            raise HTTPException(status_code=404, detail="Scenario not found")
        return _scenario_full(row)


@router.put("/scenarios/{scenario_id}")
async def update_scenario(scenario_id: str, body: ScenarioUpdateRequest) -> dict[str, Any]:
    """Update name and/or description of a scenario."""
    try:
        sid = uuid.UUID(scenario_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Scenario not found")

    async with async_session() as db:
        row = await db.get(SimulationScenario, sid)
        if row is None:
            raise HTTPException(status_code=404, detail="Scenario not found")
        if body.name is not None:
            row.name = body.name
        if body.description is not None:
            row.description = body.description
        await db.commit()
        await db.refresh(row)
        return _scenario_full(row)


@router.delete("/scenarios/{scenario_id}", status_code=204)
async def delete_scenario(scenario_id: str) -> None:
    """Delete a scenario."""
    try:
        sid = uuid.UUID(scenario_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Scenario not found")

    async with async_session() as db:
        row = await db.get(SimulationScenario, sid)
        if row is None:
            raise HTTPException(status_code=404, detail="Scenario not found")
        await db.delete(row)
        await db.commit()


@router.post("/scenarios/{scenario_id}/replay", status_code=201)
async def replay_scenario(scenario_id: str) -> dict[str, Any]:
    """Create a new SimulationSession by replaying a scenario's events.

    All event timestamps are re-anchored to now() while preserving original
    relative spacing. Returns the new session dict.
    """
    try:
        sid = uuid.UUID(scenario_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Scenario not found")

    async with async_session() as db:
        row = await db.get(SimulationScenario, sid)
        if row is None:
            raise HTTPException(status_code=404, detail="Scenario not found")

        events: list[dict[str, Any]] = list(row.events or [])
        if not events:
            raise HTTPException(status_code=400, detail="Scenario has no events to replay")

        # Anchor: parse first event's timestamp to compute offsets (always naive UTC)
        first_ts: Optional[datetime] = None
        for evt in events:
            ts_str = evt.get("timestamp") or evt.get("created_at") or ""
            if ts_str:
                try:
                    parsed = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    # Strip timezone so arithmetic stays in naive UTC
                    first_ts = parsed.replace(tzinfo=None)
                    break
                except ValueError:
                    pass

        now = datetime.utcnow()
        new_session = SimulationSession(
            name=f"Replay: {row.name}",
            config={
                "source_scenario_id": str(row.id),
                "threat_actor_name": row.threat_actor_name,
                "threat_actor_ttps": row.technique_ids or [],
                "environment_id": str(row.environment_id) if row.environment_id else None,
                "simulation_mode": "scenario_replay",
            },
            status="completed",
            events_sent=0,
            errors=0,
            stopped_at=now,
        )
        db.add(new_session)
        await db.flush()  # get new_session.id

        # Bulk insert re-timed GeneratedEvent rows
        inserted = 0
        for evt in events:
            # Compute offset from scenario's first event
            offset_seconds = 0
            ts_str = evt.get("timestamp") or evt.get("created_at") or ""
            if ts_str and first_ts is not None:
                try:
                    parsed = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    parsed_naive = parsed.replace(tzinfo=None)
                    offset_seconds = int((parsed_naive - first_ts).total_seconds())
                    if offset_seconds < 0:
                        offset_seconds = 0
                except ValueError:
                    pass

            new_ts = now + timedelta(seconds=offset_seconds)

            payload = dict(evt.get("payload") or {})
            payload["_replayed_from"] = str(row.id)
            payload["_simulated"] = True

            gen_evt = GeneratedEvent(
                session_id=new_session.id,
                product_type=evt.get("source_type", evt.get("product_type", "generic")),
                severity=evt.get("severity", "medium"),
                title=evt.get("technique_id") or evt.get("title", ""),
                payload=payload,
                target_url="",
                status_code=200,
                success=True,
                created_at=new_ts,
            )
            db.add(gen_evt)
            inserted += 1

        new_session.events_sent = inserted
        new_session.last_event_at = now

        # Increment use_count on the scenario
        row.use_count = (row.use_count or 0) + 1

        await db.commit()
        await db.refresh(new_session)

        return {
            "session_id": str(new_session.id),
            "name": new_session.name,
            "status": new_session.status,
            "config": new_session.config or {},
            "events_sent": new_session.events_sent,
            "errors": new_session.errors,
            "source_scenario_id": str(row.id),
            "created_at": new_session.created_at.isoformat() if new_session.created_at else None,
        }


# ── Save session as scenario ──────────────────────────────────────────────────

@router.post("/sessions/{session_id}/save-as-scenario", status_code=201)
async def save_session_as_scenario(
    session_id: str,
    body: SaveAsScenarioRequest,
) -> dict[str, Any]:
    """Save all GeneratedEvents for a session as a new SimulationScenario.

    Name, description, and metadata come from the request body.
    The events array is built from the session's GeneratedEvent rows.
    """
    try:
        sess_uuid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found")

    async with async_session() as db:
        session_row = await db.get(SimulationSession, sess_uuid)
        if session_row is None:
            raise HTTPException(status_code=404, detail="Session not found")

        # Load all events for this session, ordered by created_at
        result = await db.execute(
            select(GeneratedEvent)
            .where(GeneratedEvent.session_id == sess_uuid)
            .order_by(GeneratedEvent.created_at.asc())
        )
        event_rows = result.scalars().all()

        # Build the events list from DB rows
        events_list: list[dict[str, Any]] = []
        for ev in event_rows:
            events_list.append({
                "source_type": ev.product_type,
                "technique_id": ev.title,  # title stores technique_id per session_manager pattern
                "severity": ev.severity,
                "title": ev.payload.get("event_title", ev.title) if ev.payload else ev.title,
                "timestamp": ev.created_at.isoformat() if ev.created_at else None,
                "payload": ev.payload or {},
            })

        # Extract metadata from session config if not supplied in body
        session_config = session_row.config or {}
        threat_actor_name = body.threat_actor_name or session_config.get("threat_actor_name")
        technique_ids = body.technique_ids or (
            session_config.get("technique_ids")
            or session_config.get("threat_actor_ttps")
            or []
        )

        source_uuid: Optional[uuid.UUID] = None
        try:
            source_uuid = uuid.UUID(session_id)
        except ValueError:
            pass

        env_uuid: Optional[uuid.UUID] = None
        env_id_str = body.environment_id or session_config.get("environment_id")
        if env_id_str:
            try:
                env_uuid = uuid.UUID(str(env_id_str))
            except ValueError:
                pass

        # Auto-generate name from session if not provided
        scenario_name = body.name or f"Scenario: {session_row.name}"

        scenario = SimulationScenario(
            name=scenario_name,
            description=body.description,
            threat_actor_name=threat_actor_name,
            technique_ids=technique_ids,
            events=events_list,
            asset_snapshot=body.asset_snapshot,
            ioc_snapshot=body.ioc_snapshot,
            source_session_id=source_uuid,
            environment_id=env_uuid,
            use_count=0,
        )
        db.add(scenario)
        await db.commit()
        await db.refresh(scenario)
        return _scenario_full(scenario)


# ── TTP Template library endpoints ────────────────────────────────────────────

@router.get("/ttp-library")
async def list_ttp_templates(
    technique_id: Optional[str] = Query(None, description="Filter by technique_id"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """List TTP event templates, optionally filtered by technique_id."""
    async with async_session() as db:
        query = (
            select(TTPEventTemplate)
            .order_by(TTPEventTemplate.technique_id.asc(), TTPEventTemplate.hit_count.desc())
            .limit(limit)
            .offset(offset)
        )
        if technique_id:
            query = query.where(TTPEventTemplate.technique_id == technique_id)

        result = await db.execute(query)
        rows = result.scalars().all()

    return {
        "templates": [_template_dict(r) for r in rows],
        "total": len(rows),
    }


@router.post("/ttp-library", status_code=201)
async def create_ttp_template(body: TTPTemplateCreateRequest) -> dict[str, Any]:
    """Create a custom (non-builtin) TTP event template."""
    async with async_session() as db:
        row = TTPEventTemplate(
            technique_id=body.technique_id,
            tactic=body.tactic,
            log_source=body.log_source,
            severity=body.severity,
            title_template=body.title_template,
            payload_template=body.payload_template,
            variables=body.variables,
            is_builtin=False,
            hit_count=0,
        )
        db.add(row)
        await db.commit()
        await db.refresh(row)
        return _template_dict(row)


@router.delete("/ttp-library/{template_id}", status_code=204)
async def delete_ttp_template(template_id: str) -> None:
    """Delete a TTP template. Only non-builtin templates can be deleted."""
    try:
        tid = uuid.UUID(template_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Template not found")

    async with async_session() as db:
        row = await db.get(TTPEventTemplate, tid)
        if row is None:
            raise HTTPException(status_code=404, detail="Template not found")
        if row.is_builtin:
            raise HTTPException(status_code=400, detail="Cannot delete a builtin template")
        await db.delete(row)
        await db.commit()
