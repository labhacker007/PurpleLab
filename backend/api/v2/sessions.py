"""Simulation session CRUD + start/stop endpoints — v2 API.

Fully wired to the PostgreSQL database via SQLAlchemy async sessions.
Sessions track attack chain runs, event generation counts, and lifecycle.
"""
from __future__ import annotations

import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Body, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc
from sqlalchemy.orm import selectinload

from backend.db.session import async_session
from backend.db.models import SimulationSession, GeneratedEvent
from backend.engine.session_manager import get_session_manager

router = APIRouter(prefix="/sessions", tags=["sessions"])
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SessionCreateRequest(BaseModel):
    name: str = Field("Untitled Session", max_length=255)
    config: dict[str, Any] = Field(default_factory=dict)
    # Optional structured simulation params (stored into config JSONB)
    environment_id: str | None = None
    simulation_mode: str = Field("attack_chain")  # attack_chain | threat_actor | ttps | mcp_ingest
    attack_chains: list[str] = Field(default_factory=list)
    event_count: int = Field(200, ge=10, le=2000)
    # Threat actor mode
    threat_actor_id: str | None = None
    threat_actor_name: str | None = None
    threat_actor_ttps: list[str] = Field(default_factory=list)
    # TTP mode
    technique_ids: list[str] = Field(default_factory=list)
    # MCP ingest mode
    mcp_server_url: str | None = None
    mcp_api_key: str | None = None
    mcp_tool: str = Field("siem_search_events")
    mcp_query: str | None = None
    # Auto-start after creation
    auto_start: bool = False


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
    """Create a new simulation session.

    All structured simulation params (mode, chains, technique_ids, etc.)
    are merged into the config JSONB so the engine can read them.
    """
    # Auto-generate a datetime-based name when the client sends the generic default
    session_name = req.name
    if not session_name or session_name in ("Untitled Session", ""):
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
        mode_label = {
            "attack_chain": "Attack Chain",
            "threat_actor": req.threat_actor_name or "Threat Actor",
            "ttps": "TTP Simulation",
            "mcp_ingest": "MCP Ingest",
        }.get(req.simulation_mode, req.simulation_mode.replace("_", " ").title())
        session_name = f"{mode_label} — {ts}"

    # Build merged config: explicit config dict + structured params
    merged_config = dict(req.config)
    merged_config.update({
        "simulation_mode": req.simulation_mode,
        "attack_chains": req.attack_chains,
        "event_count": req.event_count,
    })
    if req.environment_id:
        merged_config["environment_id"] = req.environment_id
    if req.threat_actor_id:
        merged_config["threat_actor_id"] = req.threat_actor_id
        merged_config["threat_actor_name"] = req.threat_actor_name or req.threat_actor_id
        merged_config["threat_actor_ttps"] = req.threat_actor_ttps
    if req.technique_ids:
        merged_config["technique_ids"] = req.technique_ids
    if req.simulation_mode == "mcp_ingest" and req.mcp_server_url:
        merged_config["mcp_server_url"] = req.mcp_server_url
        merged_config["mcp_api_key"] = req.mcp_api_key or ""
        merged_config["mcp_tool"] = req.mcp_tool
        merged_config["mcp_query"] = req.mcp_query or ""

    async with async_session() as session:
        new_session = SimulationSession(
            name=session_name,
            config=merged_config,
            status="stopped",
            events_sent=0,
            errors=0,
        )
        session.add(new_session)
        await session.commit()
        await session.refresh(new_session)

    result = _session_to_dict(new_session)

    if req.auto_start:
        try:
            from backend.engine.session_manager import get_session_manager
            sid = result["id"]
            # Update status to running
            async with async_session() as session:
                row = await session.get(SimulationSession, uuid.UUID(sid))
                if row:
                    row.status = "running"
                    row.updated_at = datetime.utcnow()
                    await session.commit()
            mgr = get_session_manager()
            await mgr.start_session(sid, merged_config)
            result["status"] = "running"
        except Exception as exc:
            logger.warning("auto_start failed for session %s: %s", result.get("id"), exc)

    return result


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
        s.updated_at = datetime.utcnow()
        await session.commit()
        await session.refresh(s)
    return _session_to_dict(s)


@router.patch("/{session_id}/rename")
async def rename_session(session_id: str, body: dict):
    """Rename a session. Body: {"name": "new name"}"""
    new_name = (body.get("name") or "").strip()
    if not new_name:
        raise HTTPException(400, detail="name is required")
    async with async_session() as session:
        result = await session.execute(
            select(SimulationSession).where(SimulationSession.id == uuid.UUID(session_id))
        )
        s = result.scalar_one_or_none()
        if not s:
            raise HTTPException(404, detail=f"Session '{session_id}' not found.")
        s.name = new_name[:255]
        s.updated_at = datetime.utcnow()
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
            s.updated_at = datetime.utcnow()
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


@router.post("/{session_id}/resolve-mcp")
async def resolve_mcp_source(session_id: str):
    """Call the configured external MCP server to retrieve logs/events.

    For sessions created with simulation_mode='mcp_ingest', this endpoint:
    1. Reads mcp_server_url, mcp_api_key, mcp_tool, mcp_query from session config
    2. Issues a JSON-RPC call to the external MCP server
    3. Parses events/alerts to extract MITRE technique IDs
    4. Updates session config with resolved technique_ids

    Returns extracted techniques + raw sample events.
    """
    s = await _get_or_404(session_id)
    cfg = s.config or {}

    mcp_url = cfg.get("mcp_server_url", "")
    mcp_key = cfg.get("mcp_api_key", "")
    mcp_tool = cfg.get("mcp_tool", "siem_search_events")
    mcp_query = cfg.get("mcp_query", "")

    if not mcp_url:
        raise HTTPException(400, detail="Session has no mcp_server_url configured.")

    # Build JSON-RPC payload for the tool call
    tool_args: dict[str, Any] = {}
    if mcp_tool == "siem_search_events":
        tool_args = {"query": mcp_query or "*", "time_range_hours": 24}
    elif mcp_tool == "siem_get_alerts":
        tool_args = {"limit": 50}
    elif mcp_tool == "edr_get_detections":
        tool_args = {"limit": 50}

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": mcp_tool, "arguments": tool_args},
    }

    headers = {"Content-Type": "application/json"}
    if mcp_key:
        headers["X-API-Key"] = mcp_key

    raw_events: list[dict] = []
    extracted_ttps: list[str] = []

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(mcp_url, json=payload, headers=headers)
            resp.raise_for_status()
            rpc_result = resp.json()

        content = rpc_result.get("result", {})
        if isinstance(content, dict):
            # Handle different response shapes
            raw_events = (
                content.get("events")
                or content.get("alerts")
                or content.get("detections")
                or []
            )
        elif isinstance(content, list):
            raw_events = content

        # Extract MITRE technique IDs from events
        known_ttps: set[str] = set()
        for ev in raw_events[:100]:
            if not isinstance(ev, dict):
                continue
            # Common fields: technique_id, mitre_technique, tags, rule_name
            for field in ("technique_id", "mitre_technique", "technique", "attack_technique"):
                val = ev.get(field, "")
                if val and str(val).upper().startswith("T"):
                    known_ttps.add(str(val).upper())
            # Parse tags array
            for tag in ev.get("tags", []):
                tag_str = str(tag)
                if tag_str.upper().startswith("T") and len(tag_str) >= 5:
                    known_ttps.add(tag_str.upper())

        extracted_ttps = sorted(known_ttps)

        # Update session config
        async with async_session() as db:
            row = await db.get(SimulationSession, uuid.UUID(session_id))
            if row:
                updated_cfg = dict(row.config or {})
                updated_cfg["resolved_technique_ids"] = extracted_ttps
                updated_cfg["mcp_event_count"] = len(raw_events)
                if extracted_ttps and not updated_cfg.get("technique_ids"):
                    updated_cfg["technique_ids"] = extracted_ttps
                row.config = updated_cfg
                row.updated_at = datetime.utcnow()
                await db.commit()

    except httpx.HTTPError as exc:
        raise HTTPException(502, detail=f"MCP server unreachable: {exc}")
    except Exception as exc:
        logger.warning("MCP resolve failed for session %s: %s", session_id, exc)
        raise HTTPException(500, detail=f"MCP resolve error: {exc}")

    return {
        "session_id": session_id,
        "mcp_tool": mcp_tool,
        "events_retrieved": len(raw_events),
        "extracted_techniques": extracted_ttps,
        "sample_events": raw_events[:5],
    }


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


@router.get("/{session_id}/topology")
async def get_session_topology(session_id: str):
    """Return the topology graph for this session's environment.

    Shows which product tiers are installed, which log sources they produce,
    and which MITRE techniques each tier can observe.  Useful for the frontend
    to render a product connectivity diagram and explain coverage gaps.
    """
    s = await _get_or_404(session_id)
    products: dict = {}
    technique_ids: list = []
    try:
        cfg = s.config or {}
        products = cfg.get("products") or {}
        technique_ids = cfg.get("technique_ids") or cfg.get("threat_actor_ttps") or []
        if not products:
            from backend.db.models import Environment
            env_id = cfg.get("environment_id")
            if env_id:
                async with async_session() as db_s:
                    env = await db_s.get(Environment, int(env_id))
                    if env and env.settings:
                        products = env.settings.get("products") or {}
    except Exception:
        pass

    from backend.engine.topology_graph import build_topology, TECHNIQUE_OBSERVERS
    graph = build_topology(products)
    graph_dict = graph.to_dict()

    # Add per-technique observer breakdown
    tech_coverage = {}
    for tid in technique_ids:
        nodes = graph.resolve_observers(tid)
        tech_coverage[tid] = [n.log_source for n in nodes]

    return {
        "session_id": session_id,
        "topology": graph_dict,
        "technique_coverage": tech_coverage,
        "coverage_gaps": [
            tid for tid, srcs in tech_coverage.items() if not srcs
        ],
    }


@router.get("/{session_id}/context")
async def get_session_context(session_id: str):
    """Return the SimulationContext entities for this session.

    Shows the victim user/hostname/IP, attacker IP/C2 domain, and whether
    values came from real CMDB data or were synthetically generated.
    Returns 404 if the session doesn't exist; returns an empty context dict
    if the session was created before SimulationContext support was added.
    """
    await _get_or_404(session_id)
    mgr = get_session_manager()
    # Check in-memory cache first (populated during start_session)
    cached = mgr._sessions.get(session_id, {})
    ctx = cached.get("simulation_context")
    if ctx is None:
        # Fall back to Redis
        try:
            import os
            import redis.asyncio as aioredis
            from backend.engine.simulation_context import load_context
            r = aioredis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0"), decode_responses=True)
            sim_ctx = await load_context(session_id, r)
            if sim_ctx:
                ctx = {
                    "victim_username": sim_ctx.victim_username,
                    "victim_hostname": sim_ctx.victim_hostname,
                    "victim_ip": sim_ctx.victim_ip,
                    "attacker_ip": sim_ctx.attacker_ip,
                    "c2_domain": sim_ctx.c2_domain,
                    "malware_filename": sim_ctx.malware_filename,
                    "domain": sim_ctx.domain,
                    "from_cmdb": sim_ctx.from_cmdb,
                }
        except Exception:
            pass
    return {"session_id": session_id, "context": ctx or {}}


# ---------------------------------------------------------------------------
# SIEM push — forward generated events to a configured SIEM connection
# ---------------------------------------------------------------------------

@router.post("/{session_id}/push-to-siem")
async def push_session_to_siem(session_id: str, body: dict = Body(default={})):
    """Push all GeneratedEvents from this session to a SIEM connection.

    Body (optional):
      connection_id — UUID of a SIEMConnection. If omitted, uses the first
                      available connection or auto-creates one pointing at the
                      bundled Splunk vendor simulation.

    Returns: {pushed, connection_id, connection_name, siem_type}
    """
    import os
    from sqlalchemy import select as sa_select
    from backend.db.models import SIEMConnection
    from backend.siem_integration.connection_manager import ConnectionManager

    await _get_or_404(session_id)

    async with async_session() as db:
        # Collect events
        q = (
            sa_select(GeneratedEvent)
            .where(GeneratedEvent.session_id == uuid.UUID(session_id))
            .order_by(GeneratedEvent.created_at)
        )
        result = await db.execute(q)
        events = result.scalars().all()

        if not events:
            return {"pushed": 0, "message": "No events to push"}

        # Resolve connection
        conn_id = body.get("connection_id")
        if conn_id:
            conn_row = await db.get(SIEMConnection, uuid.UUID(conn_id))
            if not conn_row:
                raise HTTPException(status_code=404, detail="SIEM connection not found")
        else:
            # Use first available connection
            r2 = await db.execute(sa_select(SIEMConnection).limit(1))
            conn_row = r2.scalars().first()

        if not conn_row:
            # Auto-create connection to bundled Splunk sim
            mgr = ConnectionManager()
            splunk_base = os.environ.get("SPLUNK_SIM_URL", "http://purplelab-backend:8000/api/vendor/splunk")
            conn_row_dict = await mgr.create_connection(
                name="PurpleLab Splunk Sim (auto)",
                siem_type="splunk",
                config_dict={
                    "base_url": splunk_base,
                    "hec_url": splunk_base,
                    "hec_token": "purplelab-sim-token",
                    "username": "admin",
                    "password": "changeme",
                },
            )
            conn_id = conn_row_dict["id"]
            conn_name = conn_row_dict["name"]
            siem_type = "splunk"
        else:
            conn_id = str(conn_row.id)
            conn_name = conn_row.name
            siem_type = conn_row.siem_type

    # Build normalised log payloads
    logs = []
    for ev in events:
        payload = ev.payload or {}
        logs.append({
            "timestamp": ev.created_at.isoformat(),
            "session_id": session_id,
            "title": ev.title or "",
            "severity": ev.severity or "medium",
            "product_type": ev.product_type or "",
            "technique_id": payload.get("technique_id", ""),
            "tactic": payload.get("tactic", ""),
            "host": payload.get("host", payload.get("hostname", "CORP-WS-001")),
            "user": payload.get("user", payload.get("username", "")),
            "src_ip": payload.get("src_ip", ""),
            "dest_ip": payload.get("dest_ip", ""),
            "process": payload.get("process", payload.get("cmdline", "")),
            "sourcetype": "purplelab",
            "index": "purplelab",
            **payload,
        })

    mgr = ConnectionManager()
    pushed = await mgr.push_logs(conn_id, logs)
    return {
        "pushed": pushed,
        "total_events": len(events),
        "connection_id": conn_id,
        "connection_name": conn_name,
        "siem_type": siem_type,
        "message": f"Pushed {pushed} events to {conn_name}",
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
    stopped_session = None
    async with async_session() as session:
        result = await session.execute(
            select(SimulationSession).where(
                SimulationSession.id == uuid.UUID(session_id)
            )
        )
        s = result.scalar_one_or_none()
        if s and s.status == "running":
            s.status = "stopped"
            s.updated_at = datetime.utcnow()
            await session.commit()
            stopped_session = s
    try:
        from backend.engine.session_manager import get_session_manager
        mgr = get_session_manager()
        await mgr.stop_session(session_id)
    except Exception:
        pass
    # Push simulation result to Joti so it flows through the alert pipeline
    if stopped_session is not None:
        try:
            from backend.joti.client import get_joti_client
            joti = get_joti_client()
            if joti:
                cfg = stopped_session.config or {}
                await joti.push_simulation_result({
                    "session_id": session_id,
                    "session_name": stopped_session.name or "Simulation",
                    "technique_ids": cfg.get("technique_ids") or cfg.get("ttps") or [],
                    "severity": cfg.get("severity", "medium"),
                    "events_generated": stopped_session.events_sent or 0,
                    "hit": True,
                    "summary": (
                        f"PurpleLab simulation '{stopped_session.name}' completed. "
                        f"{stopped_session.events_sent or 0} events generated."
                    ),
                })
        except Exception as _exc:
            import logging as _logging
            _logging.getLogger(__name__).debug("joti_push_failed: %s", _exc)


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
        "payload": e.payload or {},
        "success": e.success,
        "status_code": e.status_code,
        "created_at": e.created_at.isoformat(),
    }
