"""IBM QRadar REST API emulation.

Mimics QRadar's REST API so Joti's QRadar connector can search AQL,
list offenses, and add items to reference sets.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from fastapi import APIRouter, Body, Header, Query

from backend.engine.action_executor import execute_action

router = APIRouter(prefix="/api/vendor/qradar", tags=["vendor:qradar"])

_searches: dict[str, dict[str, Any]] = {}


# ── Auth ─────────────────────────────────────────────────────────────────────

@router.get("/api/config/access/authorized_services")
async def check_auth(sec: Optional[str] = Header(None)):
    return [{"id": 1, "name": "sim-service", "user_id": 1}]


# ── AQL Search ────────────────────────────────────────────────────────────────

@router.post("/api/ariel/searches")
async def start_aql_search(
    session_id: Optional[str] = Query(None),
    query_expression: str = Body(default="SELECT * FROM events LAST 60 MINUTES"),
):
    cursor_id = hashlib.md5(f"{session_id}:{query_expression}:{time.time()}".encode()).hexdigest()[:16]
    _searches[cursor_id] = {
        "cursor_id": cursor_id,
        "status": "COMPLETED",
        "progress": 100,
        "session_id": session_id,
        "query_expression": query_expression,
        "record_count": 0,
        "_results": [],
    }
    if session_id:
        results = await _run_aql(session_id, query_expression)
        _searches[cursor_id]["record_count"] = len(results)
        _searches[cursor_id]["_results"] = results
    return {"cursor_id": cursor_id, "status": "COMPLETED", "progress": 100}


@router.get("/api/ariel/searches/{cursor_id}")
async def get_search_status(cursor_id: str):
    s = _searches.get(cursor_id, {"cursor_id": cursor_id, "status": "COMPLETED", "progress": 100, "record_count": 0})
    return s


@router.get("/api/ariel/searches/{cursor_id}/results")
async def get_search_results(
    cursor_id: str,
    Range: str = Header(default="items=0-49"),
):
    s = _searches.get(cursor_id, {})
    # Parse Range header: items=0-49
    start, end = 0, 49
    try:
        r = Range.replace("items=", "")
        start, end = int(r.split("-")[0]), int(r.split("-")[1])
    except Exception:
        pass
    results = (s.get("_results") or [])[start : end + 1]
    return {"events": results}


async def _run_aql(session_id: str, aql: str) -> list[dict]:
    """Simplified AQL execution — treat it like a filter on stored events."""
    from backend.db.models import GeneratedEvent
    from backend.db.session import async_session
    from sqlalchemy import select

    import re
    minutes = 60
    m = re.search(r"LAST\s+(\d+)\s+MINUTES", aql, re.IGNORECASE)
    if m:
        minutes = int(m.group(1))
    h = re.search(r"LAST\s+(\d+)\s+HOURS", aql, re.IGNORECASE)
    if h:
        minutes = int(h.group(1)) * 60

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    async with async_session() as db:
        rows = (await db.execute(
            select(GeneratedEvent)
            .where(GeneratedEvent.session_id == uuid.UUID(session_id))
            .where(GeneratedEvent.created_at >= cutoff.replace(tzinfo=None))
            .order_by(GeneratedEvent.created_at.desc())
            .limit(500)
        )).scalars().all()

    results = []
    for row in rows:
        payload = row.payload or {}
        results.append({
            "startTime": int(row.created_at.timestamp() * 1000) if row.created_at else 0,
            "sourceIP": payload.get("src_ip") or "10.0.0.1",
            "destinationIP": payload.get("dst_ip") or payload.get("dst") or "192.168.1.1",
            "eventId": str(uuid.uuid5(uuid.NAMESPACE_DNS, str(row.id))),
            "categoryId": 5000,
            "eventCount": 1,
            "deviceType": 18,
            "deviceVendor": row.product_type or "simulation",
            "logSourceName": row.product_type or "PurpleLab",
            "QIDNAME": payload.get("event_title") or row.title or "Simulated Event",
            "severity": row.severity or "info",
            "technique": row.title or "",
            "username": payload.get("user") or payload.get("UserName") or "",
            "hostname": payload.get("hostname") or payload.get("ComputerName") or "",
            **{k: str(v) for k, v in payload.items() if not k.startswith("_") and isinstance(v, (str, int, float, bool))},
        })
    return results


# ── Offenses ──────────────────────────────────────────────────────────────────

@router.get("/api/siem/offenses")
async def list_offenses(
    session_id: Optional[str] = Query(None),
    filter: Optional[str] = Query(None),
    Range: str = Header(default="items=0-19"),
):
    if not session_id:
        return []
    from backend.engine.edr_state_machine import get_machine
    machine = get_machine(session_id)
    snap = machine.snapshot()
    offenses = []
    i = 0
    for hostname, state in snap.items():
        if state in ("compromised", "at_risk"):
            offenses.append({
                "id": i + 1,
                "description": f"Potential compromise: {hostname}",
                "event_count": 15,
                "flow_count": 3,
                "device_count": 1,
                "severity": 8 if state == "compromised" else 5,
                "magnitude": 6,
                "status": "OPEN",
                "start_time": int(time.time() * 1000 - 3600000),
                "last_updated_time": int(time.time() * 1000),
                "source_network_name": "Corp",
                "category_count": 2,
                "offense_type": 0,
                "closing_reason_id": None,
                "local_destination_count": 1,
                "remote_destination_count": 0,
                "source_address_ids": [i + 1],
                "local_destination_address_ids": [i + 2],
                "assigned_to": None,
                "protected": False,
                "rules": [{"id": 100 + i, "type": "CRE_RULE"}],
                "hostname": hostname,
            })
            i += 1
    return offenses


@router.post("/api/siem/offenses/{offense_id}")
async def update_offense(offense_id: int, body: dict = Body(default={})):
    return {"id": offense_id, "status": body.get("status", "OPEN"), **body}


# ── Reference Sets (Block IOC) ────────────────────────────────────────────────

@router.post("/api/reference_data/sets/{set_name}")
async def add_to_reference_set(
    set_name: str,
    session_id: Optional[str] = Query(None),
    value: str = Query(...),
):
    """Add an IOC to a QRadar reference set (used for blocking)."""
    if session_id:
        ioc_type = "ip" if any(c.isdigit() and c == "." for c in value) else "domain"
        result = await execute_action(session_id, "block_ioc", {
            "ioc_type": ioc_type,
            "ioc_value": value,
            "reference_set": set_name,
            "actor": "joti_soar",
        })
        return {"name": set_name, "element_type": "IP", "number_of_elements": 1, "value": value, "_simulation": result.dict()}
    return {"name": set_name, "element_type": "IP", "number_of_elements": 1, "value": value}


@router.get("/api/reference_data/sets/{set_name}")
async def get_reference_set(set_name: str):
    return {"name": set_name, "element_type": "IP", "number_of_elements": 0, "data": {}}


# ── Log Sources ───────────────────────────────────────────────────────────────

@router.get("/api/config/event_sources/log_source_management/log_sources")
async def list_log_sources(session_id: Optional[str] = Query(None)):
    sources = [
        {"id": 1, "name": "PurpleLab EDR", "type_id": 18, "status": {"status": "SUCCESS"}, "protocol_type_id": 0},
        {"id": 2, "name": "PurpleLab Auth", "type_id": 25, "status": {"status": "SUCCESS"}, "protocol_type_id": 0},
        {"id": 3, "name": "PurpleLab Firewall", "type_id": 105, "status": {"status": "SUCCESS"}, "protocol_type_id": 0},
    ]
    return sources
