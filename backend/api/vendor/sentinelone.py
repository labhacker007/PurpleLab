"""SentinelOne Singularity Platform API emulation.

Mimics the SentinelOne REST API so Joti's S1 connector can execute
EDR SOAR actions against the simulation.

Key endpoints:
  POST /web/api/v2.1/users/login     API token auth
  GET  /web/api/v2.1/agents          list endpoints
  POST /web/api/v2.1/agents/actions/disconnect  isolate
  POST /web/api/v2.1/agents/actions/reconnect   release
  GET  /web/api/v2.1/threats         list threats
  POST /web/api/v2.1/threats/mitigation/kill     kill threat
  POST /web/api/v2.1/restrictions    add IOC block
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Header, Query

from backend.engine.action_executor import execute_action
from backend.engine.edr_state_machine import get_machine

router = APIRouter(prefix="/api/vendor/sentinelone", tags=["vendor:sentinelone"])

_FAKE_TOKEN = "S1-" + uuid.uuid4().hex[:32]


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")


# ── Auth ─────────────────────────────────────────────────────────────────────

@router.post("/web/api/v2.1/users/login")
async def login(body: dict = Body(default={})):
    return {
        "data": {
            "token": _FAKE_TOKEN,
            "tokenExpiration": "2026-06-05T23:26:25.000000Z",
        }
    }


# ── Agents (endpoints) ────────────────────────────────────────────────────────

@router.get("/web/api/v2.1/agents")
async def list_agents(
    session_id: Optional[str] = Query(None),
    limit: int = Query(50),
    computerName: Optional[str] = Query(None),
):
    if not session_id:
        return {"data": [], "pagination": {"totalItems": 0}}

    machine = get_machine(session_id)
    snap = machine.snapshot()
    agents = []
    for i, (hostname, state) in enumerate(snap.items()):
        if computerName and computerName.lower() not in hostname.lower():
            continue
        agents.append({
            "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"s1:{session_id}:{hostname}")),
            "computerName": hostname,
            "osName": "Windows 10 Enterprise",
            "osType": "windows",
            "agentVersion": "23.1.3.10088",
            "isActive": True,
            "networkStatus": "disconnected" if state == "isolated" else "connected",
            "networkQuarantineEnabled": state == "isolated",
            "infected": state in ("compromised", "suspicious"),
            "machineType": "laptop",
            "domain": "corp.local",
            "externalIp": f"10.0.0.{10 + i}",
            "lastActiveDate": _ts(),
        })
    return {"data": agents[:limit], "pagination": {"totalItems": len(agents)}}


@router.post("/web/api/v2.1/agents/actions/disconnect")
async def isolate_agent(
    body: dict = Body(default={}),
    session_id: Optional[str] = Query(None),
):
    """Isolate (network-disconnect) one or more agents."""
    filter_ids = body.get("filter", {}).get("ids", [])
    hostname = body.get("filter", {}).get("computerName", str(filter_ids[0]) if filter_ids else "CORP-WS-01")
    if session_id:
        await execute_action(session_id, "isolate_host",
                             {"hostname": hostname, "actor": "sentinelone_api"})
    return {"data": {"affected": len(filter_ids) or 1}}


@router.post("/web/api/v2.1/agents/actions/reconnect")
async def release_agent(
    body: dict = Body(default={}),
    session_id: Optional[str] = Query(None),
):
    filter_ids = body.get("filter", {}).get("ids", [])
    hostname = body.get("filter", {}).get("computerName", str(filter_ids[0]) if filter_ids else "CORP-WS-01")
    if session_id:
        await execute_action(session_id, "release_host",
                             {"hostname": hostname, "actor": "sentinelone_api"})
    return {"data": {"affected": len(filter_ids) or 1}}


# ── Threats ───────────────────────────────────────────────────────────────────

@router.get("/web/api/v2.1/threats")
async def list_threats(
    session_id: Optional[str] = Query(None),
    limit: int = Query(25),
    resolved: Optional[bool] = Query(None),
):
    from backend.db.session import async_session
    from backend.db.models import GeneratedEvent
    from sqlalchemy import select as _select
    import uuid as _uuid

    threats = []
    if session_id:
        try:
            async with async_session() as db:
                q = (_select(GeneratedEvent)
                     .where(GeneratedEvent.session_id == _uuid.UUID(session_id))
                     .where(GeneratedEvent.severity.in_(["critical", "high"]))
                     .order_by(GeneratedEvent.created_at.desc())
                     .limit(limit))
                rows = (await db.execute(q)).scalars().all()
            for row in rows:
                payload = row.payload or {}
                threats.append({
                    "id": str(row.id),
                    "agentComputerName": payload.get("ComputerName", "CORP-WS-01"),
                    "classification": "Malware",
                    "classificationSource": "Engine",
                    "confidence": "malicious",
                    "createdAt": row.created_at.isoformat() if row.created_at else _ts(),
                    "mitigationStatus": "not_mitigated",
                    "threatName": payload.get("event_title", row.title or "Unknown Threat"),
                    "fileSha256": payload.get("sha256", ""),
                    "indicators": [{"description": row.title or ""}],
                })
        except Exception:
            pass

    return {"data": threats, "pagination": {"totalItems": len(threats)}}


@router.post("/web/api/v2.1/threats/mitigation/kill")
async def kill_threat(
    body: dict = Body(default={}),
    session_id: Optional[str] = Query(None),
):
    threat_ids = body.get("filter", {}).get("ids", [])
    if session_id:
        await execute_action(session_id, "kill_process",
                             {"process_name": "threat_process", "actor": "sentinelone_api"})
    return {"data": {"affected": len(threat_ids) or 1}}


# ── IOC Restrictions ──────────────────────────────────────────────────────────

@router.post("/web/api/v2.1/restrictions")
async def add_restriction(
    body: dict = Body(default={}),
    session_id: Optional[str] = Query(None),
):
    """Block an IOC (file hash, domain, IP, URL)."""
    ioc_type = body.get("type", "hash")
    ioc_value = body.get("value", "")
    if session_id and ioc_value:
        await execute_action(session_id, "block_ioc",
                             {"ioc_type": ioc_type, "ioc_value": ioc_value,
                              "actor": "sentinelone_api"})
    return {
        "data": {
            "id": uuid.uuid4().hex,
            "createdAt": _ts(),
            "type": ioc_type,
            "value": ioc_value,
            "status": "active",
        }
    }


@router.get("/web/api/v2.1/restrictions")
async def list_restrictions(
    type: Optional[str] = Query(None),
    limit: int = Query(20),
):
    return {"data": [], "pagination": {"totalItems": 0}}
