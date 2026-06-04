"""Microsoft Defender for Endpoint API emulation.

Mimics the Microsoft Defender API (graph.microsoft.com/v1.0/security/)
so Joti's Defender connector can isolate endpoints, block hashes,
and list alerts in the simulation.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Query

from backend.engine.action_executor import execute_action
from backend.engine.edr_state_machine import get_machine

router = APIRouter(prefix="/api/vendor/defender", tags=["vendor:defender"])


# ── Auth ─────────────────────────────────────────────────────────────────────

@router.post("/oauth2/v2.0/token")
async def get_token(body: dict = Body(default={})):
    return {
        "token_type": "Bearer",
        "access_token": f"mde-sim-token-{uuid.uuid4().hex[:20]}",
        "expires_in": 3600,
    }


# ── Machines / Endpoints ──────────────────────────────────────────────────────

@router.get("/api/machines")
async def list_machines(session_id: Optional[str] = Query(None)):
    if not session_id:
        return {"value": []}
    machine = get_machine(session_id)
    snap = machine.snapshot()
    machines = []
    for i, (hostname, state) in enumerate(snap.items()):
        machines.append({
            "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"mde:{session_id}:{hostname}")),
            "computerDnsName": hostname,
            "firstSeen": datetime.now(timezone.utc).isoformat(),
            "lastSeen": datetime.now(timezone.utc).isoformat(),
            "osPlatform": "Windows10",
            "osVersion": "10.0.19044.1826",
            "healthStatus": "Active",
            "onboardingStatus": "Onboarded",
            "riskScore": "High" if state in ("compromised",) else ("Medium" if state == "at_risk" else "Low"),
            "exposureLevel": "Medium",
            "isAadJoined": True,
            "machineTags": [],
            "isolationStatus": "Isolated" if state == "isolated" else "NotIsolated",
        })
    return {"value": machines}


@router.post("/api/machines/{machine_id}/isolate")
async def isolate_machine(
    machine_id: str,
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    """Isolate an endpoint from the network."""
    if not session_id:
        return {"error": "session_id required"}

    machine = get_machine(session_id)
    snap = machine.snapshot()
    target = None
    for hostname in snap:
        computed = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"mde:{session_id}:{hostname}"))
        if computed == machine_id or hostname == machine_id:
            target = hostname
            break

    if not target and snap:
        target = list(snap.keys())[0]

    if target:
        result = await execute_action(session_id, "isolate_host", {
            "hostname": target,
            "actor": "joti_soar",
            "comment": body.get("Comment", "Isolated via Defender API"),
        })
        return {
            "id": str(uuid.uuid4()),
            "type": "Isolate",
            "requestorComment": body.get("Comment", ""),
            "status": "Pending",
            "machineId": machine_id,
            "computerDnsName": target,
            "creationDateTimeUtc": datetime.now(timezone.utc).isoformat(),
            "lastUpdateDateTimeUtc": datetime.now(timezone.utc).isoformat(),
            "_simulation": result.dict(),
        }
    return {"error": "Machine not found in simulation"}


@router.post("/api/machines/{machine_id}/unisolate")
async def unisolate_machine(
    machine_id: str,
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    machine = get_machine(session_id or "")
    snap = machine.snapshot()
    target = next((h for h in snap if str(uuid.uuid5(uuid.NAMESPACE_DNS, f"mde:{session_id}:{h}")) == machine_id or h == machine_id), None)
    if target:
        result = await execute_action(session_id or "", "release_host", {"hostname": target, "actor": "joti_soar"})
        return {"status": "Pending", "type": "Unisolate", "machineId": machine_id, "_simulation": result.dict()}
    return {"error": "Machine not found"}


@router.post("/api/machines/{machine_id}/stopAndQuarantineFile")
async def stop_and_quarantine(
    machine_id: str,
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    sha256 = body.get("Sha256", "")
    if session_id and sha256:
        result = await execute_action(session_id, "quarantine_file", {
            "sha256": sha256,
            "machine_id": machine_id,
            "actor": "joti_soar",
        })
        return {"type": "StopAndQuarantineFile", "status": "Pending", "sha256": sha256, "_simulation": result.dict()}
    return {"type": "StopAndQuarantineFile", "status": "Pending"}


# ── Indicators (Block IOC) ────────────────────────────────────────────────────

@router.post("/api/indicators")
async def create_indicator(
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    """Block an IP, domain, URL, or file hash."""
    indicator_value = body.get("indicatorValue") or body.get("value", "")
    indicator_type = body.get("indicatorType", "IpAddress")
    action = body.get("action", "BlockAndRemediate")

    if session_id and indicator_value:
        ioc_type_map = {"IpAddress": "ip", "DomainName": "domain", "Url": "url",
                        "FileSha256": "sha256", "FileSha1": "sha1", "FileMd5": "md5"}
        result = await execute_action(session_id, "block_ioc", {
            "ioc_type": ioc_type_map.get(indicator_type, "ip"),
            "ioc_value": indicator_value,
            "action": action,
            "actor": "joti_soar",
        })
        return {
            "id": str(uuid.uuid4()),
            "indicatorValue": indicator_value,
            "indicatorType": indicator_type,
            "action": action,
            "severity": body.get("severity", "High"),
            "creationTimeDateTimeUtc": datetime.now(timezone.utc).isoformat(),
            "_simulation": result.dict(),
        }
    return {"id": str(uuid.uuid4()), "indicatorValue": indicator_value, "action": action}


@router.get("/api/indicators")
async def list_indicators(session_id: Optional[str] = Query(None)):
    return {"value": []}


# ── Alerts ────────────────────────────────────────────────────────────────────

@router.get("/api/alerts")
async def list_alerts(
    session_id: Optional[str] = Query(None),
    limit: int = Query(50),
):
    if not session_id:
        return {"value": []}

    from backend.db.models import GeneratedEvent
    from backend.db.session import async_session
    from sqlalchemy import select

    async with async_session() as db:
        rows = (await db.execute(
            select(GeneratedEvent)
            .where(GeneratedEvent.session_id == uuid.UUID(session_id))
            .where(GeneratedEvent.severity.in_(["high", "critical"]))
            .order_by(GeneratedEvent.created_at.desc())
            .limit(limit)
        )).scalars().all()

    alerts = []
    for row in rows:
        payload = row.payload or {}
        alerts.append({
            "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, str(row.id))),
            "title": payload.get("alert_name") or payload.get("event_title") or row.title or "Alert",
            "description": f"Simulated detection: {row.title}",
            "severity": (row.severity or "High").capitalize(),
            "status": "New",
            "category": "Execution",
            "mitreTechniques": [row.title] if row.title and row.title.startswith("T") else [],
            "computerDnsName": payload.get("hostname") or payload.get("ComputerName") or "sim-host",
            "alertCreationTime": row.created_at.isoformat() if row.created_at else "",
            "firstEventTime": row.created_at.isoformat() if row.created_at else "",
            "lastEventTime": row.created_at.isoformat() if row.created_at else "",
        })
    return {"value": alerts}
