"""CrowdStrike Falcon API emulation.

Mimics the Falcon OAuth2 + REST API so Joti's CrowdStrike connector
can point to PurpleLab and execute real SOAR actions against the simulation.

Key endpoints:
  POST /oauth2/token                    OAuth2 token (always succeeds)
  GET  /devices/v1                      list simulated endpoints
  POST /devices/actions/v2              isolate / release / uninstall
  GET  /detects/queries/detects/v1      list detection IDs
  GET  /detects/entities/summaries/GET  get detection details
  POST /iocs/entities/iocs/v1           block / allow IOC
  GET  /incidents/queries/incidents/v1  list incidents
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Header, HTTPException, Query

from backend.engine.action_executor import execute_action, ActionResult
from backend.engine.edr_state_machine import get_machine, EndpointState

router = APIRouter(prefix="/api/vendor/crowdstrike", tags=["vendor:crowdstrike"])

_FAKE_TOKEN = "cs-sim-token-" + str(uuid.uuid4()).replace("-", "")[:20]


# ── Auth ─────────────────────────────────────────────────────────────────────

@router.post("/oauth2/token", include_in_schema=False)
async def get_token(
    client_id: str = Body(default="sim-client"),
    client_secret: str = Body(default="sim-secret"),
):
    return {
        "access_token": _FAKE_TOKEN,
        "token_type": "bearer",
        "expires_in": 1799,
    }


def _check_token(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(401, detail="Missing Authorization header")
    return authorization


# ── Devices / Endpoints ───────────────────────────────────────────────────────

@router.get("/devices/v1")
async def list_devices(
    session_id: Optional[str] = Query(None, description="PurpleLab session_id to scope results"),
):
    """List simulated endpoints in a session (mirrors Falcon /devices/v1)."""
    if not session_id:
        return {"resources": [], "meta": {"total": 0}}

    machine = get_machine(session_id)
    snap = machine.snapshot()
    resources = []
    for i, (hostname, state) in enumerate(snap.items()):
        resources.append({
            "device_id": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{session_id}:{hostname}")),
            "hostname": hostname,
            "status": state,
            "platform_name": "Windows",
            "os_version": "Windows Server 2019",
            "agent_version": "7.05.17009.0",
            "local_ip": f"10.0.0.{10 + i}",
            "groups": ["default"],
            "tags": [],
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "containment_status": "normal" if state not in ("isolated",) else "contained",
        })
    return {"resources": resources, "meta": {"total": len(resources)}}


@router.post("/devices/actions/v2")
async def device_action(
    action_name: str = Query(..., description="contain | lift_containment | hide_host"),
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    """Isolate or release a simulated endpoint."""
    ids = body.get("ids", [])
    if not ids:
        return {"resources": [], "errors": [{"message": "No device IDs provided"}]}

    results = []
    for device_id in ids:
        if action_name == "contain" and session_id:
            # Find hostname by device_id or use first available
            machine = get_machine(session_id)
            snap = machine.snapshot()
            target = None
            for hostname in snap:
                computed = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{session_id}:{hostname}"))
                if computed == device_id or hostname == device_id:
                    target = hostname
                    break
            if target:
                result = await execute_action(session_id, "isolate_host", {"hostname": target, "actor": "joti_soar"})
                results.append({"id": device_id, "hostname": target, "action": "contain", "result": result.dict()})
            else:
                results.append({"id": device_id, "action": "contain", "result": {"success": False, "message": "Device not found"}})

        elif action_name == "lift_containment" and session_id:
            machine = get_machine(session_id)
            snap = machine.snapshot()
            target = None
            for hostname in snap:
                computed = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{session_id}:{hostname}"))
                if computed == device_id or hostname == device_id:
                    target = hostname
                    break
            if target:
                result = await execute_action(session_id, "release_host", {"hostname": target, "actor": "joti_soar"})
                results.append({"id": device_id, "hostname": target, "action": "lift_containment", "result": result.dict()})
            else:
                results.append({"id": device_id, "action": "lift_containment", "result": {"success": False}})
        else:
            results.append({"id": device_id, "action": action_name, "result": {"success": True, "simulated": True}})

    return {"resources": results, "meta": {"total": len(results)}}


# ── Detections ────────────────────────────────────────────────────────────────

@router.get("/detects/queries/detects/v1")
async def list_detection_ids(
    session_id: Optional[str] = Query(None),
    limit: int = Query(50),
    offset: int = Query(0),
):
    """Return simulated detection IDs from a session."""
    if not session_id:
        return {"resources": [], "meta": {"pagination": {"total": 0}}}

    from backend.db.models import GeneratedEvent
    from backend.db.session import async_session
    from sqlalchemy import select

    async with async_session() as db:
        q = (select(GeneratedEvent)
             .where(GeneratedEvent.session_id == uuid.UUID(session_id))
             .where(GeneratedEvent.severity.in_(["high", "critical"]))
             .order_by(GeneratedEvent.created_at.desc())
             .offset(offset).limit(limit))
        rows = (await db.execute(q)).scalars().all()

    ids = [f"ldt:{str(r.id).replace('-', '')[:32]}:1" for r in rows]
    return {"resources": ids, "meta": {"pagination": {"total": len(ids), "offset": offset, "limit": limit}}}


@router.post("/detects/entities/summaries/GET")
async def get_detection_summaries(
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    """Get detection details for a list of detection IDs."""
    ids = body.get("ids", [])
    if not session_id or not ids:
        return {"resources": []}

    from backend.db.models import GeneratedEvent
    from backend.db.session import async_session
    from sqlalchemy import select

    async with async_session() as db:
        rows = (await db.execute(
            select(GeneratedEvent)
            .where(GeneratedEvent.session_id == uuid.UUID(session_id))
            .where(GeneratedEvent.severity.in_(["high", "critical"]))
            .limit(len(ids) * 2)
        )).scalars().all()

    resources = []
    for row in rows[:len(ids)]:
        payload = row.payload or {}
        resources.append({
            "detection_id": f"ldt:{str(row.id).replace('-', '')[:32]}:1",
            "composite_id": f"ldt:{str(row.id).replace('-', '')[:32]}:1",
            "cid": "sim-cid-0001",
            "detect_name": payload.get("alert_name") or payload.get("event_title") or row.title or "Unknown Detection",
            "detect_description": f"Simulated detection: {row.title}",
            "severity": 80 if row.severity == "critical" else 60,
            "severity_name": (row.severity or "High").capitalize(),
            "status": "new",
            "assigned_to_name": "",
            "technique_id": row.title or "",
            "tactic_id": "",
            "computer_name": payload.get("ComputerName") or payload.get("hostname") or "SIM-HOST",
            "user_name": payload.get("user") or payload.get("UserName") or "",
            "timestamp": row.created_at.isoformat() if row.created_at else "",
            "behaviors": [{"technique": row.title, "display_name": row.title or ""}],
            "device": {
                "device_id": str(uuid.uuid5(uuid.NAMESPACE_DNS, payload.get("hostname", "host"))),
                "hostname": payload.get("ComputerName") or payload.get("hostname") or "SIM-HOST",
            },
        })
    return {"resources": resources}


# ── IOC Management ────────────────────────────────────────────────────────────

@router.post("/iocs/entities/iocs/v1")
async def create_ioc(
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    """Block an IOC (IP, domain, hash) in the simulated environment."""
    resources = body.get("resources", [body])
    results = []
    for ioc in resources:
        ioc_type = ioc.get("type", "ipv4")
        ioc_value = ioc.get("value", "")
        action = ioc.get("action", "prevent")
        if session_id and ioc_value:
            result = await execute_action(session_id, "block_ioc", {
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "action": action,
                "actor": "joti_soar",
            })
            results.append({"id": str(uuid.uuid4()), "value": ioc_value, "type": ioc_type, "action": action, **result.dict()})
        else:
            results.append({"id": str(uuid.uuid4()), "value": ioc_value, "simulated": True})
    return {"resources": results}


@router.delete("/iocs/entities/iocs/v1")
async def delete_ioc(
    session_id: Optional[str] = Query(None),
    ids: list[str] = Query(default=[]),
):
    """Unblock/remove an IOC."""
    return {"resources": [{"id": i, "deleted": True} for i in ids]}


# ── Incidents ─────────────────────────────────────────────────────────────────

@router.get("/incidents/queries/incidents/v1")
async def list_incidents(
    session_id: Optional[str] = Query(None),
    limit: int = Query(20),
):
    if not session_id:
        return {"resources": [], "meta": {"total": 0}}
    machine = get_machine(session_id)
    snap = machine.snapshot()
    compromised = [h for h, s in snap.items() if s in ("compromised", "at_risk")]
    inc_ids = [f"inc:{str(uuid.uuid5(uuid.NAMESPACE_DNS, f'{session_id}:{h}')).replace('-', '')[:16]}" for h in compromised]
    return {"resources": inc_ids, "meta": {"total": len(inc_ids)}}
