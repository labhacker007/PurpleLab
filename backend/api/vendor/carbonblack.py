"""VMware Carbon Black EDR API emulation.

Supports both Carbon Black Response (CBC) and Carbon Black Cloud (CBC) API patterns.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Query

from backend.engine.action_executor import execute_action
from backend.engine.edr_state_machine import get_machine

router = APIRouter(prefix="/api/vendor/carbonblack", tags=["vendor:carbonblack"])


@router.get("/api/v1/sensor")
async def list_sensors(session_id: Optional[str] = Query(None)):
    """CB Response: list sensors (endpoints)."""
    if not session_id:
        return []
    machine = get_machine(session_id)
    snap = machine.snapshot()
    sensors = []
    for i, (hostname, state) in enumerate(snap.items()):
        sensors.append({
            "id": i + 1,
            "hostname": hostname,
            "status": "Online",
            "isolation_requested": state == "isolated",
            "is_isolating": state == "isolated",
            "os_environment_display_string": "Windows 10.0.19044 x64",
            "sensor_version": "7.4.0.12345",
            "computer_name": hostname,
            "registration_time": datetime.now(timezone.utc).isoformat(),
            "last_checkin_time": datetime.now(timezone.utc).isoformat(),
            "network_adapters": [{"ipaddr": f"10.0.0.{i + 10}", "macaddr": "aa:bb:cc:dd:ee:ff"}],
        })
    return sensors


@router.post("/api/v1/sensor/{sensor_id}")
async def update_sensor(
    sensor_id: int,
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    """Isolate (isolation_requested=true) or release sensor."""
    if not session_id:
        return {"id": sensor_id, "isolation_requested": body.get("isolation_requested", False)}

    machine = get_machine(session_id)
    snap = machine.snapshot()
    hostnames = list(snap.keys())
    target = hostnames[min(sensor_id - 1, len(hostnames) - 1)] if hostnames else None

    if target and body.get("isolation_requested"):
        result = await execute_action(session_id, "isolate_host", {"hostname": target, "actor": "joti_soar"})
        return {"id": sensor_id, "hostname": target, "isolation_requested": True, "_simulation": result.dict()}
    elif target and body.get("isolation_requested") is False:
        result = await execute_action(session_id, "release_host", {"hostname": target, "actor": "joti_soar"})
        return {"id": sensor_id, "hostname": target, "isolation_requested": False, "_simulation": result.dict()}
    return {"id": sensor_id, **body}


@router.post("/api/v1/banning/blacklist")
async def add_to_blacklist(
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    """CB Response: ban a process hash."""
    md5 = body.get("md5hash") or body.get("md5", "")
    if session_id and md5:
        result = await execute_action(session_id, "block_ioc", {
            "ioc_type": "md5",
            "ioc_value": md5,
            "actor": "joti_soar",
            "text": body.get("text", "Blocked via Carbon Black"),
        })
        return {"id": str(uuid.uuid4()), "md5hash": md5, "enabled": True, "_simulation": result.dict()}
    return {"id": str(uuid.uuid4()), "md5hash": md5, "enabled": True}


@router.get("/api/v1/banning/blacklist")
async def get_blacklist(session_id: Optional[str] = Query(None)):
    return []


# ── Carbon Black Cloud (new API) ──────────────────────────────────────────────

@router.get("/appservices/v6/orgs/{org_key}/devices/_search")
async def cbc_search_devices(org_key: str, session_id: Optional[str] = Query(None), body: dict = Body(default={})):
    if not session_id:
        return {"results": [], "num_found": 0}
    machine = get_machine(session_id)
    snap = machine.snapshot()
    results = []
    for i, (hostname, state) in enumerate(snap.items()):
        results.append({
            "id": i + 1,
            "name": hostname,
            "host_name": hostname,
            "status": "ACTIVE",
            "quarantined": state == "isolated",
            "os": "WINDOWS",
            "policy_name": "default",
            "last_contact_time": datetime.now(timezone.utc).isoformat(),
            "sensor_version": "3.9.1.1803",
        })
    return {"results": results, "num_found": len(results)}


@router.post("/appservices/v6/orgs/{org_key}/device_actions")
async def cbc_device_action(org_key: str, session_id: Optional[str] = Query(None), body: dict = Body(default={})):
    action_type = body.get("action_type", "")
    device_ids = body.get("device_id", [])
    if session_id and action_type == "QUARANTINE":
        machine = get_machine(session_id)
        snap = machine.snapshot()
        hostnames = list(snap.keys())
        results = []
        for did in device_ids:
            idx = int(str(did)) - 1 if str(did).isdigit() else 0
            target = hostnames[min(idx, len(hostnames) - 1)] if hostnames else None
            if target:
                result = await execute_action(session_id, "isolate_host", {"hostname": target, "actor": "joti_soar"})
                results.append({"device_id": did, "hostname": target, **result.dict()})
        return {"results": results}
    return {"action_type": action_type, "device_id": device_ids, "status": "COMPLETED"}


@router.post("/appservices/v6/orgs/{org_key}/reputations/hashes/_search")
async def cbc_reputation_search(org_key: str, session_id: Optional[str] = Query(None), body: dict = Body(default={})):
    return {"results": [], "num_found": 0}


@router.post("/appservices/v6/orgs/{org_key}/reputations/hashes")
async def cbc_block_hash(org_key: str, session_id: Optional[str] = Query(None), body: dict = Body(default={})):
    sha256 = body.get("sha256", "")
    if session_id and sha256:
        result = await execute_action(session_id, "block_ioc", {
            "ioc_type": "sha256",
            "ioc_value": sha256,
            "actor": "joti_soar",
            "override": body.get("override_list", "BLACK_LIST"),
        })
        return {"sha256": sha256, "override_list": "BLACK_LIST", "_simulation": result.dict()}
    return {"sha256": sha256, "override_list": "BLACK_LIST"}


@router.get("/appservices/v6/orgs/{org_key}/alerts/_search")
async def cbc_get_alerts(org_key: str, session_id: Optional[str] = Query(None)):
    if not session_id:
        return {"results": [], "num_found": 0}
    from backend.db.models import GeneratedEvent
    from backend.db.session import async_session
    from sqlalchemy import select
    async with async_session() as db:
        rows = (await db.execute(
            select(GeneratedEvent)
            .where(GeneratedEvent.session_id == uuid.UUID(session_id))
            .where(GeneratedEvent.severity.in_(["high", "critical"]))
            .limit(30)
        )).scalars().all()
    results = []
    for row in rows:
        payload = row.payload or {}
        results.append({
            "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, str(row.id))),
            "type": "THREAT",
            "backend_severity": (row.severity or "medium").upper(),
            "device_name": payload.get("hostname") or payload.get("ComputerName") or "sim-host",
            "process_name": payload.get("process_name") or "",
            "reason": payload.get("event_title") or row.title or "Simulated detection",
            "ioc_field": "process_name",
            "report_name": row.title or "",
            "create_time": row.created_at.isoformat() if row.created_at else "",
        })
    return {"results": results, "num_found": len(results)}
