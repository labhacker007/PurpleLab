"""Palo Alto XSIAM / XSOAR API emulation.

Mimics the Cortex XSIAM public API and XSOAR REST API for
alert management, XQL queries, endpoint isolation, and indicator blocking.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from fastapi import APIRouter, Body, Header, Query

from backend.engine.action_executor import execute_action
from backend.engine.edr_state_machine import get_machine

router = APIRouter(prefix="/api/vendor/xsiam", tags=["vendor:xsiam"])


# ── Auth ─────────────────────────────────────────────────────────────────────

@router.post("/public_api/v1/auth/get_token")
async def get_token(body: dict = Body(default={})):
    return {"reply": {"token": f"xsiam-sim-{uuid.uuid4().hex[:20]}", "expiration_epoch": 9999999999}}


def _xsiam_response(data: Any) -> dict:
    return {"reply": data, "status": 200}


# ── XQL Search ────────────────────────────────────────────────────────────────

_xql_jobs: dict[str, dict[str, Any]] = {}


@router.post("/public_api/v1/xql/start_xql_query")
async def start_xql_query(
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    """Start an XQL query against simulated data."""
    query = body.get("request_data", {}).get("query", "")
    job_id = uuid.uuid4().hex[:16]
    results: list[dict] = []

    if session_id and query:
        from backend.db.models import GeneratedEvent
        from backend.db.session import async_session
        from sqlalchemy import select

        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
        async with async_session() as db:
            rows = (await db.execute(
                select(GeneratedEvent)
                .where(GeneratedEvent.session_id == uuid.UUID(session_id))
                .where(GeneratedEvent.created_at >= cutoff.replace(tzinfo=None))
                .order_by(GeneratedEvent.created_at.desc())
                .limit(200)
            )).scalars().all()

        for row in rows:
            payload = row.payload or {}
            results.append({
                "_time": row.created_at.isoformat() if row.created_at else "",
                "agent_hostname": payload.get("hostname") or payload.get("ComputerName") or "",
                "actor_effective_username": payload.get("user") or "",
                "action_process_image_name": payload.get("process_name") or "",
                "action_process_image_command_line": payload.get("CommandLine") or "",
                "alert_id": str(uuid.uuid5(uuid.NAMESPACE_DNS, str(row.id))),
                "severity": row.severity or "info",
                "technique": row.title or "",
                **{k: v for k, v in payload.items() if not k.startswith("_") and isinstance(v, str)},
            })

    _xql_jobs[job_id] = {"job_id": job_id, "status": "SUCCESS", "results": {"data": results, "total_count": len(results)}}
    return _xsiam_response({"execution_id": job_id, "status": "SUCCESS"})


@router.post("/public_api/v1/xql/get_query_results")
async def get_xql_results(body: dict = Body(default={})):
    rd = body.get("request_data", {})
    # Accept both "query_id" (Joti XSIAM adapter) and "execution_id" (XSIAM native)
    job_id = rd.get("query_id") or rd.get("execution_id", "")
    job = _xql_jobs.get(job_id, {"results": {"data": [], "total_count": 0}, "status": "SUCCESS"})
    return _xsiam_response({
        "status": job.get("status", "SUCCESS"),
        "number_of_rows": len(job.get("results", {}).get("data", [])),
        "results": job.get("results", {}),
    })


@router.post("/public_api/v1/xql/quota")
async def xql_quota():
    """Return simulated XQL quota info — used by Joti test_connection."""
    return _xsiam_response({"fixed_quota": 5000000, "additional_purchased_quota": 0, "license_quota": 5000000})


# ── Incidents / Alerts ────────────────────────────────────────────────────────

@router.post("/public_api/v1/incidents/get_incidents")
async def get_incidents(
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    if not session_id:
        return _xsiam_response({"incidents": [], "total_count": 0})

    machine = get_machine(session_id)
    snap = machine.snapshot()
    incidents = []
    for i, (hostname, state) in enumerate(snap.items()):
        if state in ("compromised", "at_risk"):
            incidents.append({
                "incident_id": str(i + 1001),
                "incident_name": f"Potential Compromise: {hostname}",
                "description": f"Endpoint {hostname} is in state: {state}",
                "severity": "HIGH" if state == "compromised" else "MEDIUM",
                "status": "new",
                "creation_time": int(datetime.now(timezone.utc).timestamp() * 1000),
                "modification_time": int(datetime.now(timezone.utc).timestamp() * 1000),
                "hosts": [{"hostname": hostname, "ip": f"10.0.0.{i + 10}"}],
                "users": [],
                "alert_count": 3,
                "rule_based_score": 72,
                "manually_created": False,
            })
    return _xsiam_response({"incidents": incidents, "total_count": len(incidents)})


@router.post("/public_api/v1/alerts/get_alerts_multi_events")
async def get_alerts(
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    if not session_id:
        return _xsiam_response({"alerts": []})

    from backend.db.models import GeneratedEvent
    from backend.db.session import async_session
    from sqlalchemy import select

    async with async_session() as db:
        rows = (await db.execute(
            select(GeneratedEvent)
            .where(GeneratedEvent.session_id == uuid.UUID(session_id))
            .where(GeneratedEvent.severity.in_(["high", "critical"]))
            .order_by(GeneratedEvent.created_at.desc())
            .limit(50)
        )).scalars().all()

    alerts = []
    for row in rows:
        payload = row.payload or {}
        alerts.append({
            "alert_id": str(uuid.uuid5(uuid.NAMESPACE_DNS, str(row.id))),
            "alert_name": payload.get("alert_name") or payload.get("event_title") or row.title or "Alert",
            "severity": (row.severity or "medium").upper(),
            "category": "Malware",
            "action_pretty": "DETECTED",
            "agent_hostname": payload.get("hostname") or payload.get("ComputerName") or "",
            "actor_effective_username": payload.get("user") or "",
            "mitre_technique_id_and_name": row.title or "",
            "alert_source": "PurpleLab",
            "detection_timestamp": int(row.created_at.timestamp() * 1000) if row.created_at else 0,
        })
    return _xsiam_response({"alerts": alerts})


# ── Endpoint Isolation ────────────────────────────────────────────────────────

@router.post("/public_api/v1/endpoints/isolate")
async def isolate_endpoints(
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    filters = body.get("request_data", {}).get("filters", [])
    results = []
    if session_id:
        machine = get_machine(session_id)
        snap = machine.snapshot()
        for f in filters:
            value = f.get("value", [])
            hostnames = value if isinstance(value, list) else [value]
            for hostname in hostnames:
                if hostname in snap:
                    result = await execute_action(session_id, "isolate_host", {"hostname": hostname, "actor": "joti_soar"})
                    results.append({"hostname": hostname, "action_id": str(uuid.uuid4()), **result.dict()})
    return _xsiam_response({"action_id": str(uuid.uuid4()), "endpoints_count": len(results), "details": results})


@router.post("/public_api/v1/endpoints/unisolate")
async def unisolate_endpoints(
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    filters = body.get("request_data", {}).get("filters", [])
    results = []
    if session_id:
        for f in filters:
            value = f.get("value", [])
            hostnames = value if isinstance(value, list) else [value]
            for hostname in hostnames:
                result = await execute_action(session_id, "release_host", {"hostname": hostname, "actor": "joti_soar"})
                results.append({"hostname": hostname, **result.dict()})
    return _xsiam_response({"action_id": str(uuid.uuid4()), "endpoints_count": len(results)})


# ── Indicators ────────────────────────────────────────────────────────────────

@router.post("/public_api/v1/indicators/insert_jsons")
async def insert_indicators(
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    rd = body.get("request_data", {})
    # Accept both "json_indicators" (XSIAM spec) and "json_objects" (legacy)
    indicators = rd.get("json_indicators") or rd.get("json_objects", [])
    results = []
    for ind in indicators:
        value = ind.get("indicator") or ind.get("value", "")
        if session_id and value:
            result = await execute_action(session_id, "block_ioc", {
                "ioc_type": ind.get("type", "ip").lower(),
                "ioc_value": value,
                "actor": "joti_soar",
            })
            results.append({"indicator": value, **result.dict()})
    return _xsiam_response({"success": True, "inserted": len(results)})


@router.post("/public_api/v1/indicators/delete")
async def delete_indicators(
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    """Remove IOCs from the simulated blocklist."""
    filters = body.get("request_data", {}).get("filters", [])
    deleted = 0
    for f in filters:
        if f.get("field") == "indicator" and session_id:
            deleted += 1
    return _xsiam_response({"success": True, "deleted": deleted})


# ── Endpoint Scan ─────────────────────────────────────────────────────────────

@router.post("/public_api/v1/endpoints/scan")
async def scan_endpoints(
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    """Trigger a simulated AV scan on target endpoints."""
    filters = body.get("request_data", {}).get("filters", [])
    action_id = str(uuid.uuid4())
    scanned = []
    if session_id:
        for f in filters:
            value = f.get("value", [])
            endpoints = value if isinstance(value, list) else [value]
            for ep in endpoints:
                scanned.append({"endpoint_id": ep, "scan_status": "SCANNING"})
    return _xsiam_response({"action_id": action_id, "endpoints_count": len(scanned), "details": scanned})


# ── Script Execution (kill_process) ──────────────────────────────────────────

@router.post("/public_api/v1/scripts/run_script")
async def run_script(
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    """Execute a remote script on target endpoints — simulates kill_process."""
    rd = body.get("request_data", {})
    filters = rd.get("filters", [])
    script_name = rd.get("script_name", "joti_script")
    action_id = str(uuid.uuid4())
    results = []
    if session_id:
        machine = get_machine(session_id)
        for f in filters:
            value = f.get("value", [])
            endpoints = value if isinstance(value, list) else [value]
            for ep in endpoints:
                results.append({"endpoint_id": ep, "output": f"Script '{script_name}' executed", "status": "SUCCESS"})
    return _xsiam_response({"action_id": action_id, "endpoints_count": len(results), "details": results})


# ── File Quarantine ───────────────────────────────────────────────────────────

@router.post("/public_api/v1/endpoints/quarantine_files")
async def quarantine_files(
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    """Quarantine a file on target endpoints."""
    files = body.get("request_data", {}).get("files", [])
    action_id = str(uuid.uuid4())
    results = []
    for f in files:
        ep_id = f.get("endpoint_id", "unknown")
        file_path = f.get("file_path", f.get("file_hash", "unknown"))
        results.append({"endpoint_id": ep_id, "file": file_path, "status": "QUARANTINED"})
    return _xsiam_response({"action_id": action_id, "files_count": len(results), "details": results})


# ── Incident Update ───────────────────────────────────────────────────────────

@router.post("/public_api/v1/incidents/update_incident")
async def update_incident(
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    """Update an incident status in the simulation."""
    rd = body.get("request_data", {})
    incident_id = rd.get("incident_id", "")
    new_status = rd.get("status", "resolved_threat_handled")
    return _xsiam_response({
        "incident_id": incident_id,
        "status": new_status,
        "modification_time": int(datetime.now(timezone.utc).timestamp() * 1000),
    })


# ── Endpoint Info ─────────────────────────────────────────────────────────────

@router.post("/public_api/v1/endpoints/get_endpoint")
async def get_endpoint(
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    """Return simulated endpoint details."""
    filters = body.get("request_data", {}).get("filters", [])
    endpoints = []
    if session_id:
        machine = get_machine(session_id)
        snap = machine.snapshot()
        for f in filters:
            value = f.get("value", [])
            ep_ids = value if isinstance(value, list) else [value]
            for ep_id in ep_ids:
                hostname = ep_id if ep_id in snap else next(iter(snap), ep_id)
                state = snap.get(hostname, "healthy")
                endpoints.append({
                    "endpoint_id": ep_id,
                    "endpoint_name": hostname,
                    "endpoint_type": "AGENT_TYPE_WORKSTATION",
                    "os_type": "WINDOWS",
                    "ip": [f"10.0.0.{hash(ep_id) % 200 + 10}"],
                    "users": ["lab_user"],
                    "domain": "purplelab.local",
                    "is_isolated": state == "isolated",
                    "last_seen": int(datetime.now(timezone.utc).timestamp() * 1000),
                    "agent_version": "8.1.0.123456",
                    "operational_status": "PROTECTED" if state == "healthy" else "PARTIALLY_PROTECTED",
                    "endpoint_status": state.upper(),
                })
    return _xsiam_response({"endpoints": endpoints, "result_count": len(endpoints)})
