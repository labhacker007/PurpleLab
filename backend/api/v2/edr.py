"""EDR Simulation API — v2.

Emulates CrowdStrike Falcon / Microsoft Defender / SentinelOne APIs.
Supports detections, host isolation, hash/process blocking, IOC hunting,
and live response command execution against simulated endpoints.

All mutation operations are logged to containment_actions for audit.
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, or_

from backend.db.session import async_session
from backend.db.models import (
    SimulatedEndpoint, SimulatedUser, ContainmentAction, BlockListEntry, GeneratedEvent,
)

router = APIRouter(prefix="/edr", tags=["edr"])


# ── Request / Response schemas ────────────────────────────────────────────────

class IsolateRequest(BaseModel):
    reason: str = Field("", description="Reason for isolation")
    requester: str = Field("api", description="Who triggered the action")


class BlockHashRequest(BaseModel):
    sha256: str = Field(..., description="SHA-256 hash of the file to block")
    md5: Optional[str] = None
    filename: Optional[str] = None
    reason: str = ""
    requester: str = "api"
    vendor: str = "crowdstrike"


class BlockProcessRequest(BaseModel):
    process_name: str = Field(..., description="Process name to block (e.g. mimikatz.exe)")
    reason: str = ""
    requester: str = "api"
    vendor: str = "crowdstrike"


class HuntIOCRequest(BaseModel):
    ioc_type: str = Field(..., description="ip | domain | hash | filename | process")
    ioc_value: str
    time_range_hours: int = Field(24, ge=1, le=720)


class RunCommandRequest(BaseModel):
    command: str = Field(..., description="Live response / RTR command to run")
    requester: str = "api"
    timeout_seconds: int = Field(30, ge=5, le=300)


# ── Seed helpers ──────────────────────────────────────────────────────────────

_SEED_ENDPOINTS = [
    ("dc01.corp.local", "10.0.0.1", "windows", "Windows Server 2022", "crowdstrike"),
    ("dc02.corp.local", "10.0.0.2", "windows", "Windows Server 2022", "crowdstrike"),
    ("ws-dev-001.corp.local", "10.1.10.15", "windows", "Windows 11 23H2", "crowdstrike"),
    ("ws-dev-002.corp.local", "10.1.10.16", "windows", "Windows 11 23H2", "crowdstrike"),
    ("ws-finance-001.corp.local", "10.1.20.5", "windows", "Windows 10 22H2", "defender"),
    ("ws-finance-002.corp.local", "10.1.20.6", "windows", "Windows 10 22H2", "defender"),
    ("ws-exec-ceo.corp.local", "10.1.30.1", "windows", "Windows 11 23H2", "crowdstrike"),
    ("srv-web-01.corp.local", "10.2.0.10", "linux", "Ubuntu 22.04 LTS", "sentinelone"),
    ("srv-web-02.corp.local", "10.2.0.11", "linux", "Ubuntu 22.04 LTS", "sentinelone"),
    ("srv-db-01.corp.local", "10.2.1.5", "linux", "RHEL 9.2", "sentinelone"),
    ("srv-jump-01.corp.local", "10.0.100.1", "linux", "Ubuntu 20.04 LTS", "crowdstrike"),
    ("laptop-sec-001.corp.local", "10.1.40.3", "macos", "macOS 14.3 Sonoma", "crowdstrike"),
]

_SEED_DETECTIONS = [
    {"title": "Credential Dumping via LSASS", "severity": "critical", "technique": "T1003.001"},
    {"title": "Suspicious PowerShell Encoded Command", "severity": "high", "technique": "T1059.001"},
    {"title": "Pass-the-Hash Lateral Movement", "severity": "high", "technique": "T1550.002"},
    {"title": "Scheduled Task Created for Persistence", "severity": "medium", "technique": "T1053.005"},
    {"title": "Mimikatz Keywords in CommandLine", "severity": "critical", "technique": "T1003"},
    {"title": "Network Port Scan Detected", "severity": "medium", "technique": "T1046"},
    {"title": "NTDS.dit Access Attempt", "severity": "critical", "technique": "T1003.003"},
    {"title": "Registry Run Key Modified", "severity": "medium", "technique": "T1547.001"},
    {"title": "CertUtil Download via CLI", "severity": "high", "technique": "T1105"},
    {"title": "WMI Remote Process Execution", "severity": "high", "technique": "T1047"},
]


async def _ensure_seed_endpoints(environment_id: Optional[uuid.UUID] = None):
    """Lazily seed simulated endpoints if none exist for the given environment."""
    async with async_session() as session:
        q = select(func.count()).select_from(SimulatedEndpoint)
        if environment_id:
            q = q.where(SimulatedEndpoint.environment_id == environment_id)
        count = (await session.execute(q)).scalar() or 0

        if count == 0:
            for hostname, ip, os_p, os_v, edr in _SEED_ENDPOINTS:
                ep = SimulatedEndpoint(
                    id=uuid.uuid4(),
                    environment_id=environment_id,
                    hostname=hostname,
                    ip_address=ip,
                    os_platform=os_p,
                    os_version=os_v,
                    edr_vendor=edr,
                    agent_version="7.14.0" if edr == "crowdstrike" else "22.3.1",
                    status="online",
                    last_seen=datetime.utcnow() - timedelta(minutes=random.randint(0, 30)),
                    tags={"team": "corp", "criticality": random.choice(["low", "medium", "high"])},
                )
                session.add(ep)
            await session.commit()


def _log_action(
    action_type: str, target_type: str, target_value: str,
    target_id: Optional[str], requester: str, reason: str,
    status: str = "success", detail: Optional[dict] = None,
    environment_id: Optional[uuid.UUID] = None,
) -> ContainmentAction:
    return ContainmentAction(
        id=uuid.uuid4(),
        environment_id=environment_id,
        action_type=action_type,
        target_type=target_type,
        target_value=target_value,
        target_id=target_id,
        requester=requester,
        reason=reason,
        status=status,
        result_detail=detail or {},
    )


# ── Detection endpoints ───────────────────────────────────────────────────────

@router.get("/detections")
async def list_detections(
    severity: Optional[str] = None,
    environment_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = 0,
):
    """List simulated EDR detections pulled from generated events + synthetic alerts."""
    await _ensure_seed_endpoints()

    async with async_session() as session:
        q = select(GeneratedEvent).order_by(GeneratedEvent.created_at.desc())
        if severity:
            q = q.where(GeneratedEvent.severity == severity)
        q = q.offset(offset).limit(limit)
        events = (await session.execute(q)).scalars().all()

    detections = []
    for ev in events:
        payload = ev.payload or {}
        detections.append({
            "detection_id": str(ev.id),
            "title": payload.get("title") or payload.get("AlertDisplayName") or "Suspicious Activity",
            "severity": ev.severity or "medium",
            "product_type": ev.product_type,
            "hostname": payload.get("ComputerName") or payload.get("hostname") or "unknown",
            "ip_address": payload.get("src_ip") or payload.get("local_ip") or "10.0.0.0",
            "technique": payload.get("technique_id") or "T1059",
            "status": "new",
            "timestamp": ev.created_at.isoformat() if ev.created_at else None,
            "raw_payload": payload,
        })

    # Supplement with synthetic detections if fewer than 10 real events
    if len(detections) < 10:
        for i, seed in enumerate(_SEED_DETECTIONS[:max(10 - len(detections), 5)]):
            if severity and seed["severity"] != severity:
                continue
            detections.insert(i, {
                "detection_id": f"syn-{seed['technique']}-{i}",
                "title": seed["title"],
                "severity": seed["severity"],
                "product_type": "crowdstrike",
                "hostname": random.choice([h for h, *_ in _SEED_ENDPOINTS[:4]]),
                "ip_address": random.choice([ip for _, ip, *_ in _SEED_ENDPOINTS[:4]]),
                "technique": seed["technique"],
                "status": random.choice(["new", "in_progress", "closed"]),
                "timestamp": (datetime.utcnow() - timedelta(minutes=random.randint(1, 120))).isoformat(),
                "raw_payload": {},
            })

    return {"detections": detections, "total": len(detections), "offset": offset, "limit": limit}


# ── Endpoint management ───────────────────────────────────────────────────────

@router.get("/devices")
async def list_devices(
    status: Optional[str] = None,
    edr_vendor: Optional[str] = None,
    os_platform: Optional[str] = None,
    environment_id: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = 0,
):
    """List all managed endpoints in the simulated EDR environment."""
    await _ensure_seed_endpoints()

    async with async_session() as session:
        q = select(SimulatedEndpoint).order_by(SimulatedEndpoint.hostname)
        if status:
            q = q.where(SimulatedEndpoint.status == status)
        if edr_vendor:
            q = q.where(SimulatedEndpoint.edr_vendor == edr_vendor)
        if os_platform:
            q = q.where(SimulatedEndpoint.os_platform == os_platform)
        if environment_id:
            try:
                q = q.where(SimulatedEndpoint.environment_id == uuid.UUID(environment_id))
            except ValueError:
                raise HTTPException(400, "Invalid environment_id UUID")
        total_q = select(func.count()).select_from(q.subquery())
        total = (await session.execute(total_q)).scalar() or 0
        q = q.offset(offset).limit(limit)
        endpoints = (await session.execute(q)).scalars().all()

    return {
        "devices": [_ep_to_dict(ep) for ep in endpoints],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.get("/devices/{device_id}")
async def get_device(device_id: str):
    """Get details for a specific simulated endpoint."""
    await _ensure_seed_endpoints()
    async with async_session() as session:
        ep = await _get_endpoint(session, device_id)
        return _ep_to_dict(ep)


def _ep_to_dict(ep: SimulatedEndpoint) -> dict[str, Any]:
    return {
        "id": str(ep.id),
        "hostname": ep.hostname,
        "ip_address": ep.ip_address,
        "os_platform": ep.os_platform,
        "os_version": ep.os_version,
        "edr_vendor": ep.edr_vendor,
        "agent_version": ep.agent_version,
        "status": ep.status,
        "last_seen": ep.last_seen.isoformat() if ep.last_seen else None,
        "tags": ep.tags or {},
        "environment_id": str(ep.environment_id) if ep.environment_id else None,
        "created_at": ep.created_at.isoformat() if ep.created_at else None,
    }


async def _get_endpoint(session, device_id: str) -> SimulatedEndpoint:
    """Resolve a device by UUID or hostname."""
    try:
        uid = uuid.UUID(device_id)
        q = select(SimulatedEndpoint).where(SimulatedEndpoint.id == uid)
    except ValueError:
        q = select(SimulatedEndpoint).where(SimulatedEndpoint.hostname.ilike(f"%{device_id}%"))
    ep = (await session.execute(q)).scalar_one_or_none()
    if not ep:
        raise HTTPException(404, f"Device '{device_id}' not found")
    return ep


# ── Containment — Host isolation ──────────────────────────────────────────────

@router.post("/devices/{device_id}/isolate")
async def isolate_host(device_id: str, req: IsolateRequest):
    """Isolate a simulated endpoint (network isolation / quarantine).

    Simulates CrowdStrike RTR host isolation. The device status transitions
    to 'isolated'. A ContainmentAction audit record is written.
    """
    async with async_session() as session:
        ep = await _get_endpoint(session, device_id)
        if ep.status == "isolated":
            raise HTTPException(409, f"Host '{ep.hostname}' is already isolated")

        prev_status = ep.status
        ep.status = "isolated"
        ep.updated_at = datetime.utcnow()

        action = _log_action(
            "isolate_host", "endpoint", ep.hostname,
            str(ep.id), req.requester, req.reason,
            detail={"previous_status": prev_status, "hostname": ep.hostname, "ip": ep.ip_address},
            environment_id=ep.environment_id,
        )
        session.add(action)
        await session.commit()

    return {
        "success": True,
        "action_id": str(action.id),
        "device_id": str(ep.id),
        "hostname": ep.hostname,
        "previous_status": prev_status,
        "current_status": "isolated",
        "message": f"Host {ep.hostname} isolated successfully",
        "timestamp": action.executed_at.isoformat(),
    }


@router.delete("/devices/{device_id}/isolate")
async def release_isolation(device_id: str, requester: str = "api", reason: str = ""):
    """Release a simulated endpoint from network isolation."""
    async with async_session() as session:
        ep = await _get_endpoint(session, device_id)
        if ep.status != "isolated":
            raise HTTPException(409, f"Host '{ep.hostname}' is not isolated (status: {ep.status})")

        ep.status = "online"
        ep.updated_at = datetime.utcnow()

        action = _log_action(
            "release_host", "endpoint", ep.hostname,
            str(ep.id), requester, reason or "Isolation released",
            detail={"hostname": ep.hostname},
            environment_id=ep.environment_id,
        )
        session.add(action)
        await session.commit()

    return {
        "success": True,
        "action_id": str(action.id),
        "hostname": ep.hostname,
        "current_status": "online",
        "message": f"Host {ep.hostname} released from isolation",
    }


# ── Block list — Hash / Process ───────────────────────────────────────────────

@router.post("/block/hash")
async def block_hash(req: BlockHashRequest):
    """Block a file by SHA-256 hash across the simulated EDR fleet."""
    async with async_session() as session:
        # Check if already blocked
        existing = (await session.execute(
            select(BlockListEntry).where(
                BlockListEntry.block_type == "hash",
                BlockListEntry.value == req.sha256.lower(),
                BlockListEntry.is_active == True,
            )
        )).scalar_one_or_none()
        if existing:
            raise HTTPException(409, f"Hash {req.sha256[:12]}... is already blocked (id: {existing.id})")

        entry = BlockListEntry(
            id=uuid.uuid4(),
            block_type="hash",
            value=req.sha256.lower(),
            hash_type="sha256",
            vendor=req.vendor,
            reason=req.reason,
            comment=req.filename or "",
            added_by=req.requester,
            is_active=True,
        )
        action = _log_action(
            "block_hash", "hash", req.sha256, None, req.requester, req.reason,
            detail={"sha256": req.sha256, "md5": req.md5, "filename": req.filename, "vendor": req.vendor},
        )
        session.add(entry)
        session.add(action)
        await session.commit()

    return {
        "success": True,
        "block_id": str(entry.id),
        "action_id": str(action.id),
        "sha256": req.sha256,
        "vendor": req.vendor,
        "message": f"Hash {req.sha256[:12]}... blocked on {req.vendor}",
        "timestamp": entry.created_at.isoformat(),
    }


@router.delete("/block/hash/{sha256}")
async def unblock_hash(sha256: str, requester: str = "api"):
    """Remove a file hash from the block list."""
    async with async_session() as session:
        entry = (await session.execute(
            select(BlockListEntry).where(
                BlockListEntry.block_type == "hash",
                BlockListEntry.value == sha256.lower(),
                BlockListEntry.is_active == True,
            )
        )).scalar_one_or_none()
        if not entry:
            raise HTTPException(404, f"Hash {sha256[:12]}... not in active block list")

        entry.is_active = False
        action = _log_action(
            "unblock_hash", "hash", sha256, str(entry.id), requester, "",
            detail={"sha256": sha256},
        )
        session.add(action)
        await session.commit()

    return {"success": True, "action_id": str(action.id), "message": f"Hash {sha256[:12]}... unblocked"}


@router.post("/block/process")
async def block_process(req: BlockProcessRequest):
    """Block a process name across the simulated EDR fleet."""
    async with async_session() as session:
        existing = (await session.execute(
            select(BlockListEntry).where(
                BlockListEntry.block_type == "process",
                BlockListEntry.value == req.process_name.lower(),
                BlockListEntry.is_active == True,
            )
        )).scalar_one_or_none()
        if existing:
            raise HTTPException(409, f"Process '{req.process_name}' is already blocked")

        entry = BlockListEntry(
            id=uuid.uuid4(),
            block_type="process",
            value=req.process_name.lower(),
            vendor=req.vendor,
            reason=req.reason,
            added_by=req.requester,
        )
        action = _log_action(
            "block_process", "process", req.process_name, None, req.requester, req.reason,
            detail={"process_name": req.process_name, "vendor": req.vendor},
        )
        session.add(entry)
        session.add(action)
        await session.commit()

    return {
        "success": True,
        "block_id": str(entry.id),
        "action_id": str(action.id),
        "process_name": req.process_name,
        "message": f"Process '{req.process_name}' blocked",
    }


@router.get("/block/list")
async def list_edr_blocks(
    block_type: Optional[str] = None,
    active_only: bool = True,
    limit: int = Query(100, ge=1, le=500),
):
    """List all active EDR block list entries (hashes, processes)."""
    async with async_session() as session:
        q = select(BlockListEntry).where(
            BlockListEntry.block_type.in_(["hash", "process"])
        ).order_by(BlockListEntry.created_at.desc())
        if active_only:
            q = q.where(BlockListEntry.is_active == True)
        if block_type:
            q = q.where(BlockListEntry.block_type == block_type)
        q = q.limit(limit)
        entries = (await session.execute(q)).scalars().all()

    return {
        "blocks": [_entry_to_dict(e) for e in entries],
        "total": len(entries),
    }


# ── IOC Hunt ──────────────────────────────────────────────────────────────────

@router.post("/hunt")
async def hunt_ioc(req: HuntIOCRequest):
    """Hunt for an IOC across the simulated endpoint fleet.

    Searches generated event payloads for matches, returns hit summary.
    """
    await _ensure_seed_endpoints()
    cutoff = datetime.utcnow() - timedelta(hours=req.time_range_hours)

    async with async_session() as session:
        # Search generated events for the IOC value
        events_q = select(GeneratedEvent).where(
            GeneratedEvent.created_at >= cutoff,
        ).order_by(GeneratedEvent.created_at.desc()).limit(200)
        events = (await session.execute(events_q)).scalars().all()

        # Also fetch all endpoints for context
        endpoints = (await session.execute(select(SimulatedEndpoint))).scalars().all()

    hits = []
    for ev in events:
        payload_str = str(ev.payload or {}).lower()
        if req.ioc_value.lower() in payload_str:
            hits.append({
                "event_id": str(ev.id),
                "hostname": (ev.payload or {}).get("hostname", "unknown"),
                "product_type": ev.product_type,
                "severity": ev.severity,
                "timestamp": ev.created_at.isoformat() if ev.created_at else None,
                "context": f"IOC found in {ev.product_type} event",
            })

    # Synthetic hits for demonstration
    if not hits and endpoints:
        sample_eps = random.sample(endpoints, min(3, len(endpoints)))
        for ep in sample_eps:
            if random.random() > 0.4:
                hits.append({
                    "event_id": f"syn-hunt-{uuid.uuid4().hex[:8]}",
                    "hostname": ep.hostname,
                    "product_type": ep.edr_vendor,
                    "severity": random.choice(["medium", "high"]),
                    "timestamp": (datetime.utcnow() - timedelta(hours=random.randint(1, req.time_range_hours))).isoformat(),
                    "context": f"Simulated {req.ioc_type} match: {req.ioc_value}",
                })

    return {
        "ioc_type": req.ioc_type,
        "ioc_value": req.ioc_value,
        "time_range_hours": req.time_range_hours,
        "total_hits": len(hits),
        "hits": hits,
        "scanned_endpoints": len(endpoints),
        "hunt_id": f"hunt-{uuid.uuid4().hex[:10]}",
    }


# ── Live response / RTR command ───────────────────────────────────────────────

@router.post("/devices/{device_id}/command")
async def run_command(device_id: str, req: RunCommandRequest):
    """Execute a live response / RTR command on a simulated endpoint.

    Returns simulated stdout/stderr. Commands are logged to containment_actions.
    """
    async with async_session() as session:
        ep = await _get_endpoint(session, device_id)

        if ep.status == "isolated":
            raise HTTPException(409, f"Cannot run command: host {ep.hostname} is isolated")

        stdout, stderr, exit_code = _simulate_command(req.command)

        action = _log_action(
            "run_command", "endpoint", ep.hostname, str(ep.id),
            req.requester, f"Live response: {req.command}",
            detail={"command": req.command, "stdout": stdout, "exit_code": exit_code},
            environment_id=ep.environment_id,
        )
        session.add(action)
        await session.commit()

    return {
        "success": exit_code == 0,
        "action_id": str(action.id),
        "hostname": ep.hostname,
        "command": req.command,
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
        "execution_time_ms": random.randint(80, 1200),
    }


def _simulate_command(cmd: str) -> tuple[str, str, int]:
    """Return plausible (stdout, stderr, exit_code) for common RTR commands."""
    c = cmd.strip().lower()
    if c.startswith("ls") or c.startswith("dir"):
        return (
            "drwxr-xr-x  2 root root 4096 Jun  2 10:41 /tmp\n"
            "-rw-r--r--  1 root root  220 Jun  2 10:41 .bash_logout\n"
            "-rw-r--r--  1 root root 3526 Jun  2 10:41 .bashrc",
            "", 0,
        )
    if c.startswith("ps") or c.startswith("tasklist"):
        return (
            "PID  PPID  NAME\n"
            "1    0     systemd\n"
            "423  1     sshd\n"
            "1204 423   bash\n"
            "2089 1204  python3",
            "", 0,
        )
    if "whoami" in c:
        return "CORP\\SYSTEM", "", 0
    if "netstat" in c or "ss " in c:
        return (
            "Proto  Local           Foreign         State\n"
            "tcp    0.0.0.0:22      0.0.0.0:*       LISTEN\n"
            "tcp    10.0.0.5:443    54.x.x.x:51234  ESTABLISHED",
            "", 0,
        )
    if "reg query" in c or "regedit" in c:
        return "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n(Default) REG_SZ (value not set)", "", 0
    return f"Executed: {cmd}", "", 0


# ── Action log ────────────────────────────────────────────────────────────────

@router.get("/actions")
async def list_actions(
    action_type: Optional[str] = None,
    target_type: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = 0,
):
    """List all containment actions in the audit log."""
    async with async_session() as session:
        q = select(ContainmentAction).order_by(ContainmentAction.executed_at.desc())
        if action_type:
            q = q.where(ContainmentAction.action_type == action_type)
        if target_type:
            q = q.where(ContainmentAction.target_type == target_type)
        total = (await session.execute(
            select(func.count()).select_from(q.subquery())
        )).scalar() or 0
        actions = (await session.execute(q.offset(offset).limit(limit))).scalars().all()

    return {
        "actions": [_action_to_dict(a) for a in actions],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


def _action_to_dict(a: ContainmentAction) -> dict[str, Any]:
    return {
        "id": str(a.id),
        "action_type": a.action_type,
        "target_type": a.target_type,
        "target_value": a.target_value,
        "target_id": a.target_id,
        "requester": a.requester,
        "reason": a.reason,
        "status": a.status,
        "result_detail": a.result_detail or {},
        "reversed_at": a.reversed_at.isoformat() if a.reversed_at else None,
        "executed_at": a.executed_at.isoformat() if a.executed_at else None,
    }


def _entry_to_dict(e: BlockListEntry) -> dict[str, Any]:
    return {
        "id": str(e.id),
        "block_type": e.block_type,
        "value": e.value,
        "hash_type": e.hash_type,
        "direction": e.direction,
        "vendor": e.vendor,
        "reason": e.reason,
        "comment": e.comment,
        "added_by": e.added_by,
        "is_active": e.is_active,
        "expires_at": e.expires_at.isoformat() if e.expires_at else None,
        "created_at": e.created_at.isoformat() if e.created_at else None,
    }


# ── Threat graph ──────────────────────────────────────────────────────────────

@router.get("/sessions/{session_id}/threat-graph")
async def get_threat_graph(session_id: str):
    """Return the process/lateral-movement graph for a simulation session.

    The graph is built incrementally as events are generated. Nodes represent
    processes, endpoints, external IPs, and users. Edges show parent-child
    process creation, network connections, and lateral movement paths.
    """
    from backend.engine.threat_graph import get_graph
    graph = get_graph(session_id)
    return graph.to_dict()


@router.get("/sessions/{session_id}/threat-graph/stats")
async def get_threat_graph_stats(session_id: str):
    """Return summary statistics for the threat graph of a session."""
    from backend.engine.threat_graph import get_graph
    graph = get_graph(session_id)
    return {"session_id": session_id, **graph.stats()}


# ── Endpoint state machine ────────────────────────────────────────────────────

@router.get("/sessions/{session_id}/endpoint-states")
async def get_endpoint_states(session_id: str):
    """Return the current EDR state for every endpoint in a session.

    States: online | at_risk | compromised | isolated | remediated | offline
    State transitions are driven automatically as attack events are processed.
    """
    from backend.engine.edr_state_machine import get_machine
    machine = get_machine(session_id)
    return {
        "session_id": session_id,
        "endpoint_states": machine.snapshot(),
    }


class ManualTransitionRequest(BaseModel):
    hostname: str = Field(..., description="Endpoint hostname to transition")
    new_state: str = Field(..., description="Target state: online|at_risk|compromised|isolated|remediated|offline")
    reason: str = Field("", description="Reason for manual override")


@router.post("/sessions/{session_id}/endpoint-states/transition")
async def manual_state_transition(session_id: str, req: ManualTransitionRequest):
    """Manually force an endpoint state transition (e.g. isolate from SOC console)."""
    from backend.engine.edr_state_machine import get_machine, EndpointState
    try:
        new_state = EndpointState(req.new_state)
    except ValueError:
        valid = [s.value for s in EndpointState]
        raise HTTPException(400, detail=f"Invalid state '{req.new_state}'. Valid: {valid}")

    machine = get_machine(session_id)
    old_state = machine.get_state(req.hostname)
    machine.set_state(req.hostname, new_state)

    return {
        "session_id": session_id,
        "hostname": req.hostname,
        "previous_state": old_state.value,
        "new_state": new_state.value,
        "reason": req.reason,
    }


# ── Prevention policies ───────────────────────────────────────────────────────

# In-memory prevention policy store (per-environment)
_prevention_policies: dict[str, dict[str, str]] = {}

# Default policy: detect everything, block known-bad
_DEFAULT_POLICY: dict[str, str] = {
    "execution":            "detect",     # T1059.*
    "persistence":          "detect",     # T1053.*, T1547.*
    "privilege_escalation": "detect",     # T1055.*, T1134.*
    "defense_evasion":      "detect",     # T1036.*, T1070.*
    "credential_access":    "block",      # T1003.*  — always block credential dumping
    "lateral_movement":     "detect",     # T1021.*
    "collection":           "detect",     # T1005.*
    "command_and_control":  "block",      # T1071.*  — block C2 beaconing
    "exfiltration":         "block",      # T1041.*
    "impact":               "block",      # T1486.*  — block ransomware
    "initial_access":       "detect",
    "discovery":            "alert_only",
    "reconnaissance":       "alert_only",
}

# Map technique IDs to policy categories
_TECHNIQUE_CATEGORY_MAP: dict[str, str] = {
    "T1059": "execution", "T1059.001": "execution", "T1059.003": "execution",
    "T1053": "persistence", "T1053.005": "persistence",
    "T1547": "persistence", "T1547.001": "persistence",
    "T1055": "privilege_escalation", "T1055.001": "privilege_escalation",
    "T1003": "credential_access", "T1003.001": "credential_access", "T1003.003": "credential_access",
    "T1021": "lateral_movement", "T1021.001": "lateral_movement", "T1021.002": "lateral_movement",
    "T1071": "command_and_control", "T1071.001": "command_and_control", "T1071.004": "command_and_control",
    "T1041": "exfiltration",
    "T1486": "impact",
    "T1046": "discovery",
    "T1566": "initial_access", "T1566.001": "initial_access",
    "T1078": "initial_access",
}


@router.get("/prevention-policies")
async def get_prevention_policies(environment_id: Optional[str] = None):
    """Return the current prevention policy for each technique category.

    Policy values: block | detect | alert_only | disabled
    """
    key = environment_id or "default"
    policy = _prevention_policies.get(key, dict(_DEFAULT_POLICY))
    return {
        "environment_id": key,
        "policies": policy,
        "categories": list(policy.keys()),
    }


class PolicyUpdateRequest(BaseModel):
    category: str = Field(..., description="Technique category name")
    mode: str = Field(..., description="block | detect | alert_only | disabled")
    environment_id: Optional[str] = None


@router.put("/prevention-policies")
async def update_prevention_policy(req: PolicyUpdateRequest):
    """Update the prevention mode for a technique category."""
    valid_modes = {"block", "detect", "alert_only", "disabled"}
    if req.mode not in valid_modes:
        raise HTTPException(400, detail=f"mode must be one of {valid_modes}")

    key = req.environment_id or "default"
    if key not in _prevention_policies:
        _prevention_policies[key] = dict(_DEFAULT_POLICY)
    _prevention_policies[key][req.category] = req.mode

    return {
        "environment_id": key,
        "category": req.category,
        "mode": req.mode,
        "policies": _prevention_policies[key],
    }


@router.get("/prevention-policies/check/{technique_id}")
async def check_technique_policy(technique_id: str, environment_id: Optional[str] = None):
    """Check what prevention action applies for a specific MITRE technique."""
    key = environment_id or "default"
    policy = _prevention_policies.get(key, dict(_DEFAULT_POLICY))

    # Exact match first, then parent technique, then category
    category = (
        _TECHNIQUE_CATEGORY_MAP.get(technique_id)
        or _TECHNIQUE_CATEGORY_MAP.get(technique_id.split(".")[0])
        or "execution"
    )
    mode = policy.get(category, "detect")

    return {
        "technique_id": technique_id,
        "category": category,
        "mode": mode,
        "would_block": mode == "block",
        "would_alert": mode in ("block", "detect", "alert_only"),
    }
