"""Splunk Enterprise Security REST API emulation.

Mimics the Splunk REST API so Joti's Splunk connector can execute
SPL searches, deploy saved searches, and create notable events
against the simulation.

Key endpoints:
  POST /services/search/jobs              create SPL search job
  GET  /services/search/jobs/{sid}        job status
  GET  /services/search/jobs/{sid}/results get search results
  POST /services/saved/searches           deploy saved search (detection)
  GET  /services/saved/searches           list deployed searches
  POST /services/alerts/fired_alerts      create notable event
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from fastapi import APIRouter, Body, Query
from pydantic import BaseModel

from backend.engine.action_executor import execute_action

router = APIRouter(prefix="/api/vendor/splunk", tags=["vendor:splunk"])

# In-memory job registry (keyed by sid)
_jobs: dict[str, dict[str, Any]] = {}
# Deployed saved searches per session
_saved_searches: dict[str, dict[str, Any]] = {}


# ── Search Jobs ───────────────────────────────────────────────────────────────

@router.post("/services/search/jobs")
async def create_search_job(
    session_id: Optional[str] = Query(None),
    search: str = Body(default="search *"),
    earliest_time: str = Body(default="-60m"),
    latest_time: str = Body(default="now"),
    output_mode: str = Query("json"),
):
    """Create a SPL search job against simulated events."""
    sid = f"sim_{hashlib.md5(f'{session_id}:{search}:{time.time()}'.encode()).hexdigest()[:16]}"
    _jobs[sid] = {
        "sid": sid,
        "session_id": session_id,
        "search": search,
        "status": "DONE",
        "dispatchState": "DONE",
        "resultCount": 0,
        "doneProgress": 1.0,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "earliest_time": earliest_time,
        "latest_time": latest_time,
    }
    # Pre-run the search against stored events
    if session_id:
        results = await _run_spl_search(session_id, search, earliest_time)
        _jobs[sid]["resultCount"] = len(results)
        _jobs[sid]["_results"] = results
    return {"sid": sid}


@router.get("/services/search/jobs/{sid}")
async def get_job_status(sid: str, output_mode: str = Query("json")):
    job = _jobs.get(sid, {"sid": sid, "status": "DONE", "dispatchState": "DONE", "resultCount": 0, "doneProgress": 1.0})
    return {"entry": [{"name": sid, "content": job}]}


@router.get("/services/search/jobs/{sid}/results")
async def get_job_results(
    sid: str,
    count: int = Query(50),
    offset: int = Query(0),
    output_mode: str = Query("json"),
):
    """Return results for a previously created search job."""
    job = _jobs.get(sid)
    if not job:
        return {"results": [], "messages": [{"type": "WARN", "text": "Unknown job"}]}
    results = (job.get("_results") or [])[offset : offset + count]
    return {
        "results": results,
        "preview": False,
        "highlighted": {},
        "init_offset": offset,
        "messages": [],
    }


async def _run_spl_search(session_id: str, spl_query: str, earliest_time: str = "-60m") -> list[dict]:
    """Execute a simplified SPL query against stored simulated events."""
    from backend.db.models import GeneratedEvent
    from backend.db.session import async_session
    from sqlalchemy import select

    # Parse time range
    minutes = 60
    if earliest_time.endswith("m"):
        try:
            minutes = abs(int(earliest_time[1:-1]))
        except ValueError:
            pass
    elif earliest_time.endswith("h"):
        try:
            minutes = abs(int(earliest_time[1:-1])) * 60
        except ValueError:
            pass

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)

    async with async_session() as db:
        q = (select(GeneratedEvent)
             .where(GeneratedEvent.session_id == uuid.UUID(session_id))
             .where(GeneratedEvent.created_at >= cutoff.replace(tzinfo=None))
             .order_by(GeneratedEvent.created_at.desc())
             .limit(500))
        rows = (await db.execute(q)).scalars().all()

    # Apply simple keyword filter from SPL (extract keywords between quotes)
    import re
    keywords = re.findall(r'"([^"]+)"', spl_query)
    sourcetype_match = re.search(r'sourcetype\s*=\s*"?([^\s"]+)"?', spl_query, re.IGNORECASE)
    host_match = re.search(r'\bhost\s*=\s*"?([^\s"]+)"?', spl_query, re.IGNORECASE)

    results = []
    for row in rows:
        payload = row.payload or {}

        # Sourcetype filter
        if sourcetype_match:
            st = sourcetype_match.group(1).lower()
            if st not in (row.product_type or "").lower() and st != "*":
                continue

        # Host filter
        if host_match:
            h = host_match.group(1).lower()
            if h not in (payload.get("hostname") or payload.get("ComputerName") or "").lower() and h != "*":
                continue

        # Keyword filter
        if keywords:
            raw = json.dumps(payload).lower()
            if not all(k.lower() in raw for k in keywords):
                continue

        ts = row.created_at.isoformat() if row.created_at else ""
        results.append({
            "_time": ts,
            "_raw": json.dumps(payload),
            "host": payload.get("hostname") or payload.get("ComputerName") or "sim-host",
            "source": row.product_type or "simulation",
            "sourcetype": row.product_type or "purplelab:sim",
            "index": "main",
            "technique": row.title or "",
            "severity": row.severity or "info",
            **{k: v for k, v in payload.items() if not k.startswith("_")},
        })

    return results


# ── Saved Searches (Detection Deployment) ────────────────────────────────────

class SavedSearchCreate(BaseModel):
    name: str
    search: str
    description: str = ""
    alert_type: str = "number of events"
    alert_comparator: str = "greater than"
    alert_threshold: str = "0"
    cron_schedule: str = "*/15 * * * *"
    session_id: Optional[str] = None


@router.post("/services/saved/searches")
async def create_saved_search(req: SavedSearchCreate):
    """Deploy a detection search to the simulated SIEM."""
    search_id = str(uuid.uuid4())
    entry = {
        "id": search_id,
        "name": req.name,
        "search": req.search,
        "description": req.description,
        "cron_schedule": req.cron_schedule,
        "alert_type": req.alert_type,
        "enabled": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "session_id": req.session_id,
    }
    key = req.session_id or "global"
    _saved_searches[f"{key}:{search_id}"] = entry

    # Store in deployed_detections table
    if req.session_id:
        await execute_action(req.session_id, "deploy_detection", {
            "name": req.name,
            "query_spl": req.search,
            "actor": "joti_soar",
        })

    return {"entry": [{"name": req.name, "id": search_id, "content": entry}]}


@router.get("/services/saved/searches")
async def list_saved_searches(
    session_id: Optional[str] = Query(None),
    count: int = Query(50),
    output_mode: str = Query("json"),
):
    key_prefix = session_id or "global"
    entries = [
        v for k, v in _saved_searches.items()
        if k.startswith(key_prefix)
    ][:count]
    return {"entry": [{"name": e["name"], "id": e["id"], "content": e} for e in entries]}


# ── Notable Events (Alert Creation) ──────────────────────────────────────────

@router.post("/services/alerts/fired_alerts")
async def create_notable(
    session_id: Optional[str] = Query(None),
    body: dict = Body(default={}),
):
    """Create a notable event (Splunk ES notable) in the simulation."""
    notable_id = str(uuid.uuid4())
    if session_id:
        await execute_action(session_id, "inject_alert", {
            "title": body.get("search_name", "Splunk Notable"),
            "severity": body.get("urgency", "medium"),
            "actor": "splunk_es",
        })
    return {"success": True, "notable_id": notable_id}


# ── System Info ───────────────────────────────────────────────────────────────

@router.get("/services/server/info")
async def server_info(output_mode: str = Query("json")):
    return {
        "entry": [{
            "name": "server-info",
            "content": {
                "version": "9.1.0 (PurpleLab Emulation)",
                "serverName": "purplelab-splunk-sim",
                "os_name": "Linux",
                "build": "purplelab",
                "isFree": False,
                "isTrial": False,
                "activeLicenseGroup": "Enterprise",
            },
        }]
    }
