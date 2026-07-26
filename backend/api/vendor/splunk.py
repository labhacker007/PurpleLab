"""Splunk Enterprise Security REST API emulation — enterprise rewrite.

Grounded in official Splunk documentation:
  https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch
  https://docs.splunk.com/Documentation/ES/latest/REST/Overview

Base URL: https://<splunk-host>:<port>  (default: 8089)
Auth: Basic auth (admin:changeme) or token via Authorization: Splunk <token>

Implements:
  Auth — /services/auth/login, token management
  Search Jobs (V1) — create, poll, results, preview, control (cancel/pause/finalize)
  Search Jobs (V2) — /services/search/v2/jobs (async)
  Saved Searches (detections) — CRUD, dispatch, history
  Alerts/Notable Events — ES-specific notable event management
  KV Store — key-value store collections for ES lookups
  Risk-Based Alerting (RBA) — risk score management
  Lookups — threat intelligence lookup tables
  Macros — saved search macros
  Event Types — custom event classification

SPL field operators: =, !=, <, >, <=, >=
SPL functions: stats, eval, table, head, tail, sort, dedup, search, where,
               lookup, inputlookup, outputlookup, timechart, chart, rex, rename,
               fields, join, append, appendcols, transaction, bucket
Output modes: json, xml, csv, raw (query param output_mode)
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from fastapi import APIRouter, Body, Form, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse

router = APIRouter(prefix="/api/vendor/splunk", tags=["vendor:splunk"])


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _epoch() -> float:
    return datetime.now(timezone.utc).timestamp()


def _uuid() -> str:
    return str(uuid.uuid4())


def _sid() -> str:
    return f"1722000000.{uuid.uuid4().hex[:8]}"


# ─────────────────────────────────────────────────────────────────────────────
# Seed data — events, saved searches, KV store, notables
# ─────────────────────────────────────────────────────────────────────────────

_SIM_TOKEN = f"splunk-sim-{uuid.uuid4().hex[:24]}"

_SEARCH_JOBS: dict[str, dict] = {}

_SAVED_SEARCHES: dict[str, dict] = {
    "PowerShell Encoded Command - Detection": {
        "name": "PowerShell Encoded Command - Detection",
        "title": "PowerShell Encoded Command - Detection",
        "search": "index=wineventlog EventCode=4688 CommandLine=\"*-enc*\" OR CommandLine=\"*-EncodedCommand*\" | table _time, host, user, CommandLine",
        "dispatch.earliest_time": "-24h",
        "dispatch.latest_time": "now",
        "alert.type": "number of events",
        "alert.condition": "search count > 0",
        "alert.severity": "3",
        "alert.actions": "notable",
        "action.notable.param.security_domain": "endpoint",
        "action.notable.param.severity": "high",
        "action.notable.param.rule_name": "PowerShell Encoded Command",
        "action.notable.param.rule_description": "Detected base64-encoded PowerShell command, potential malicious macro activity",
        "action.notable.param.mitre_attack_id": "T1059.001",
        "cron_schedule": "*/15 * * * *",
        "is_scheduled": "1",
        "disabled": "0",
        "realtime_schedule": "0",
        "updated": _now(),
    },
    "LSASS Memory Access - Detection": {
        "name": "LSASS Memory Access - Detection",
        "title": "LSASS Memory Access - Detection",
        "search": "index=wineventlog EventCode=4656 Object_Name=\"*lsass*\" AccessMask=0x1010 | table _time, host, SubjectUserName, ProcessName, Object_Name",
        "dispatch.earliest_time": "-1h",
        "dispatch.latest_time": "now",
        "alert.severity": "4",
        "alert.actions": "notable",
        "action.notable.param.security_domain": "endpoint",
        "action.notable.param.severity": "critical",
        "action.notable.param.rule_name": "LSASS Memory Access",
        "action.notable.param.mitre_attack_id": "T1003.001",
        "cron_schedule": "*/5 * * * *",
        "is_scheduled": "1",
        "disabled": "0",
        "updated": _now(),
    },
}

_NOTABLE_EVENTS: dict[str, dict] = {
    "notable-001": {
        "event_id": "notable-001",
        "_time": (datetime.now(timezone.utc) - timedelta(minutes=30)).timestamp(),
        "rule_name": "PowerShell Encoded Command",
        "rule_id": "powershell_encoded_command_detection",
        "security_domain": "endpoint",
        "severity": "high",
        "urgency": "high",
        "priority": "medium",
        "status": "1",
        "status_label": "New",
        "owner": "unassigned",
        "dest": "CORP-WS-001",
        "src": "10.10.1.101",
        "user": "jsmith",
        "src_user": "CORP\\jsmith",
        "dest_nt_host": "CORP-WS-001",
        "orig_host": "CORP-WS-001",
        "orig_index": "wineventlog",
        "orig_source": "WinEventLog:Security",
        "orig_time": (datetime.now(timezone.utc) - timedelta(minutes=30)).timestamp(),
        "orig_raw": "",
        "tag": "attack endpoint malware",
        "mitre_attack_id": "T1059.001",
        "mitre_technique_id": "T1059.001",
        "mitre_tactic": "Execution",
        "comment": "",
        "annotations": "{}",
        "num_hosts": "1",
        "num_events": "1",
        "next_steps": "Investigate PowerShell execution context",
        "drilldown_search": "index=wineventlog host=CORP-WS-001 CommandLine=*-enc*",
        "drilldown_earliest": "-30m",
        "drilldown_latest": "now",
        "process": "powershell.exe",
        "process_name": "powershell.exe",
        "commandline": "powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0",
        "parent_process": "WINWORD.EXE",
        "signature": "Suspicious PowerShell Encoded Command",
        "category": "Malware",
        "nist": "PR.PT",
        "kill_chain_phase": "Execution",
        "cve": "",
        "cvss": "",
        "impact": "high",
        "confidence": "high",
        "risk_score": "75",
        "closed_time": "",
        "disposition": "",
        "disposition_label": "",
    },
}

_KV_COLLECTIONS: dict[str, dict] = {
    "threat_intelligence": {
        "_meta": {"collection": "threat_intelligence", "fields": ["indicator", "type", "threat_group", "confidence"]},
        "records": [
            {"_key": "ti-001", "indicator": "203.0.113.200", "type": "ip", "threat_group": "APT28", "confidence": "90"},
            {"_key": "ti-002", "indicator": "malicious-domain.evil.example", "type": "domain", "threat_group": "CARBON SPIDER", "confidence": "85"},
        ],
    },
    "asset_lookup": {
        "_meta": {"collection": "asset_lookup", "fields": ["ip", "hostname", "owner", "priority", "category"]},
        "records": [
            {"_key": "asset-001", "ip": "10.10.1.101", "hostname": "CORP-WS-001", "owner": "jsmith", "priority": "medium", "category": "endpoint"},
            {"_key": "asset-002", "ip": "10.10.2.10", "hostname": "CORP-SRV-001", "owner": "agarcia", "priority": "high", "category": "server"},
            {"_key": "asset-003", "ip": "10.10.2.1", "hostname": "CORP-DC-001", "owner": "itsec@corp.local", "priority": "critical", "category": "domain_controller"},
        ],
    },
}

_RISK_SCORES: dict[str, dict] = {}


# ─────────────────────────────────────────────────────────────────────────────
# SPL query interpreter — generates realistic results per query pattern
# ─────────────────────────────────────────────────────────────────────────────

def _execute_spl(spl: str, earliest: str = "-24h", latest: str = "now") -> list[dict]:
    """Generate synthetic results based on SPL query patterns."""
    spl_lower = spl.lower()

    # Notable events queries
    if "notableevent" in spl_lower or "notable" in spl_lower and "index=notable" in spl_lower:
        return list(_NOTABLE_EVENTS.values())

    # Windows process events
    if "eventcode=4688" in spl_lower or "eventcode=1" in spl_lower or "process" in spl_lower:
        return [
            {"_time": str((datetime.now(timezone.utc) - timedelta(minutes=30)).timestamp()), "host": "CORP-WS-001", "user": "CORP\\jsmith", "CommandLine": "powershell.exe -enc SQBuAHYAbwBr...", "EventCode": "4688", "Process_Name": "powershell.exe", "Parent_Process_Name": "WINWORD.EXE", "ProcessId": "4200", "ParentProcessId": "3100", "index": "wineventlog", "sourcetype": "WinEventLog:Security"},
            {"_time": str((datetime.now(timezone.utc) - timedelta(minutes=29)).timestamp()), "host": "CORP-WS-001", "user": "CORP\\jsmith", "CommandLine": "net.exe user /domain", "EventCode": "4688", "Process_Name": "net.exe", "Parent_Process_Name": "powershell.exe", "ProcessId": "4300", "ParentProcessId": "4200", "index": "wineventlog", "sourcetype": "WinEventLog:Security"},
        ]

    # Network connections
    if "networkconnect" in spl_lower or "dest_port" in spl_lower or "network" in spl_lower:
        return [
            {"_time": str((datetime.now(timezone.utc) - timedelta(minutes=25)).timestamp()), "host": "CORP-WS-001", "src_ip": "10.10.1.101", "dest_ip": "203.0.113.200", "dest_port": "443", "protocol": "tcp", "bytes_sent": "15234", "bytes_received": "4321", "app": "powershell.exe", "user": "jsmith"},
            {"_time": str((datetime.now(timezone.utc) - timedelta(minutes=24)).timestamp()), "host": "CORP-WS-001", "src_ip": "10.10.1.101", "dest_ip": "10.10.2.1", "dest_port": "445", "protocol": "tcp", "bytes_sent": "2048", "bytes_received": "8192", "app": "powershell.exe", "user": "jsmith"},
        ]

    # Authentication events
    if "eventcode=4624" in spl_lower or "eventcode=4625" in spl_lower or "authentication" in spl_lower or "logon" in spl_lower:
        return [
            {"_time": str((datetime.now(timezone.utc) - timedelta(minutes=40)).timestamp()), "host": "CORP-DC-001", "EventCode": "4624", "Account_Name": "jsmith", "Account_Domain": "CORP", "Logon_Type": "3", "Logon_Process": "NtLmSsp", "Source_Network_Address": "10.10.1.101", "Workstation_Name": "CORP-WS-001"},
            {"_time": str((datetime.now(timezone.utc) - timedelta(minutes=35)).timestamp()), "host": "CORP-SRV-001", "EventCode": "4624", "Account_Name": "jsmith", "Account_Domain": "CORP", "Logon_Type": "3", "Logon_Process": "Kerberos", "Source_Network_Address": "10.10.1.101", "Workstation_Name": "CORP-WS-001"},
        ]

    # LSASS access
    if "lsass" in spl_lower:
        return [
            {"_time": str((datetime.now(timezone.utc) - timedelta(minutes=20)).timestamp()), "host": "CORP-WS-001", "EventCode": "4656", "SubjectUserName": "jsmith", "Object_Name": "\\Device\\HarddiskVolume3\\Windows\\System32\\lsass.exe", "AccessMask": "0x1010", "ProcessName": "powershell.exe"},
        ]

    # Stats aggregation
    if "stats count" in spl_lower or "stats sum" in spl_lower:
        return [{"count": "3", "host": "CORP-WS-001"}, {"count": "1", "host": "CORP-SRV-001"}]

    # Generic index search
    if "index=" in spl_lower:
        index_match = re.search(r"index=(\w+)", spl_lower)
        index = index_match.group(1) if index_match else "main"
        return [
            {"_time": str(_epoch()), "index": index, "host": "CORP-WS-001", "_raw": f"Synthetic event from {index}", "source": "simulation", "sourcetype": "generic"},
        ]

    return []


# ─────────────────────────────────────────────────────────────────────────────
# Authentication
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/services/auth/login")
async def login(request: Request):
    """Splunk basic auth login. Returns session key."""
    body = await request.body()
    return {
        "sessionKey": _SIM_TOKEN,
        "message": "",
        "name": "admin",
    }


@router.delete("/services/auth/login")
async def logout(Authorization: Optional[str] = Header(None)):
    """Log out (invalidate session)."""
    return {}


@router.get("/services/auth/current-context")
async def current_context():
    """Get current auth context."""
    return {
        "entry": [{
            "name": "admin",
            "content": {
                "capabilities": ["admin_all_objects", "search"],
                "defaultApp": "search",
                "email": "admin@corp.local",
                "realname": "Splunk Administrator",
                "roles": ["admin"],
                "username": "admin",
            },
        }]
    }


# ─────────────────────────────────────────────────────────────────────────────
# Search Jobs V1
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/services/search/jobs")
async def create_search_job(request: Request):
    """
    Create a search job.
    Form fields: search (SPL string), earliest_time, latest_time, output_mode (json|xml|csv|raw),
                 max_count, exec_mode (normal|oneshot|blocking)
    For oneshot: returns results immediately (use exec_mode=oneshot).
    For normal: returns sid, then poll /services/search/jobs/{sid} for status.
    """
    try:
        form = await request.form()
        spl = form.get("search", "")
        earliest = form.get("earliest_time", "-24h")
        latest = form.get("latest_time", "now")
        exec_mode = form.get("exec_mode", "normal")
        output_mode = form.get("output_mode", "json")
    except Exception:
        body = await request.body()
        body_str = body.decode("utf-8", errors="ignore")
        spl = ""
        earliest = "-24h"
        latest = "now"
        exec_mode = "normal"
        output_mode = "json"
        for part in body_str.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                if k == "search":
                    spl = v
                elif k == "earliest_time":
                    earliest = v
                elif k == "exec_mode":
                    exec_mode = v

    events = _execute_spl(spl, earliest, latest)

    if exec_mode == "oneshot":
        return {
            "results": events,
            "preview": False,
            "init_offset": 0,
            "messages": [],
            "fields": [{"name": k} for k in (events[0].keys() if events else [])],
            "highlighted": {},
        }

    sid = _sid()
    _SEARCH_JOBS[sid] = {
        "sid": sid,
        "search": spl,
        "earliest_time": earliest,
        "latest_time": latest,
        "results": events,
        "status": "DONE",
        "eventCount": len(events),
        "resultCount": len(events),
        "scanCount": len(events),
        "doneProgress": 1.0,
        "dispatchState": "DONE",
        "isFailed": False,
        "ttl": 86400,
        "createTime": _epoch(),
        "runDuration": 0.05,
        "is_done": True,
    }

    return {"sid": sid}


@router.get("/services/search/jobs/{sid}")
async def get_search_job(sid: str, output_mode: str = Query("json")):
    """Get search job status and metadata."""
    if sid not in _SEARCH_JOBS:
        raise HTTPException(404, detail={"messages": [{"type": "ERROR", "text": f"Unknown sid: {sid}"}]})
    job = _SEARCH_JOBS[sid]
    return {
        "entry": [{
            "name": sid,
            "id": f"https://localhost:8089/services/search/jobs/{sid}",
            "content": {
                "sid": sid,
                "search": job["search"],
                "earliestTime": job["earliest_time"],
                "latestTime": job["latest_time"],
                "eventCount": job["eventCount"],
                "resultCount": job["resultCount"],
                "scanCount": job["scanCount"],
                "doneProgress": job["doneProgress"],
                "dispatchState": job["dispatchState"],
                "isFailed": job["isFailed"],
                "isDone": job["is_done"],
                "ttl": job["ttl"],
                "createTime": job["createTime"],
                "runDuration": job["runDuration"],
                "statusBuckets": 0,
                "isFinalized": False,
                "isSaved": False,
                "performance": {"command.search.fieldsummary": {"duration_secs": 0.01}},
            },
        }],
    }


@router.get("/services/search/jobs/{sid}/results")
async def get_search_results(
    sid: str,
    output_mode: str = Query("json"),
    count: int = Query(100, ge=0),
    offset: int = Query(0),
    f: Optional[str] = Query(None, description="Field list to return"),
):
    """Get search results. output_mode: json|xml|csv|raw"""
    if sid not in _SEARCH_JOBS:
        raise HTTPException(404, detail={"messages": [{"type": "ERROR", "text": f"Unknown sid: {sid}"}]})
    job = _SEARCH_JOBS[sid]
    results = job["results"]
    if count == 0:
        page = results[offset:]
    else:
        page = results[offset: offset + count]

    if output_mode == "csv":
        if not page:
            return PlainTextResponse("")
        headers = list(page[0].keys())
        lines = [",".join(headers)]
        for row in page:
            lines.append(",".join(f'"{row.get(h, "")}"' for h in headers))
        return PlainTextResponse("\n".join(lines))

    return {
        "results": page,
        "preview": False,
        "init_offset": offset,
        "messages": [],
        "fields": [{"name": k} for k in (page[0].keys() if page else [])],
        "highlighted": {},
    }


@router.get("/services/search/jobs/{sid}/results_preview")
async def get_search_preview(sid: str, output_mode: str = Query("json"), count: int = Query(100), offset: int = Query(0)):
    """Get partial results while job is running."""
    return await get_search_results(sid=sid, output_mode=output_mode, count=count, offset=offset, f=None)


@router.get("/services/search/jobs/{sid}/events")
async def get_search_events(sid: str, output_mode: str = Query("json"), count: int = Query(100), offset: int = Query(0)):
    """Get raw events (before field extraction) from a search job."""
    return await get_search_results(sid=sid, output_mode=output_mode, count=count, offset=offset, f=None)


@router.post("/services/search/jobs/{sid}/control")
async def control_search_job(sid: str, request: Request):
    """
    Control a search job.
    action values: cancel | pause | unpause | finalize | touch | setpriority | setttl | disablepreview | enablepreview
    """
    if sid in _SEARCH_JOBS:
        try:
            form = await request.form()
            action = form.get("action", "cancel")
        except Exception:
            action = "cancel"
        if action == "cancel":
            del _SEARCH_JOBS[sid]
        elif action == "finalize":
            _SEARCH_JOBS[sid]["dispatchState"] = "DONE"
            _SEARCH_JOBS[sid]["is_done"] = True
    return {}


@router.delete("/services/search/jobs/{sid}")
async def delete_search_job(sid: str):
    """Delete (cancel) a search job."""
    _SEARCH_JOBS.pop(sid, None)
    return {}


@router.get("/services/search/jobs")
async def list_search_jobs(output_mode: str = Query("json"), count: int = Query(30)):
    """List all active search jobs."""
    entries = [{"name": sid, "id": f"https://localhost:8089/services/search/jobs/{sid}", "content": {"sid": sid, "dispatchState": j["dispatchState"], "isDone": j["is_done"], "resultCount": j["resultCount"], "doneProgress": j["doneProgress"], "search": j["search"]}} for sid, j in list(_SEARCH_JOBS.items())[:count]]
    return {"entry": entries, "messages": []}


# ─────────────────────────────────────────────────────────────────────────────
# Search Jobs V2 (async API)
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/services/search/v2/jobs")
async def create_search_job_v2(body: dict = Body(default={})):
    """V2 search API — JSON body instead of form. Returns sid."""
    spl = body.get("search", "")
    earliest = body.get("earliest", "-24h")
    latest = body.get("latest", "now")
    events = _execute_spl(spl, earliest, latest)
    sid = _sid()
    _SEARCH_JOBS[sid] = {"sid": sid, "search": spl, "earliest_time": earliest, "latest_time": latest, "results": events, "status": "DONE", "eventCount": len(events), "resultCount": len(events), "scanCount": len(events), "doneProgress": 1.0, "dispatchState": "DONE", "isFailed": False, "ttl": 86400, "createTime": _epoch(), "runDuration": 0.05, "is_done": True}
    return {"sid": sid, "status": "DONE"}


@router.get("/services/search/v2/jobs/{sid}")
async def get_search_job_v2(sid: str):
    return await get_search_job(sid=sid, output_mode="json")


@router.get("/services/search/v2/jobs/{sid}/results")
async def get_search_results_v2(sid: str, count: int = Query(100), offset: int = Query(0)):
    return await get_search_results(sid=sid, output_mode="json", count=count, offset=offset, f=None)


# ─────────────────────────────────────────────────────────────────────────────
# Saved Searches (detections/correlation searches)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/services/saved/searches")
async def list_saved_searches(
    output_mode: str = Query("json"),
    count: int = Query(100),
    offset: int = Query(0),
    search: Optional[str] = Query(None, description="Filter by name substring"),
    app: Optional[str] = Query(None),
):
    """List saved searches (detection rules in ES)."""
    searches = list(_SAVED_SEARCHES.values())
    if search:
        searches = [s for s in searches if search.lower() in s["name"].lower()]
    page = searches[offset: offset + count]
    return {
        "entry": [{"name": s["name"], "id": f"https://localhost:8089/services/saved/searches/{s['name']}", "content": s} for s in page],
        "messages": [],
        "paging": {"total": len(searches), "perPage": count, "offset": offset},
    }


@router.get("/services/saved/searches/{name}")
async def get_saved_search(name: str, output_mode: str = Query("json")):
    """Get a specific saved search."""
    if name not in _SAVED_SEARCHES:
        raise HTTPException(404, detail={"messages": [{"type": "ERROR", "text": f"Saved search '{name}' not found"}]})
    s = _SAVED_SEARCHES[name]
    return {"entry": [{"name": name, "content": s}], "messages": []}


@router.post("/services/saved/searches")
async def create_saved_search(request: Request):
    """Create/deploy a new saved search (detection rule)."""
    try:
        form = await request.form()
        form_dict = dict(form)
    except Exception:
        body = await request.body()
        form_dict = {}
        for part in body.decode("utf-8", errors="ignore").split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                form_dict[k] = v

    name = form_dict.get("name", f"search-{_uuid()[:8]}")
    _SAVED_SEARCHES[name] = {
        "name": name,
        "search": form_dict.get("search", ""),
        "cron_schedule": form_dict.get("cron_schedule", "*/15 * * * *"),
        "is_scheduled": form_dict.get("is_scheduled", "1"),
        "disabled": form_dict.get("disabled", "0"),
        "updated": _now(),
        **{k: v for k, v in form_dict.items() if k not in ("name", "search")},
    }
    return {"entry": [{"name": name, "content": _SAVED_SEARCHES[name]}], "messages": []}


@router.post("/services/saved/searches/{name}")
async def update_saved_search(name: str, request: Request):
    """Update a saved search."""
    try:
        form = await request.form()
        form_dict = dict(form)
    except Exception:
        form_dict = {}
    if name in _SAVED_SEARCHES:
        _SAVED_SEARCHES[name].update(form_dict)
        _SAVED_SEARCHES[name]["updated"] = _now()
    return {"entry": [{"name": name, "content": _SAVED_SEARCHES.get(name, {})}], "messages": []}


@router.delete("/services/saved/searches/{name}")
async def delete_saved_search(name: str):
    """Delete a saved search."""
    _SAVED_SEARCHES.pop(name, None)
    return {}


@router.post("/services/saved/searches/{name}/dispatch")
async def dispatch_saved_search(name: str, request: Request):
    """Manually run a saved search now."""
    if name not in _SAVED_SEARCHES:
        raise HTTPException(404, detail={"messages": [{"type": "ERROR", "text": f"Saved search '{name}' not found"}]})
    spl = _SAVED_SEARCHES[name].get("search", "")
    events = _execute_spl(spl)
    sid = _sid()
    _SEARCH_JOBS[sid] = {"sid": sid, "search": spl, "results": events, "eventCount": len(events), "resultCount": len(events), "scanCount": len(events), "doneProgress": 1.0, "dispatchState": "DONE", "isFailed": False, "ttl": 86400, "createTime": _epoch(), "runDuration": 0.1, "is_done": True, "earliest_time": "-24h", "latest_time": "now"}
    return {"sid": sid}


@router.get("/services/saved/searches/{name}/history")
async def get_saved_search_history(name: str, output_mode: str = Query("json")):
    """Get search run history for a saved search."""
    return {"entry": [], "messages": []}


@router.post("/services/saved/searches/{name}/acl")
async def update_saved_search_acl(name: str, request: Request):
    """Update ACL (sharing) of a saved search."""
    return {"entry": [{"name": name, "acl": {"owner": "admin", "sharing": "app"}}], "messages": []}


# ─────────────────────────────────────────────────────────────────────────────
# Notable Events (Splunk ES)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/services/notable_update")
@router.get("/services/alerts/fired_alerts")
async def list_notable_events(
    output_mode: str = Query("json"),
    count: int = Query(100),
    offset: int = Query(0),
    search: Optional[str] = Query(None),
):
    """List notable events (ES-specific)."""
    events = list(_NOTABLE_EVENTS.values())
    if search:
        events = [e for e in events if search.lower() in str(e).lower()]
    page = events[offset: offset + count]
    return {
        "entry": [{"name": e["event_id"], "content": e} for e in page],
        "messages": [],
        "paging": {"total": len(events), "perPage": count, "offset": offset},
    }


@router.post("/services/notable_update")
async def update_notable_event(request: Request):
    """
    Update notable event status/owner/urgency/comment.
    Form fields: ruleUIDs (comma-separated), status (0=Unassigned, 1=New, 2=In Progress, 3=Pending, 4=Resolved, 5=Closed),
                 urgency (informational|low|medium|high|critical), owner, comment, newOwner, disposition
    """
    try:
        form = await request.form()
        rule_uids = (form.get("ruleUIDs", "") or "").split(",")
        status = form.get("status", None)
        urgency = form.get("urgency", None)
        owner = form.get("owner", None)
        new_owner = form.get("newOwner", owner)
        comment = form.get("comment", "")
        disposition = form.get("disposition", None)
    except Exception:
        rule_uids = []
        status = None
        owner = None
        new_owner = None
        comment = ""
        urgency = None
        disposition = None

    status_labels = {"0": "Unassigned", "1": "New", "2": "In Progress", "3": "Pending", "4": "Resolved", "5": "Closed"}
    updated = 0
    for uid in rule_uids:
        uid = uid.strip()
        if uid in _NOTABLE_EVENTS:
            if status is not None:
                _NOTABLE_EVENTS[uid]["status"] = status
                _NOTABLE_EVENTS[uid]["status_label"] = status_labels.get(str(status), "Unknown")
            if owner or new_owner:
                _NOTABLE_EVENTS[uid]["owner"] = new_owner or owner
            if comment:
                _NOTABLE_EVENTS[uid]["comment"] = comment
            if urgency:
                _NOTABLE_EVENTS[uid]["urgency"] = urgency
            if disposition:
                _NOTABLE_EVENTS[uid]["disposition"] = disposition
            updated += 1

    return {"message": f"Successfully updated {updated} notable event(s)", "success": True, "details": []}


@router.post("/services/alerts/fired_alerts")
async def create_notable_event(request: Request):
    """Create a new notable event (used by ES correlation searches)."""
    try:
        form = await request.form()
        form_dict = dict(form)
    except Exception:
        form_dict = {}

    event_id = f"notable-{_uuid()[:8]}"
    event = {
        "event_id": event_id,
        "_time": _epoch(),
        "rule_name": form_dict.get("rule_name", "Custom Notable Event"),
        "security_domain": form_dict.get("security_domain", "endpoint"),
        "severity": form_dict.get("severity", "medium"),
        "urgency": form_dict.get("urgency", "medium"),
        "status": "1",
        "status_label": "New",
        "owner": "unassigned",
        "dest": form_dict.get("dest", ""),
        "src": form_dict.get("src", ""),
        "user": form_dict.get("user", ""),
        "comment": "",
        **{k: v for k, v in form_dict.items() if k not in ("rule_name", "security_domain", "severity", "urgency")},
    }
    _NOTABLE_EVENTS[event_id] = event
    return {"entry": [{"name": event_id, "content": event}], "messages": []}


# ─────────────────────────────────────────────────────────────────────────────
# KV Store — key-value collections for ES lookups
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/servicesNS/nobody/{app}/storage/collections/config")
async def list_kv_collections(app: str, output_mode: str = Query("json")):
    """List KV store collections."""
    return {
        "entry": [
            {"name": name, "content": {"_meta": col["_meta"]}, "id": f"https://localhost:8089/servicesNS/nobody/{app}/storage/collections/config/{name}"}
            for name, col in _KV_COLLECTIONS.items()
        ],
        "messages": [],
    }


@router.get("/servicesNS/nobody/{app}/storage/collections/data/{collection}")
async def get_kv_records(
    app: str,
    collection: str,
    output_mode: str = Query("json"),
    count: int = Query(100),
    offset: int = Query(0),
    query: Optional[str] = Query(None, description="MongoDB-style JSON filter: {\"type\": \"ip\"}"),
    fields: Optional[str] = Query(None, description="Comma-separated field list"),
):
    """Get records from a KV store collection."""
    if collection not in _KV_COLLECTIONS:
        return []
    records = list(_KV_COLLECTIONS[collection]["records"])

    # Apply MongoDB-style query filter
    if query:
        try:
            q = json.loads(query)
            records = [r for r in records if all(str(r.get(k, "")) == str(v) for k, v in q.items())]
        except json.JSONDecodeError:
            pass

    page = records[offset: offset + count]

    # Apply field projection
    if fields:
        field_list = [f.strip() for f in fields.split(",")]
        page = [{f: r.get(f) for f in field_list if f in r} for r in page]

    return page


@router.post("/servicesNS/nobody/{app}/storage/collections/data/{collection}")
async def insert_kv_record(app: str, collection: str, body: dict = Body(default={})):
    """Insert a record into a KV store collection."""
    if collection not in _KV_COLLECTIONS:
        _KV_COLLECTIONS[collection] = {"_meta": {"collection": collection, "fields": []}, "records": []}
    record = {"_key": _uuid(), **body}
    _KV_COLLECTIONS[collection]["records"].append(record)
    return {"_key": record["_key"]}


@router.post("/servicesNS/nobody/{app}/storage/collections/data/{collection}/batch_save")
async def batch_save_kv_records(app: str, collection: str, body: list = Body(default=[])):
    """Batch insert/update KV store records."""
    if collection not in _KV_COLLECTIONS:
        _KV_COLLECTIONS[collection] = {"_meta": {"collection": collection, "fields": []}, "records": []}
    for record in body:
        if "_key" not in record:
            record["_key"] = _uuid()
        # Upsert: replace existing with same _key
        existing = [r for r in _KV_COLLECTIONS[collection]["records"] if r.get("_key") != record["_key"]]
        _KV_COLLECTIONS[collection]["records"] = existing + [record]
    return [r["_key"] for r in body]


@router.delete("/servicesNS/nobody/{app}/storage/collections/data/{collection}/{key}")
async def delete_kv_record(app: str, collection: str, key: str):
    """Delete a specific KV record."""
    if collection in _KV_COLLECTIONS:
        _KV_COLLECTIONS[collection]["records"] = [r for r in _KV_COLLECTIONS[collection]["records"] if r.get("_key") != key]
    return {}


@router.delete("/servicesNS/nobody/{app}/storage/collections/data/{collection}")
async def clear_kv_collection(app: str, collection: str, query: Optional[str] = Query(None)):
    """Clear all records (or filtered records) from a KV collection."""
    if collection in _KV_COLLECTIONS:
        if query:
            try:
                q = json.loads(query)
                _KV_COLLECTIONS[collection]["records"] = [r for r in _KV_COLLECTIONS[collection]["records"] if not all(str(r.get(k, "")) == str(v) for k, v in q.items())]
            except json.JSONDecodeError:
                pass
        else:
            _KV_COLLECTIONS[collection]["records"] = []
    return {}


# ─────────────────────────────────────────────────────────────────────────────
# Risk-Based Alerting (RBA)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/servicesNS/nobody/SplunkEnterpriseSecuritySuite/risk/")
async def get_risk_framework():
    """Get RBA framework configuration."""
    return {"risk_threshold": 100, "risk_incident_generation": True}


@router.get("/servicesNS/nobody/SplunkEnterpriseSecuritySuite/risk/risk_factors")
async def list_risk_factors(output_mode: str = Query("json"), count: int = Query(100)):
    """
    List Risk Analysis risk factors.
    Risk factors define how risk scores are accumulated per object (user/system/other).
    risk_score: points added, risk_object_type: user|system|other, risk_object: value
    """
    return {
        "entry": [
            {"name": "Suspicious PowerShell", "content": {"risk_score": 40, "risk_object": "jsmith", "risk_object_type": "user", "src": "10.10.1.101", "dest": "CORP-WS-001", "rule_attack_tactic_technique": "Execution:T1059.001", "info_min_time": str(_epoch() - 3600), "info_max_time": str(_epoch())}},
            {"name": "LSASS Access", "content": {"risk_score": 75, "risk_object": "jsmith", "risk_object_type": "user", "src": "10.10.1.101", "dest": "CORP-WS-001", "rule_attack_tactic_technique": "CredentialAccess:T1003.001", "info_min_time": str(_epoch() - 1800), "info_max_time": str(_epoch())}},
        ],
        "messages": [],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Lookups (threat intelligence CSV/KV lookups)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/services/data/lookup-table-files")
async def list_lookup_files(output_mode: str = Query("json"), count: int = Query(100)):
    """List lookup table files (CSV files in /lookups)."""
    return {
        "entry": [
            {"name": "threat_intel_ip.csv", "content": {"filename": "threat_intel_ip.csv", "size": 1024}},
            {"name": "asset_lookup.csv", "content": {"filename": "asset_lookup.csv", "size": 2048}},
        ],
        "messages": [],
    }


@router.post("/services/data/lookup-table-files")
async def upload_lookup_file(request: Request):
    """Upload/update a lookup file."""
    return {"entry": [{"name": "uploaded_lookup.csv"}], "messages": []}


# ─────────────────────────────────────────────────────────────────────────────
# Input Lookup (SPL inputlookup simulation via REST)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/services/data/transforms/lookups")
async def list_lookup_transforms(output_mode: str = Query("json"), count: int = Query(100)):
    """List configured lookup transforms."""
    return {
        "entry": [
            {"name": "threat_intel_ip", "content": {"filename": "threat_intel_ip.csv", "fields_list": ["indicator,type,threat_group,confidence"]}},
            {"name": "asset_lookup", "content": {"filename": "asset_lookup.csv", "fields_list": ["ip,hostname,owner,priority,category"]}},
        ],
        "messages": [],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Macros
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/servicesNS/nobody/{app}/admin/macros")
async def list_macros(app: str, output_mode: str = Query("json")):
    """List saved search macros."""
    return {
        "entry": [
            {"name": "cim_authentication_indexes", "content": {"definition": "index=wineventlog OR index=auth", "args": ""}},
            {"name": "cim_endpoint_indexes", "content": {"definition": "index=wineventlog OR index=sysmon", "args": ""}},
        ],
        "messages": [],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Indexes
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/services/data/indexes")
async def list_indexes(output_mode: str = Query("json"), count: int = Query(100)):
    """List available indexes."""
    indexes = ["main", "wineventlog", "sysmon", "network", "dns", "firewall", "auth", "notable", "risk", "summary", "history", "es_notable_events"]
    return {
        "entry": [
            {"name": idx, "content": {"totalEventCount": 100000, "currentDBSizeMB": 1024, "maxTime": _now(), "minTime": "2024-01-01T00:00:00+00:00", "homePath": f"$SPLUNK_DB/{idx}/db", "coldPath": f"$SPLUNK_DB/{idx}/colddb", "isInternal": idx.startswith("_")}}
            for idx in indexes
        ],
        "messages": [],
        "paging": {"total": len(indexes), "perPage": count, "offset": 0},
    }


# ─────────────────────────────────────────────────────────────────────────────
# Server info
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/services/server/info")
async def server_info(output_mode: str = Query("json")):
    """Get Splunk server info."""
    return {
        "entry": [{
            "name": "server-info",
            "content": {
                "build": "2308088",
                "cpu_arch": "x86_64",
                "guid": _uuid(),
                "host": "splunk-sim.corp.local",
                "isFree": False,
                "isTrial": False,
                "licenseKeys": ["enterprise"],
                "licenseSignature": "sim-license",
                "licenseState": "OK",
                "master_guid": _uuid(),
                "mode": "Enterprise",
                "numberOfProcessors": 8,
                "os_build": "amd64",
                "os_name": "Linux",
                "os_name_extended": "Linux 5.15.0-76-generic",
                "os_version": "5.15.0",
                "product_type": "enterprise",
                "serverName": "splunk-sim",
                "staticAssetVersion": "7",
                "version": "9.2.1",
            },
        }],
        "messages": [],
    }


@router.get("/services/server/settings")
async def server_settings(output_mode: str = Query("json")):
    """Get Splunk server settings."""
    return {"entry": [{"name": "settings", "content": {"SPLUNK_HOME": "/opt/splunk", "httpport": 8000, "mgmtHostPort": "0.0.0.0:8089", "enableSplunkdSSL": True}}], "messages": []}
