"""Legacy API routes — backward-compatible /api/ endpoints.

All existing endpoint handlers from the original main.py are preserved here
as a FastAPI APIRouter. The main app mounts this at /api/.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from backend.engine import engine, SessionConfig, ProductNode, TargetNode
from backend.generators.base import GeneratorConfig

router = APIRouter(tags=["legacy"])

# ── Product Catalog ───────────────────────────────────────────────────────────

PRODUCT_CATALOG = [
    # SIEM
    {"id": "splunk", "name": "Splunk Enterprise", "category": "siem", "icon": "database", "color": "#65A637",
     "description": "SIEM alerts via saved search webhook actions"},
    {"id": "sentinel", "name": "Microsoft Sentinel", "category": "siem", "icon": "shield", "color": "#0078D4",
     "description": "Cloud-native SIEM alert webhooks"},
    {"id": "qradar", "name": "IBM QRadar", "category": "siem", "icon": "server", "color": "#054ADA",
     "description": "Offense notification payloads"},
    {"id": "elastic", "name": "Elastic SIEM", "category": "siem", "icon": "search", "color": "#FEC514",
     "description": "Kibana alert rule webhooks"},
    # EDR
    {"id": "crowdstrike", "name": "CrowdStrike Falcon", "category": "edr", "icon": "crosshair", "color": "#E01E5A",
     "description": "Falcon detection streaming events"},
    {"id": "carbon_black", "name": "Carbon Black", "category": "edr", "icon": "shield-alert", "color": "#4B8BBE",
     "description": "VMware Carbon Black alert webhooks"},
    {"id": "defender_endpoint", "name": "Defender for Endpoint", "category": "edr", "icon": "shield-check", "color": "#0078D4",
     "description": "Microsoft MDE alert API format"},
    # Identity
    {"id": "okta", "name": "Okta", "category": "itdr", "icon": "user-check", "color": "#007DC1",
     "description": "System Log events (auth, MFA, impossible travel)"},
    {"id": "entra_id", "name": "Microsoft Entra ID", "category": "itdr", "icon": "users", "color": "#0078D4",
     "description": "Sign-in + audit log events"},
    # Email
    {"id": "proofpoint", "name": "Proofpoint TAP", "category": "email", "icon": "mail", "color": "#FF6600",
     "description": "Phishing/malware email threat events"},
    # ITSM
    {"id": "servicenow", "name": "ServiceNow", "category": "itsm", "icon": "ticket", "color": "#81B5A1",
     "description": "Incident management REST API format"},
    # Cloud
    {"id": "guardduty", "name": "AWS GuardDuty", "category": "cloud", "icon": "cloud", "color": "#FF9900",
     "description": "Threat finding format (recon, trojan, exfil)"},
]


# ── Routes ───────────────────────────────────────────────────────────────────

@router.get("/catalog")
def get_catalog():
    """Return available product simulators."""
    return {"products": PRODUCT_CATALOG}


@router.get("/sessions")
def list_sessions():
    return {"sessions": engine.list_sessions()}


@router.post("/sessions")
def create_session(config: SessionConfig):
    return engine.create_session(config)


@router.get("/sessions/{session_id}")
def get_session(session_id: str):
    s = engine.get_session(session_id)
    if not s:
        raise HTTPException(404, "Session not found")
    return {
        **s.model_dump(),
        "running": engine.running.get(session_id, False),
        "stats": engine.stats.get(session_id, {}),
    }


@router.put("/sessions/{session_id}")
async def update_session(session_id: str, config: SessionConfig):
    s = await engine.update_session(session_id, config)
    if not s:
        raise HTTPException(404, "Session not found")
    return s


@router.delete("/sessions/{session_id}")
def delete_session(session_id: str):
    engine.delete_session(session_id)
    return {"status": "deleted"}


@router.post("/sessions/{session_id}/start")
def start_session(session_id: str):
    if not engine.start_session(session_id):
        raise HTTPException(400, "Failed to start session")
    return {"status": "started"}


@router.post("/sessions/{session_id}/stop")
def stop_session(session_id: str):
    engine.stop_session(session_id)
    return {"status": "stopped"}


@router.get("/sessions/{session_id}/events")
def get_events(session_id: str, limit: int = Query(50, ge=1, le=200)):
    return {"events": engine.get_event_log(session_id, limit)}


@router.get("/events")
def get_all_events(limit: int = Query(50, ge=1, le=200)):
    return {"events": engine.get_event_log(limit=limit)}


@router.get("/preview/{product_type}")
def preview_event(product_type: str):
    """Generate a sample event without sending it."""
    event = engine.preview_event(product_type)
    if "error" in event:
        raise HTTPException(400, event["error"])
    return event
