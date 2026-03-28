"""Threat intelligence endpoints for v2 API.

Provides access to threat actors, MITRE ATT&CK techniques,
coverage analysis, and research capabilities.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from backend.dependencies import get_actor_service, get_mitre_service, get_threat_researcher

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ResearchRequest(BaseModel):
    name: str


class ResearchTopicRequest(BaseModel):
    query: str


class CreateActorRequest(BaseModel):
    name: str
    aliases: list[str] = []
    description: str = ""


# ---------------------------------------------------------------------------
# Actor endpoints
# ---------------------------------------------------------------------------

@router.get("/actors")
async def list_actors(
    search: str = Query("", description="Search query for filtering actors"),
    actor_svc=Depends(get_actor_service),
):
    """List known threat actors with optional search."""
    try:
        actors = await actor_svc.list_actors(search=search)
        return {"actors": actors, "total": len(actors)}
    except Exception as exc:
        logger.error("list_actors failed: %s", exc)
        return {"actors": [], "total": 0, "error": str(exc)}


@router.get("/actors/{actor_id}")
async def get_actor(
    actor_id: str,
    actor_svc=Depends(get_actor_service),
):
    """Get detailed threat actor profile."""
    actor = await actor_svc.get_actor(actor_id)
    if actor:
        return actor
    return {"id": actor_id, "status": "not_found"}


@router.post("/actors")
async def create_actor(
    req: CreateActorRequest,
    actor_svc=Depends(get_actor_service),
):
    """Create a new threat actor profile."""
    actor = await actor_svc.create_or_update_actor(req.model_dump())
    return actor


@router.post("/actors/research")
async def research_actor(
    req: ResearchRequest,
    actor_svc=Depends(get_actor_service),
):
    """Research a threat actor using MITRE ATT&CK and web sources."""
    try:
        result = await actor_svc.research_actor(req.name)
        return result
    except Exception as exc:
        logger.error("research_actor failed: %s", exc)
        return {"name": req.name, "status": "error", "error": str(exc)}


@router.get("/actors/{actor_id}/ttps")
async def get_actor_ttps(
    actor_id: str,
    actor_svc=Depends(get_actor_service),
):
    """Get TTPs for a specific threat actor."""
    ttps = await actor_svc.get_actor_ttps(actor_id)
    return {"actor_id": actor_id, "ttps": ttps, "total": len(ttps)}


# ---------------------------------------------------------------------------
# Technique endpoints
# ---------------------------------------------------------------------------

@router.get("/techniques")
async def list_techniques(
    tactic: str = Query("", description="Filter by tactic (e.g., 'execution')"),
    platform: str = Query("", description="Filter by platform (e.g., 'Windows')"),
    search: str = Query("", description="Search query"),
    mitre_svc=Depends(get_mitre_service),
):
    """List MITRE ATT&CK techniques with filtering."""
    try:
        if search:
            techniques = await mitre_svc.search_techniques(search)
        else:
            techniques = await mitre_svc.list_techniques(tactic=tactic, platform=platform)
        return {"techniques": techniques, "total": len(techniques)}
    except Exception as exc:
        logger.error("list_techniques failed: %s", exc)
        return {"techniques": [], "total": 0, "error": str(exc)}


@router.get("/techniques/{technique_id}")
async def get_technique(
    technique_id: str,
    mitre_svc=Depends(get_mitre_service),
):
    """Get detailed MITRE technique info."""
    technique = await mitre_svc.get_technique(technique_id)
    if technique:
        return technique
    return {"technique_id": technique_id, "status": "not_found"}


# ---------------------------------------------------------------------------
# Groups endpoint
# ---------------------------------------------------------------------------

@router.get("/groups")
async def list_groups(
    mitre_svc=Depends(get_mitre_service),
):
    """List all MITRE ATT&CK threat groups."""
    try:
        groups = await mitre_svc.get_all_groups()
        return {"groups": groups, "total": len(groups)}
    except Exception as exc:
        logger.error("list_groups failed: %s", exc)
        return {"groups": [], "total": 0, "error": str(exc)}


# ---------------------------------------------------------------------------
# Coverage endpoint
# ---------------------------------------------------------------------------

@router.get("/coverage")
async def get_coverage(
    technique_ids: str = Query("", description="Comma-separated technique IDs that are covered"),
    mitre_svc=Depends(get_mitre_service),
):
    """Get MITRE ATT&CK coverage matrix.

    Shows which techniques are covered by detection rules or other
    provided technique IDs.
    """
    try:
        ids = [t.strip() for t in technique_ids.split(",") if t.strip()] if technique_ids else None
        result = await mitre_svc.get_coverage_matrix(ids)
        return result
    except Exception as exc:
        logger.error("get_coverage failed: %s", exc)
        return {"coverage": {}, "total_techniques": 0, "covered": 0, "coverage_pct": 0.0, "error": str(exc)}


# ---------------------------------------------------------------------------
# Research endpoints
# ---------------------------------------------------------------------------

@router.post("/research/topic")
async def research_topic(
    req: ResearchTopicRequest,
    researcher=Depends(get_threat_researcher),
):
    """Research an arbitrary threat intelligence topic."""
    try:
        result = await researcher.research_topic(req.query)
        return result
    except Exception as exc:
        logger.error("research_topic failed: %s", exc)
        return {"query": req.query, "status": "error", "error": str(exc)}


@router.post("/research/technique/{technique_id}")
async def research_technique(
    technique_id: str,
    researcher=Depends(get_threat_researcher),
):
    """Deep research on a specific MITRE technique."""
    try:
        result = await researcher.research_technique(technique_id)
        return result
    except Exception as exc:
        logger.error("research_technique failed: %s", exc)
        return {"technique_id": technique_id, "status": "error", "error": str(exc)}
