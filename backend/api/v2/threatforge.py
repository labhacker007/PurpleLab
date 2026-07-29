"""ThreatForge integration — proxy endpoints for Joti threat model → PurpleLab simulation."""
from __future__ import annotations

import os
import logging

import httpx
from fastapi import APIRouter, HTTPException

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threatforge", tags=["threatforge"])

# ThreatForge base URL — inside Docker it's accessible as the service name
THREATFORGE_URL = os.getenv("THREATFORGE_URL", "http://host.docker.internal:4000")


@router.get("/health")
async def check_threatforge_health():
    """Check if ThreatForge API is reachable."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{THREATFORGE_URL}/health")
            if resp.status_code == 200:
                return {"connected": True, "url": THREATFORGE_URL, "status": resp.json()}
    except Exception as e:
        logger.warning("ThreatForge unreachable: %s", e)
    return {"connected": False, "url": THREATFORGE_URL, "status": None}


@router.get("/models")
async def list_threatforge_models():
    """Proxy — list threat models from ThreatForge with extracted ATT&CK technique IDs."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{THREATFORGE_URL}/threat-models")
            if resp.status_code != 200:
                raise HTTPException(status_code=502, detail="ThreatForge returned an error")
            data = resp.json()
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"Cannot reach ThreatForge: {e}")

    models = data.get("models", [])
    result = []
    for m in models:
        # Extract technique IDs from mitre_techniques array
        technique_ids = [t["technique_id"] for t in (m.get("mitre_techniques") or []) if t.get("technique_id")]
        # Also pull technique IDs from threats array as fallback
        if not technique_ids:
            technique_ids = list({t["technique"] for t in (m.get("threats") or []) if t.get("technique")})
        # Gather sigma rules count
        sigma_count = len(m.get("sigma_rules") or [])
        result.append({
            "id": m["id"],
            "name": m.get("name", "Untitled"),
            "description": m.get("description"),
            "framework": m.get("framework", "STRIDE"),
            "status": m.get("status", "draft"),
            "technique_ids": technique_ids,
            "technique_count": len(technique_ids),
            "sigma_count": sigma_count,
            "threat_count": len(m.get("threats") or []),
            "component_count": len(m.get("components") or []),
            "risk_score": m.get("risk_score"),
            "updated_at": m.get("updated_at"),
            "joti_model_id": m.get("joti_model_id"),
        })

    return {"models": result, "total": len(result), "threatforge_url": THREATFORGE_URL}


@router.get("/models/{model_id}")
async def get_threatforge_model(model_id: int):
    """Proxy — get a single threat model with full technique list."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{THREATFORGE_URL}/threat-models/{model_id}")
            if resp.status_code == 404:
                raise HTTPException(status_code=404, detail="Threat model not found")
            if resp.status_code != 200:
                raise HTTPException(status_code=502, detail="ThreatForge returned an error")
            return resp.json()
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"Cannot reach ThreatForge: {e}")
