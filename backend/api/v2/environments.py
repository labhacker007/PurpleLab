"""Environment CRUD endpoints — v2 API.

Environments represent a simulated SOC setup: SIEM platform + log sources + config.
Fully persisted to PostgreSQL via SQLAlchemy async.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc

from backend.db.session import async_session
from backend.db.models import Environment, SIEMConnection, TestRun

router = APIRouter(prefix="/environments", tags=["environments"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class EnvironmentCreateRequest(BaseModel):
    name: str = Field(..., max_length=255)
    description: str = Field("", max_length=2000)
    siem_platform: str = Field("splunk", description="splunk|sentinel|elastic|qradar|chronicle")
    log_sources: list[str] = Field(
        default_factory=list,
        description="Log source IDs to enable (e.g. ['windows_sysmon', 'aws_cloudtrail'])",
    )
    settings: dict[str, Any] = Field(default_factory=dict)


class EnvironmentUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    siem_platform: str | None = None
    log_sources: list[str] | None = None
    settings: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("")
async def list_environments(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=200),
):
    """List all environments with SIEM connection counts."""
    async with async_session() as session:
        query = select(Environment).order_by(desc(Environment.created_at))
        query = query.offset(skip).limit(limit)
        result = await session.execute(query)
        environments = result.scalars().all()

        total_result = await session.execute(
            select(func.count()).select_from(Environment)
        )
        total = total_result.scalar() or 0

    return {
        "environments": [await _env_to_dict(e) for e in environments],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.post("")
async def create_environment(req: EnvironmentCreateRequest):
    """Create a new simulated environment."""
    async with async_session() as session:
        env = Environment(
            name=req.name,
            description=req.description,
            siem_platform=req.siem_platform,
            log_sources={"enabled": req.log_sources} if req.log_sources else {},
            settings=req.settings,
        )
        session.add(env)
        await session.commit()
        await session.refresh(env)

    return await _env_to_dict(env)


@router.get("/{environment_id}")
async def get_environment(environment_id: str):
    """Get environment details with SIEM connections and recent test runs."""
    async with async_session() as session:
        try:
            uid = uuid.UUID(environment_id)
        except ValueError:
            raise HTTPException(400, detail="Invalid environment ID.")

        result = await session.execute(
            select(Environment).where(Environment.id == uid)
        )
        env = result.scalar_one_or_none()
        if not env:
            raise HTTPException(404, detail=f"Environment '{environment_id}' not found.")

        # Get SIEM connections
        conn_result = await session.execute(
            select(SIEMConnection).where(SIEMConnection.environment_id == uid)
        )
        connections = conn_result.scalars().all()

        # Get recent test runs
        test_result = await session.execute(
            select(TestRun)
            .where(TestRun.environment_id == uid)
            .order_by(desc(TestRun.created_at))
            .limit(5)
        )
        test_runs = test_result.scalars().all()

    d = await _env_to_dict(env)
    d["siem_connections"] = [_conn_to_dict(c) for c in connections]
    d["recent_test_runs"] = [_test_run_to_dict(t) for t in test_runs]
    return d


@router.put("/{environment_id}")
async def update_environment(environment_id: str, req: EnvironmentUpdateRequest):
    """Update an environment's configuration."""
    async with async_session() as session:
        try:
            uid = uuid.UUID(environment_id)
        except ValueError:
            raise HTTPException(400, detail="Invalid environment ID.")

        result = await session.execute(
            select(Environment).where(Environment.id == uid)
        )
        env = result.scalar_one_or_none()
        if not env:
            raise HTTPException(404, detail=f"Environment '{environment_id}' not found.")

        if req.name is not None:
            env.name = req.name
        if req.description is not None:
            env.description = req.description
        if req.siem_platform is not None:
            env.siem_platform = req.siem_platform
        if req.log_sources is not None:
            env.log_sources = {"enabled": req.log_sources}
        if req.settings is not None:
            env.settings = req.settings
        env.updated_at = datetime.now(timezone.utc)

        await session.commit()
        await session.refresh(env)

    return await _env_to_dict(env)


@router.delete("/{environment_id}")
async def delete_environment(environment_id: str):
    """Delete an environment and all related data (cascade)."""
    async with async_session() as session:
        try:
            uid = uuid.UUID(environment_id)
        except ValueError:
            raise HTTPException(400, detail="Invalid environment ID.")

        result = await session.execute(
            select(Environment).where(Environment.id == uid)
        )
        env = result.scalar_one_or_none()
        if not env:
            raise HTTPException(404, detail=f"Environment '{environment_id}' not found.")

        await session.delete(env)
        await session.commit()

    return {"status": "deleted", "id": environment_id}


@router.get("/{environment_id}/log-sources")
async def get_environment_log_sources(environment_id: str):
    """List enabled log sources for an environment with schema metadata."""
    async with async_session() as session:
        try:
            uid = uuid.UUID(environment_id)
        except ValueError:
            raise HTTPException(400, detail="Invalid environment ID.")
        result = await session.execute(
            select(Environment).where(Environment.id == uid)
        )
        env = result.scalar_one_or_none()
        if not env:
            raise HTTPException(404, detail="Environment not found.")

    enabled = (env.log_sources or {}).get("enabled", [])

    from backend.log_sources.schema_registry import get_registry
    registry = get_registry()
    sources = []
    for source_id in enabled:
        schema = registry.get(source_id)
        if schema:
            sources.append({
                "source_id": source_id,
                "vendor": schema.vendor,
                "product": schema.product,
                "category": schema.category,
                "mitre_techniques": list(schema.mitre_mappings.keys()),
            })
        else:
            sources.append({"source_id": source_id, "status": "schema_not_found"})

    return {
        "environment_id": environment_id,
        "enabled_count": len(enabled),
        "sources": sources,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _env_to_dict(env: Environment) -> dict[str, Any]:
    return {
        "id": str(env.id),
        "name": env.name,
        "description": env.description,
        "siem_platform": env.siem_platform,
        "log_sources": env.log_sources or {},
        "settings": env.settings or {},
        "created_at": env.created_at.isoformat(),
        "updated_at": env.updated_at.isoformat(),
    }


def _conn_to_dict(c: SIEMConnection) -> dict[str, Any]:
    return {
        "id": str(c.id),
        "name": c.name,
        "siem_type": c.siem_type,
        "base_url": c.base_url,
        "is_connected": c.is_connected,
        "last_sync_at": c.last_sync_at.isoformat() if c.last_sync_at else None,
    }


def _test_run_to_dict(t: TestRun) -> dict[str, Any]:
    return {
        "id": str(t.id),
        "status": t.status,
        "total_rules": t.total_rules,
        "rules_passed": t.rules_passed,
        "rules_failed": t.rules_failed,
        "coverage_pct": t.coverage_pct,
        "created_at": t.created_at.isoformat(),
    }
