"""Pipeline management REST API.

Provides CRUD and run-control endpoints for continuous purple team pipelines.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from backend.db.session import async_session
from backend.db.models import PipelineConfig, PipelineRun

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/pipeline", tags=["pipeline"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class PipelineCreateRequest(BaseModel):
    name: str
    description: str = ""
    schedule_cron: str | None = None
    enabled: bool = True
    chain_ids: list[str] = []
    siem_connection_id: str | None = None
    hitl_level_override: int | None = None
    notify_slack_channel: str = ""


class PipelineUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    schedule_cron: str | None = None
    enabled: bool | None = None
    chain_ids: list[str] | None = None
    siem_connection_id: str | None = None
    hitl_level_override: int | None = None
    notify_slack_channel: str | None = None


class RunNowRequest(BaseModel):
    triggered_by: str = "manual"


# ---------------------------------------------------------------------------
# GET /pipeline  — list all pipelines with latest run
# ---------------------------------------------------------------------------

@router.get("")
async def list_pipelines() -> dict[str, Any]:
    """List all pipeline configs with their latest run status."""
    from sqlalchemy import select, desc

    async with async_session() as db:
        result = await db.execute(
            select(PipelineConfig).order_by(PipelineConfig.created_at.desc())
        )
        configs = result.scalars().all()

    pipelines = []
    for config in configs:
        latest_run = await _get_latest_run(str(config.id))
        pipelines.append({
            "id": str(config.id),
            "name": config.name,
            "description": config.description,
            "enabled": config.enabled,
            "schedule_cron": config.schedule_cron,
            "chain_ids": list(config.chain_ids or []),
            "siem_connection_id": str(config.siem_connection_id) if config.siem_connection_id else None,
            "hitl_level_override": config.hitl_level_override,
            "notify_slack_channel": config.notify_slack_channel,
            "created_at": config.created_at.isoformat() if config.created_at else None,
            "updated_at": config.updated_at.isoformat() if config.updated_at else None,
            "latest_run": latest_run,
        })

    return {"pipelines": pipelines}


# ---------------------------------------------------------------------------
# POST /pipeline  — create
# ---------------------------------------------------------------------------

@router.post("")
async def create_pipeline(body: PipelineCreateRequest) -> dict[str, Any]:
    """Create a new pipeline config."""
    siem_id = uuid.UUID(body.siem_connection_id) if body.siem_connection_id else None

    config = PipelineConfig(
        id=uuid.uuid4(),
        name=body.name,
        description=body.description,
        schedule_cron=body.schedule_cron,
        enabled=body.enabled,
        chain_ids=body.chain_ids,
        siem_connection_id=siem_id,
        hitl_level_override=body.hitl_level_override,
        notify_slack_channel=body.notify_slack_channel,
    )

    async with async_session() as db:
        db.add(config)
        await db.commit()
        await db.refresh(config)

    pipeline_id = str(config.id)

    # Schedule if cron provided and enabled
    if config.schedule_cron and config.enabled:
        asyncio.create_task(
            _schedule_pipeline(pipeline_id, config.schedule_cron)
        )

    logger.info("Created pipeline %s ('%s')", pipeline_id, config.name)
    return _config_to_dict(config)


# ---------------------------------------------------------------------------
# GET /pipeline/coverage-gaps  — must be before /{id} route
# ---------------------------------------------------------------------------

@router.get("/coverage-gaps")
async def get_coverage_gaps() -> dict[str, Any]:
    """Return current MITRE coverage gaps (techniques with no detection rules)."""
    from backend.pipeline.engine import get_pipeline_engine

    engine = await get_pipeline_engine()
    gaps = await engine.get_coverage_gaps()
    return {
        "gap_count": len(gaps),
        "gap_techniques": gaps,
    }


# ---------------------------------------------------------------------------
# GET /pipeline/runs/{run_id}  — must be before /{id} route
# ---------------------------------------------------------------------------

@router.get("/runs/{run_id}")
async def get_run(run_id: str) -> dict[str, Any]:
    """Get a single pipeline run by ID."""
    from sqlalchemy import select

    try:
        run_uuid = uuid.UUID(run_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid run ID")

    async with async_session() as db:
        result = await db.execute(
            select(PipelineRun).where(PipelineRun.id == run_uuid)
        )
        run = result.scalar_one_or_none()

    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")

    return _run_to_dict(run)


# ---------------------------------------------------------------------------
# GET /pipeline/{id}  — get single pipeline with all runs
# ---------------------------------------------------------------------------

@router.get("/{pipeline_id}")
async def get_pipeline(pipeline_id: str) -> dict[str, Any]:
    """Get a single pipeline config with all its runs."""
    from sqlalchemy import select, desc

    try:
        pid = uuid.UUID(pipeline_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid pipeline ID")

    async with async_session() as db:
        result = await db.execute(
            select(PipelineConfig).where(PipelineConfig.id == pid)
        )
        config = result.scalar_one_or_none()

    if config is None:
        raise HTTPException(status_code=404, detail="Pipeline not found")

    # Load all runs
    async with async_session() as db:
        result = await db.execute(
            select(PipelineRun)
            .where(PipelineRun.pipeline_id == pid)
            .order_by(PipelineRun.created_at.desc())
        )
        runs = result.scalars().all()

    data = _config_to_dict(config)
    data["runs"] = [_run_to_dict(r) for r in runs]
    return data


# ---------------------------------------------------------------------------
# PUT /pipeline/{id}  — update
# ---------------------------------------------------------------------------

@router.put("/{pipeline_id}")
async def update_pipeline(
    pipeline_id: str, body: PipelineUpdateRequest
) -> dict[str, Any]:
    """Update pipeline config. Reschedules if cron changed."""
    from sqlalchemy import select

    try:
        pid = uuid.UUID(pipeline_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid pipeline ID")

    async with async_session() as db:
        result = await db.execute(
            select(PipelineConfig).where(PipelineConfig.id == pid)
        )
        config = result.scalar_one_or_none()

        if config is None:
            raise HTTPException(status_code=404, detail="Pipeline not found")

        old_cron = config.schedule_cron

        if body.name is not None:
            config.name = body.name
        if body.description is not None:
            config.description = body.description
        if body.schedule_cron is not None:
            config.schedule_cron = body.schedule_cron
        if body.enabled is not None:
            config.enabled = body.enabled
        if body.chain_ids is not None:
            config.chain_ids = body.chain_ids
        if body.siem_connection_id is not None:
            config.siem_connection_id = uuid.UUID(body.siem_connection_id)
        if body.hitl_level_override is not None:
            config.hitl_level_override = body.hitl_level_override
        if body.notify_slack_channel is not None:
            config.notify_slack_channel = body.notify_slack_channel

        config.updated_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(config)

    # Re-schedule if cron or enabled status changed
    new_cron = config.schedule_cron
    cron_changed = new_cron != old_cron or body.enabled is not None
    if cron_changed:
        if config.enabled and new_cron:
            asyncio.create_task(_schedule_pipeline(pipeline_id, new_cron))
        else:
            asyncio.create_task(_unschedule_pipeline(pipeline_id))

    logger.info("Updated pipeline %s", pipeline_id)
    return _config_to_dict(config)


# ---------------------------------------------------------------------------
# DELETE /pipeline/{id}
# ---------------------------------------------------------------------------

@router.delete("/{pipeline_id}")
async def delete_pipeline(pipeline_id: str) -> dict[str, Any]:
    """Delete a pipeline config and unschedule it."""
    from sqlalchemy import select

    try:
        pid = uuid.UUID(pipeline_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid pipeline ID")

    async with async_session() as db:
        result = await db.execute(
            select(PipelineConfig).where(PipelineConfig.id == pid)
        )
        config = result.scalar_one_or_none()

        if config is None:
            raise HTTPException(status_code=404, detail="Pipeline not found")

        await db.delete(config)
        await db.commit()

    asyncio.create_task(_unschedule_pipeline(pipeline_id))
    logger.info("Deleted pipeline %s", pipeline_id)
    return {"deleted": True, "id": pipeline_id}


# ---------------------------------------------------------------------------
# POST /pipeline/{id}/run  — trigger immediate run
# ---------------------------------------------------------------------------

@router.post("/{pipeline_id}/run")
async def trigger_run(pipeline_id: str, body: RunNowRequest) -> dict[str, Any]:
    """Trigger an immediate pipeline run. Returns run ID immediately."""
    from sqlalchemy import select

    try:
        pid = uuid.UUID(pipeline_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid pipeline ID")

    # Verify pipeline exists
    async with async_session() as db:
        result = await db.execute(
            select(PipelineConfig).where(PipelineConfig.id == pid)
        )
        config = result.scalar_one_or_none()

    if config is None:
        raise HTTPException(status_code=404, detail="Pipeline not found")

    # Create a placeholder run record so we can return the ID immediately
    run = PipelineRun(
        id=uuid.uuid4(),
        pipeline_id=pid,
        status="pending",
        triggered_by=body.triggered_by,
        started_at=datetime.now(timezone.utc),
    )
    async with async_session() as db:
        db.add(run)
        await db.commit()
        await db.refresh(run)

    run_id = str(run.id)

    # Fire pipeline execution as a background task
    async def _execute() -> None:
        from backend.pipeline.engine import get_pipeline_engine
        engine = await get_pipeline_engine()
        await engine.run_pipeline(pipeline_id, triggered_by=body.triggered_by)

    asyncio.create_task(_execute())

    logger.info("Triggered immediate run for pipeline %s (run_id=%s)", pipeline_id, run_id)
    return {
        "run_id": run_id,
        "pipeline_id": pipeline_id,
        "status": "pending",
        "triggered_by": body.triggered_by,
    }


# ---------------------------------------------------------------------------
# GET /pipeline/{id}/runs  — paginated run list
# ---------------------------------------------------------------------------

@router.get("/{pipeline_id}/runs")
async def list_runs(
    pipeline_id: str,
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Paginated list of runs for a pipeline."""
    from sqlalchemy import select, func, desc

    try:
        pid = uuid.UUID(pipeline_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid pipeline ID")

    async with async_session() as db:
        # Total count
        count_result = await db.execute(
            select(func.count(PipelineRun.id)).where(
                PipelineRun.pipeline_id == pid
            )
        )
        total = count_result.scalar() or 0

        # Paginated rows
        result = await db.execute(
            select(PipelineRun)
            .where(PipelineRun.pipeline_id == pid)
            .order_by(desc(PipelineRun.created_at))
            .offset(offset)
            .limit(limit)
        )
        runs = result.scalars().all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "runs": [_run_to_dict(r) for r in runs],
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _config_to_dict(config: PipelineConfig) -> dict[str, Any]:
    return {
        "id": str(config.id),
        "name": config.name,
        "description": config.description,
        "enabled": config.enabled,
        "schedule_cron": config.schedule_cron,
        "chain_ids": list(config.chain_ids or []),
        "siem_connection_id": str(config.siem_connection_id) if config.siem_connection_id else None,
        "hitl_level_override": config.hitl_level_override,
        "notify_slack_channel": config.notify_slack_channel,
        "created_at": config.created_at.isoformat() if config.created_at else None,
        "updated_at": config.updated_at.isoformat() if config.updated_at else None,
    }


def _run_to_dict(run: PipelineRun) -> dict[str, Any]:
    return {
        "id": str(run.id),
        "pipeline_id": str(run.pipeline_id),
        "status": run.status,
        "triggered_by": run.triggered_by,
        "chains_run": run.chains_run,
        "events_generated": run.events_generated,
        "detections_fired": run.detections_fired,
        "des_before": run.des_before,
        "des_after": run.des_after,
        "error_message": run.error_message,
        "report_url": run.report_url,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }


async def _get_latest_run(pipeline_id: str) -> dict[str, Any] | None:
    from sqlalchemy import select, desc

    try:
        async with async_session() as db:
            result = await db.execute(
                select(PipelineRun)
                .where(PipelineRun.pipeline_id == uuid.UUID(pipeline_id))
                .order_by(desc(PipelineRun.created_at))
                .limit(1)
            )
            run = result.scalar_one_or_none()
        return _run_to_dict(run) if run else None
    except Exception:
        return None


async def _schedule_pipeline(pipeline_id: str, cron_expr: str) -> None:
    try:
        from backend.pipeline.scheduler import get_scheduler
        sched = await get_scheduler()
        await sched.schedule_pipeline(pipeline_id, cron_expr)
    except Exception as exc:
        logger.warning("Failed to schedule pipeline %s: %s", pipeline_id, exc)


async def _unschedule_pipeline(pipeline_id: str) -> None:
    try:
        from backend.pipeline.scheduler import get_scheduler
        sched = await get_scheduler()
        await sched.unschedule_pipeline(pipeline_id)
    except Exception as exc:
        logger.warning("Failed to unschedule pipeline %s: %s", pipeline_id, exc)
