"""Use case management REST API.

Provides CRUD, validation run control, coverage reporting, and bulk operations
for purple team use cases.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/use-cases", tags=["use-cases"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class UseCaseCreateRequest(BaseModel):
    name: str
    description: str = ""
    technique_ids: list[str] = Field(default_factory=list)
    tactic: str = ""
    threat_actor: str = ""
    attack_chain_id: str = ""
    expected_log_sources: list[str] = Field(default_factory=list)
    severity: str = "high"
    tags: list[str] = Field(default_factory=list)
    is_active: bool = True


class UseCaseUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    technique_ids: list[str] | None = None
    tactic: str | None = None
    threat_actor: str | None = None
    attack_chain_id: str | None = None
    expected_log_sources: list[str] | None = None
    severity: str | None = None
    tags: list[str] | None = None
    is_active: bool | None = None


class RunTriggerRequest(BaseModel):
    triggered_by: str = "manual"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("")
async def list_use_cases(
    active_only: bool = Query(False, description="Return only active use cases"),
    tactic: str | None = Query(None),
    severity: str | None = Query(None),
    search: str | None = Query(None, description="Search name and description"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """List all use cases with optional filters."""
    from backend.use_cases.service import UseCaseService
    svc = UseCaseService()
    use_cases = await svc.list_use_cases(
        active_only=active_only,
        tactic=tactic,
        severity=severity,
        search=search,
        limit=limit,
        offset=offset,
    )
    return {"use_cases": use_cases, "total": len(use_cases), "offset": offset, "limit": limit}


@router.post("")
async def create_use_case(body: UseCaseCreateRequest) -> dict[str, Any]:
    """Create a new use case."""
    from backend.use_cases.service import UseCaseService
    svc = UseCaseService()
    return await svc.create_use_case(body.model_dump())


@router.get("/coverage")
async def get_coverage_summary() -> dict[str, Any]:
    """Coverage summary: per-tactic pass/fail stats and overall coverage percentage."""
    from backend.use_cases.service import UseCaseService
    svc = UseCaseService()
    return await svc.get_coverage_summary()


@router.get("/failing")
async def get_failing_use_cases() -> dict[str, Any]:
    """All use cases with no passing run or that have never been run."""
    from backend.use_cases.service import UseCaseService
    svc = UseCaseService()
    failing = await svc.get_failing_use_cases()
    return {"failing": failing, "total": len(failing)}


@router.post("/run-all")
async def run_all_use_cases(
    triggered_by: str = Query("manual"),
) -> dict[str, Any]:
    """Trigger validation for all active use cases via a single Celery task.

    Returns immediately with task_id to poll for completion.
    """
    from backend.tasks.use_case_tasks import run_all_use_cases_task

    task = run_all_use_cases_task.delay(triggered_by=triggered_by)
    return {
        "status": "queued",
        "task_id": task.id,
        "message": "Validation for all active use cases has been queued",
    }


@router.get("/{use_case_id}")
async def get_use_case(use_case_id: str) -> dict[str, Any]:
    """Get a single use case with recent run history."""
    from backend.use_cases.service import UseCaseService
    svc = UseCaseService()
    uc = await svc.get_use_case(use_case_id)
    if not uc:
        raise HTTPException(status_code=404, detail=f"Use case {use_case_id} not found")
    return uc


@router.put("/{use_case_id}")
async def update_use_case(
    use_case_id: str, body: UseCaseUpdateRequest
) -> dict[str, Any]:
    """Update a use case."""
    from backend.use_cases.service import UseCaseService
    svc = UseCaseService()
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    updated = await svc.update_use_case(use_case_id, updates)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Use case {use_case_id} not found")
    return updated


@router.delete("/{use_case_id}")
async def delete_use_case(use_case_id: str) -> dict[str, Any]:
    """Delete a use case and all its runs."""
    from backend.use_cases.service import UseCaseService
    svc = UseCaseService()
    deleted = await svc.delete_use_case(use_case_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Use case {use_case_id} not found")
    return {"status": "deleted", "id": use_case_id}


@router.post("/{use_case_id}/run")
async def run_use_case(
    use_case_id: str,
    body: RunTriggerRequest = RunTriggerRequest(),
) -> dict[str, Any]:
    """Trigger a validation run for a use case via Celery.

    Returns immediately with task_id. Poll GET /tasks/{task_id} for status.
    """
    from backend.db.session import async_session
    from backend.db import models
    from backend.tasks.use_case_tasks import run_use_case_task

    # Verify use case exists first
    async with async_session() as db:
        uc = await db.get(models.UseCase, uuid.UUID(use_case_id))
        if not uc:
            raise HTTPException(status_code=404, detail=f"Use case {use_case_id} not found")

        # Create a pending run record so callers can track via run history
        run = models.UseCaseRun(
            use_case_id=uc.id,
            status="pending",
            triggered_by=body.triggered_by,
        )
        db.add(run)
        await db.commit()
        await db.refresh(run)
        run_id = str(run.id)

    task = run_use_case_task.delay(use_case_id, triggered_by=body.triggered_by)

    return {
        "run_id": run_id,
        "use_case_id": use_case_id,
        "status": "queued",
        "task_id": task.id,
    }


@router.get("/{use_case_id}/runs")
async def get_run_history(
    use_case_id: str,
    limit: int = Query(20, ge=1, le=100),
) -> dict[str, Any]:
    """Get validation run history for a use case."""
    from backend.use_cases.service import UseCaseService
    svc = UseCaseService()
    runs = await svc.get_run_history(use_case_id, limit=limit)
    return {"runs": runs, "total": len(runs)}
