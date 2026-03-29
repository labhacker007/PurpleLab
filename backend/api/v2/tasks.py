"""Task status API — inspect Celery task state."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from backend.auth.dependencies import get_current_active_user

router = APIRouter(prefix="/tasks", tags=["tasks"])


@router.get("/{task_id}")
async def get_task_status(
    task_id: str,
    current_user=Depends(get_current_active_user),
) -> dict[str, Any]:
    """Get Celery task status: pending/started/success/failure + result/error."""
    from backend.celery_app import celery_app

    result = celery_app.AsyncResult(task_id)
    return {
        "task_id": task_id,
        "status": result.status.lower(),
        "result": result.result if result.successful() else None,
        "error": str(result.result) if result.failed() else None,
        "progress": result.info if isinstance(result.info, dict) else None,
    }


@router.get("")
async def list_active_tasks(
    current_user=Depends(get_current_active_user),
) -> dict[str, Any]:
    """List active/reserved tasks from Celery inspect."""
    from backend.celery_app import celery_app

    inspect = celery_app.control.inspect(timeout=2.0)
    active = inspect.active() or {}
    reserved = inspect.reserved() or {}
    all_tasks: list[dict[str, Any]] = []
    for worker, tasks in {**active, **reserved}.items():
        for t in tasks:
            all_tasks.append({
                "worker": worker,
                "task_id": t["id"],
                "name": t["name"],
                "args": t.get("args", []),
            })
    return {"tasks": all_tasks, "count": len(all_tasks)}
