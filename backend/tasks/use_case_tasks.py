"""Celery tasks for use case execution."""
from __future__ import annotations

from backend.celery_app import celery_app


@celery_app.task(bind=True, name="use_case.run", max_retries=1)
def run_use_case_task(self, use_case_id: str, triggered_by: str = "api"):
    """Run validation for a single use case."""
    import asyncio
    from backend.use_cases.service import UseCaseService

    asyncio.run(UseCaseService().run_use_case(use_case_id, triggered_by=triggered_by))


@celery_app.task(bind=True, name="use_case.run_all")
def run_all_use_cases_task(self, triggered_by: str = "api"):
    """Run validation for all active use cases."""
    import asyncio
    from backend.use_cases.service import UseCaseService

    async def _run_all():
        svc = UseCaseService()
        active = await svc.list_use_cases(active_only=True, limit=500)
        for uc in active:
            await svc.run_use_case(uc["id"], triggered_by=triggered_by)

    asyncio.run(_run_all())
