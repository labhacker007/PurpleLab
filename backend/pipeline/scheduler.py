"""Pipeline scheduler using APScheduler."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)


class PipelineScheduler:
    """Manages cron-based pipeline runs via APScheduler."""

    def __init__(self) -> None:
        self._scheduler = AsyncIOScheduler()
        self._jobs: dict[str, str] = {}  # pipeline_id → APScheduler job_id

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Load all enabled pipeline configs and schedule them."""
        await self._load_and_schedule_all()
        self._scheduler.start()
        logger.info("PipelineScheduler started with %d jobs", len(self._jobs))

    def stop(self) -> None:
        """Shut down the scheduler gracefully."""
        try:
            self._scheduler.shutdown(wait=False)
        except Exception as exc:
            logger.debug("Scheduler shutdown: %s", exc)

    # ------------------------------------------------------------------
    # Job management
    # ------------------------------------------------------------------

    async def schedule_pipeline(self, pipeline_id: str, cron_expr: str) -> str:
        """Add or replace a scheduled job for a pipeline.

        Returns the APScheduler job ID.
        """
        # Remove existing job if any
        await self.unschedule_pipeline(pipeline_id)

        try:
            trigger = CronTrigger.from_crontab(cron_expr)
        except Exception as exc:
            raise ValueError(f"Invalid cron expression '{cron_expr}': {exc}") from exc

        job = self._scheduler.add_job(
            self._run_pipeline_task,
            trigger=trigger,
            args=[pipeline_id],
            id=f"pipeline_{pipeline_id}",
            name=f"Pipeline {pipeline_id}",
            replace_existing=True,
            misfire_grace_time=300,   # 5-minute grace window
        )
        self._jobs[pipeline_id] = job.id
        logger.info(
            "Scheduled pipeline %s with cron '%s' (job_id=%s)",
            pipeline_id, cron_expr, job.id,
        )
        return job.id

    async def unschedule_pipeline(self, pipeline_id: str) -> None:
        """Remove the scheduled job for a pipeline (if any)."""
        job_id = self._jobs.pop(pipeline_id, None)
        if job_id:
            try:
                self._scheduler.remove_job(job_id)
                logger.info("Unscheduled pipeline %s (job_id=%s)", pipeline_id, job_id)
            except Exception as exc:
                logger.debug("unschedule_pipeline: %s", exc)

    async def run_now(self, pipeline_id: str) -> None:
        """Trigger an immediate run (fire and forget)."""
        asyncio.create_task(self._run_pipeline_task(pipeline_id, triggered_by="manual"))

    def list_jobs(self) -> list[dict[str, Any]]:
        """Return scheduled job info for all pipelines."""
        jobs = []
        for pipeline_id, job_id in self._jobs.items():
            try:
                job = self._scheduler.get_job(job_id)
                if job:
                    jobs.append({
                        "pipeline_id": pipeline_id,
                        "job_id": job_id,
                        "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
                    })
            except Exception:
                pass
        return jobs

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _load_and_schedule_all(self) -> None:
        """Load enabled pipelines with cron schedules from DB and schedule them."""
        try:
            from backend.db.session import async_session
            from backend.db.models import PipelineConfig
            from sqlalchemy import select

            async with async_session() as db:
                result = await db.execute(
                    select(PipelineConfig).where(
                        PipelineConfig.enabled == True,
                        PipelineConfig.schedule_cron.isnot(None),
                    )
                )
                configs = result.scalars().all()

            for config in configs:
                try:
                    await self.schedule_pipeline(
                        str(config.id), config.schedule_cron
                    )
                except Exception as exc:
                    logger.warning(
                        "Failed to schedule pipeline %s ('%s'): %s",
                        config.id, config.name, exc,
                    )
        except Exception as exc:
            logger.warning("_load_and_schedule_all failed: %s", exc)

    async def _run_pipeline_task(
        self, pipeline_id: str, triggered_by: str = "scheduler"
    ) -> None:
        """Coroutine called by APScheduler for each scheduled run."""
        logger.info("Scheduler triggered pipeline %s", pipeline_id)
        try:
            from backend.pipeline.engine import get_pipeline_engine
            engine = await get_pipeline_engine()
            summary = await engine.run_pipeline(pipeline_id, triggered_by=triggered_by)
            logger.info(
                "Scheduled run for pipeline %s completed: status=%s",
                pipeline_id, summary.get("status"),
            )
        except Exception as exc:
            logger.exception(
                "Scheduled pipeline run %s raised: %s", pipeline_id, exc
            )


# ---------------------------------------------------------------------------
# Singleton factory
# ---------------------------------------------------------------------------

_scheduler: PipelineScheduler | None = None


async def get_scheduler() -> PipelineScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = PipelineScheduler()
    return _scheduler
