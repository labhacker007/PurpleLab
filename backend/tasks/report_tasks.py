"""Celery tasks for report generation."""
from __future__ import annotations

import logging

from backend.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="report.generate")
def generate_report_task(self, report_id: str):
    """Generate a report asynchronously and update its status in the DB."""
    import asyncio
    from datetime import datetime, timezone

    async def _generate():
        from backend.db.session import async_session
        from backend.db import models

        # Mark report as generating
        async with async_session() as db:
            report = await db.get(models.Report, report_id)
            if not report:
                logger.warning("report.generate: report %s not found", report_id)
                return
            report.status = "generating"
            await db.commit()

        try:
            # Import and call the report data generator from the API layer
            from backend.api.v2.reports import _generate_report_data
            data = await _generate_report_data(report_id)

            async with async_session() as db:
                report = await db.get(models.Report, report_id)
                if report:
                    report.status = "completed"
                    report.data = data
                    report.completed_at = datetime.now(timezone.utc)
                    await db.commit()
                    logger.info("Report %s generated successfully", report_id)

        except Exception as exc:
            logger.exception("Report generation failed for %s: %s", report_id, exc)
            async with async_session() as db:
                report = await db.get(models.Report, report_id)
                if report:
                    report.status = "error"
                    report.error_message = str(exc)
                    report.completed_at = datetime.now(timezone.utc)
                    await db.commit()
            raise

    asyncio.run(_generate())
