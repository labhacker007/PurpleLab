"""Celery tasks for pipeline execution."""
from __future__ import annotations

from backend.celery_app import celery_app


@celery_app.task(bind=True, name="pipeline.run", max_retries=2)
def run_pipeline_task(self, pipeline_config_id: str, triggered_by: str = "scheduler"):
    """Run a full pipeline. Wraps PipelineEngine.run_pipeline() in a sync Celery task."""
    import asyncio
    from backend.pipeline.engine import PipelineEngine

    asyncio.run(PipelineEngine().run_pipeline(pipeline_config_id, triggered_by=triggered_by))
