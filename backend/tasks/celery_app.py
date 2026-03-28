"""Celery application configuration.

TODO: Define async tasks for:
- Long-running rule evaluations
- MITRE ATT&CK data sync
- SIEM rule sync
- Knowledge base indexing
- Threat actor research
"""
from __future__ import annotations

from celery import Celery

from backend.config import settings

celery_app = Celery(
    "joti_sim",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,  # 5 minutes max per task
    worker_prefetch_multiplier=1,
)


# TODO: Register tasks
# @celery_app.task
# def evaluate_rules_task(test_run_id: str) -> dict:
#     """Run detection rule evaluation in background."""
#     pass

# @celery_app.task
# def sync_mitre_data_task() -> int:
#     """Sync MITRE ATT&CK data from STIX repository."""
#     pass

# @celery_app.task
# def sync_siem_rules_task(connection_id: str) -> dict:
#     """Pull rules from a connected SIEM."""
#     pass
