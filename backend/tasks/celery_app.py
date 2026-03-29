"""Re-export the canonical Celery app from backend.celery_app.

This module is kept for backwards compatibility; import from backend.celery_app
directly in new code.
"""
from backend.celery_app import celery_app  # noqa: F401

__all__ = ["celery_app"]
