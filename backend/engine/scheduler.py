"""Event scheduler — extracted from engine.py.

Wraps APScheduler to manage per-session job scheduling for
periodic event generation.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

from apscheduler.schedulers.asyncio import AsyncIOScheduler

log = logging.getLogger(__name__)


class EventScheduler:
    """Manages APScheduler instances for simulation sessions.

    TODO: Consider migrating to Celery Beat for distributed scheduling
    when scaling beyond a single process.
    """

    def __init__(self) -> None:
        self.schedulers: dict[str, AsyncIOScheduler] = {}

    def start_session(
        self,
        session_id: str,
        products: list[Any],
        send_callback: Callable,
    ) -> bool:
        """Create and start a scheduler for the given session.

        Args:
            session_id: The session to schedule.
            products: List of ProductNode objects with config.
            send_callback: Async callable(session_id, product) to fire events.
        """
        scheduler = AsyncIOScheduler()

        for product in products:
            if not product.config.enabled:
                continue
            interval = 60.0 / max(product.config.events_per_minute, 0.1)
            scheduler.add_job(
                send_callback,
                "interval",
                seconds=interval,
                args=[session_id, product],
                id=f"{session_id}_{product.id}",
                replace_existing=True,
            )

        scheduler.start()
        self.schedulers[session_id] = scheduler
        log.info("scheduler_started session=%s jobs=%d", session_id, len(scheduler.get_jobs()))
        return True

    def stop_session(self, session_id: str) -> bool:
        """Stop and remove the scheduler for a session."""
        scheduler = self.schedulers.pop(session_id, None)
        if scheduler:
            scheduler.shutdown(wait=False)
            log.info("scheduler_stopped session=%s", session_id)
            return True
        return False

    def is_running(self, session_id: str) -> bool:
        """Check if a session scheduler is active."""
        return session_id in self.schedulers
