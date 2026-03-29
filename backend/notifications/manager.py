"""In-process notification broadcast manager using SSE."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


class NotificationManager:
    """Manages SSE subscriber queues for per-user push notifications."""

    def __init__(self) -> None:
        self._queues: dict[str, list[asyncio.Queue]] = {}  # user_id -> list of queues

    async def subscribe(self, user_id: str) -> asyncio.Queue:
        """Returns a new queue for this user. Call unsubscribe when done."""
        q: asyncio.Queue = asyncio.Queue()
        if user_id not in self._queues:
            self._queues[user_id] = []
        self._queues[user_id].append(q)
        logger.debug("NotificationManager: subscribed user=%s (total queues=%d)", user_id, len(self._queues[user_id]))
        return q

    def unsubscribe(self, user_id: str, queue: asyncio.Queue) -> None:
        """Remove a queue for this user."""
        if user_id in self._queues:
            try:
                self._queues[user_id].remove(queue)
            except ValueError:
                pass
            if not self._queues[user_id]:
                del self._queues[user_id]
        logger.debug("NotificationManager: unsubscribed user=%s", user_id)

    async def send(self, user_id: str, notification: dict[str, Any]) -> None:
        """Push notification to all queues for user_id."""
        queues = self._queues.get(user_id, [])
        for q in list(queues):
            try:
                await q.put(notification)
            except Exception as exc:
                logger.warning("NotificationManager.send failed for user=%s: %s", user_id, exc)

    async def broadcast(self, notification: dict[str, Any]) -> None:
        """Send to ALL connected users."""
        for user_id in list(self._queues.keys()):
            await self.send(user_id, notification)

    def connected_users(self) -> list[str]:
        """List of user_ids with active connections."""
        return list(self._queues.keys())


_manager: NotificationManager | None = None


def get_notification_manager() -> NotificationManager:
    global _manager
    if _manager is None:
        _manager = NotificationManager()
    return _manager
