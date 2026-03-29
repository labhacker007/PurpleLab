"""Notifications API — real-time SSE stream and CRUD for per-user notifications."""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncGenerator

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from backend.auth.dependencies import get_current_user
from backend.db import models
from backend.dependencies import get_redis
from backend.notifications.manager import get_notification_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/notifications", tags=["notifications"])

_REDIS_KEY_PREFIX = "pl:notifs:"
_MAX_STORED = 100
_TTL_SECONDS = 7 * 24 * 3600  # 7 days


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_notification(
    notif_type: str,
    title: str,
    message: str,
    link: str | None = None,
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "type": notif_type,
        "title": title,
        "message": message,
        "link": link,
        "read": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


async def _store_notification(redis, user_id: str, notification: dict[str, Any]) -> None:
    """Prepend notification to Redis list and cap at _MAX_STORED."""
    if redis is None:
        return
    key = f"{_REDIS_KEY_PREFIX}{user_id}"
    try:
        await redis.lpush(key, json.dumps(notification))
        await redis.ltrim(key, 0, _MAX_STORED - 1)
        await redis.expire(key, _TTL_SECONDS)
    except Exception as exc:
        logger.warning("_store_notification failed for user=%s: %s", user_id, exc)


async def _get_notifications(redis, user_id: str, limit: int = 50) -> list[dict[str, Any]]:
    """Retrieve stored notifications from Redis."""
    if redis is None:
        return []
    key = f"{_REDIS_KEY_PREFIX}{user_id}"
    try:
        raw_items = await redis.lrange(key, 0, limit - 1)
        result = []
        for raw in raw_items:
            try:
                result.append(json.loads(raw))
            except Exception:
                pass
        return result
    except Exception as exc:
        logger.warning("_get_notifications failed for user=%s: %s", user_id, exc)
        return []


# ---------------------------------------------------------------------------
# SSE stream
# ---------------------------------------------------------------------------

@router.get("/stream")
async def notification_stream(
    request: Request,
    current_user: models.User = Depends(get_current_user),
):
    """SSE stream of notifications for the authenticated user."""
    user_id = str(current_user.id)
    mgr = get_notification_manager()
    redis = await get_redis()

    async def event_generator() -> AsyncGenerator[str, None]:
        queue = await mgr.subscribe(user_id)
        try:
            # Send "connected" event
            connected_payload = json.dumps({
                "type": "info",
                "title": "Connected",
                "message": "Real-time notifications active",
                "id": str(uuid.uuid4()),
                "read": True,
                "created_at": datetime.now(timezone.utc).isoformat(),
            })
            yield f"event: connected\ndata: {connected_payload}\n\n"

            while True:
                if await request.is_disconnected():
                    break

                # Wait for a notification or heartbeat timeout
                try:
                    notification = await asyncio.wait_for(queue.get(), timeout=15.0)
                    # Store in Redis before yielding
                    await _store_notification(redis, user_id, notification)
                    data = json.dumps(notification)
                    yield f"event: notification\ndata: {data}\n\n"
                except asyncio.TimeoutError:
                    # Send heartbeat comment to keep connection alive
                    yield ": heartbeat\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            mgr.unsubscribe(user_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ---------------------------------------------------------------------------
# List notifications
# ---------------------------------------------------------------------------

@router.get("")
async def list_notifications(
    limit: int = Query(default=50, ge=1, le=100),
    current_user: models.User = Depends(get_current_user),
) -> dict[str, Any]:
    """Get recent notifications from Redis."""
    redis = await get_redis()
    user_id = str(current_user.id)
    notifications = await _get_notifications(redis, user_id, limit=limit)
    unread_count = sum(1 for n in notifications if not n.get("read", False))
    return {"notifications": notifications, "unread_count": unread_count}


# ---------------------------------------------------------------------------
# Mark read
# ---------------------------------------------------------------------------

@router.post("/{notification_id}/read")
async def mark_read(
    notification_id: str,
    current_user: models.User = Depends(get_current_user),
) -> dict[str, str]:
    """Mark a specific notification as read in Redis."""
    redis = await get_redis()
    user_id = str(current_user.id)
    if redis is None:
        return {"status": "ok"}

    key = f"{_REDIS_KEY_PREFIX}{user_id}"
    try:
        raw_items = await redis.lrange(key, 0, _MAX_STORED - 1)
        for i, raw in enumerate(raw_items):
            try:
                notif = json.loads(raw)
                if notif.get("id") == notification_id:
                    notif["read"] = True
                    await redis.lset(key, i, json.dumps(notif))
                    break
            except Exception:
                pass
    except Exception as exc:
        logger.warning("mark_read failed for user=%s notif=%s: %s", user_id, notification_id, exc)

    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Clear all notifications
# ---------------------------------------------------------------------------

@router.delete("/clear")
async def clear_notifications(
    current_user: models.User = Depends(get_current_user),
) -> dict[str, str]:
    """Clear all notifications for the current user."""
    redis = await get_redis()
    user_id = str(current_user.id)
    if redis is not None:
        key = f"{_REDIS_KEY_PREFIX}{user_id}"
        try:
            await redis.delete(key)
        except Exception as exc:
            logger.warning("clear_notifications failed for user=%s: %s", user_id, exc)
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Public helper for other modules to send notifications
# ---------------------------------------------------------------------------

async def send_notification(
    user_id: str,
    notif_type: str,
    title: str,
    message: str,
    link: str | None = None,
) -> None:
    """Convenience wrapper used by pipeline/use-case services."""
    notification = _build_notification(notif_type, title, message, link)
    mgr = get_notification_manager()
    redis = await get_redis()
    # Store in Redis
    await _store_notification(redis, user_id, notification)
    # Push to live SSE subscribers
    await mgr.send(user_id, notification)
