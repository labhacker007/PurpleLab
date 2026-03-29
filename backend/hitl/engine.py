"""HITL Approval Engine.

Manages the full lifecycle of human-in-the-loop approval requests:
  - Creating requests with DB persistence
  - Sending notifications (Slack, Magic Link, PagerDuty, webhook)
  - Waiting for approval with asyncio.Event
  - Magic Link token generation + validation
  - Auto-approve L0 / timeout-expire L1-L3
  - Admin config CRUD
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from backend.hitl.models import (
    HITLLevel,
    HITLRequest,
    HITLStatus,
    ActionConfig,
    DEFAULT_ACTION_CONFIGS,
    NotificationChannels,
)

logger = logging.getLogger(__name__)

# In-memory wait handles: request_id → asyncio.Event
_pending_events: dict[str, asyncio.Event] = {}

# In-memory action config cache (loaded from DB + defaults)
_action_config_cache: dict[str, ActionConfig] = {}

# Base URL for Magic Links
_MAGIC_LINK_BASE = os.environ.get("PURPLELAB_BASE_URL", "http://localhost:4000")


class HITLEngine:
    """Core HITL approval engine."""

    def __init__(self) -> None:
        self._configs: dict[str, ActionConfig] = dict(DEFAULT_ACTION_CONFIGS)

    # ------------------------------------------------------------------
    # Main entry point — request an approval
    # ------------------------------------------------------------------

    async def request(
        self,
        action_type: str,
        payload: dict[str, Any],
        requested_by: str = "agent",
        context: dict[str, Any] | None = None,
        override_level: HITLLevel | None = None,
    ) -> HITLRequest:
        """Create an approval request for an action.

        If L0: auto-approves immediately and returns an approved request.
        If L1-L3: persists to DB, sends notifications, returns pending request.
        Caller should then await engine.wait_for_approval(request.id).
        """
        config = await self._get_config(action_type)
        level = override_level if override_level is not None else config.level

        # L0 — auto-approve immediately
        if level == HITLLevel.L0_AUTO:
            req = self._make_request(action_type, payload, level, requested_by, context, config)
            req.status = HITLStatus.AUTO_APPROVED
            req.resolved_at = datetime.now(timezone.utc)
            logger.debug("HITL L0 auto-approved: %s", action_type)
            return req

        # L1-L3 — create pending request
        req = self._make_request(action_type, payload, level, requested_by, context, config)

        # Persist to DB
        await self._save_to_db(req, config)

        # Create wait event
        _pending_events[req.id] = asyncio.Event()

        # Send notifications
        await self._send_notifications(req, config)

        # L0 with grace period (soft auto-approve)
        if config.auto_approve_after_seconds and level == HITLLevel.L1_SOFT:
            asyncio.create_task(
                self._auto_approve_after(req.id, config.auto_approve_after_seconds)
            )

        # Schedule expiry
        asyncio.create_task(
            self._expire_after(req.id, config.timeout_seconds)
        )

        logger.info(
            "HITL request created: id=%s action=%s level=L%d",
            req.id, action_type, int(level)
        )
        return req

    async def wait_for_approval(
        self, request_id: str, timeout: float | None = None
    ) -> HITLRequest | None:
        """Block until the request is resolved (approved/rejected/expired).

        Returns the resolved HITLRequest, or None if not found.
        """
        event = _pending_events.get(request_id)
        if not event:
            # Already resolved (or not found) — load from DB
            return await self._load_from_db(request_id)

        try:
            await asyncio.wait_for(event.wait(), timeout=timeout or 7200)
        except asyncio.TimeoutError:
            await self.expire(request_id)

        _pending_events.pop(request_id, None)
        return await self._load_from_db(request_id)

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    async def approve(
        self,
        request_id: str,
        reviewed_by: str,
        note: str = "",
    ) -> HITLRequest | None:
        """Approve a pending request."""
        return await self._resolve(request_id, HITLStatus.APPROVED, reviewed_by, note)

    async def reject(
        self,
        request_id: str,
        reviewed_by: str,
        note: str = "",
    ) -> HITLRequest | None:
        """Reject a pending request."""
        return await self._resolve(request_id, HITLStatus.REJECTED, reviewed_by, note)

    async def expire(self, request_id: str) -> None:
        """Mark a request as expired."""
        await self._resolve(request_id, HITLStatus.EXPIRED, "system", "Timeout expired")

    async def approve_via_magic_link(
        self, token: str, reviewed_by: str = "magic_link"
    ) -> HITLRequest | None:
        """Validate a Magic Link token and approve the associated request."""
        request_id = await self._lookup_magic_link(token)
        if not request_id:
            return None
        return await self.approve(request_id, reviewed_by, note="Approved via Magic Link")

    # ------------------------------------------------------------------
    # Admin config
    # ------------------------------------------------------------------

    async def get_config(self, action_type: str) -> ActionConfig:
        return await self._get_config(action_type)

    async def set_config(self, config: ActionConfig) -> ActionConfig:
        self._configs[config.action_type] = config
        await self._save_config_to_db(config)
        logger.info("HITL config updated: %s → L%d", config.action_type, int(config.level))
        return config

    def list_configs(self) -> list[ActionConfig]:
        return list(self._configs.values())

    async def list_pending(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return pending requests from DB."""
        try:
            from backend.db.session import async_session
            from backend.db.models import HITLApprovalRequest
            from sqlalchemy import select, desc
            async with async_session() as session:
                result = await session.execute(
                    select(HITLApprovalRequest)
                    .where(HITLApprovalRequest.status == "pending")
                    .order_by(desc(HITLApprovalRequest.created_at))
                    .limit(limit)
                )
                rows = result.scalars().all()
                return [self._db_to_request(r).to_dict() for r in rows]
        except Exception as exc:
            logger.warning("list_pending DB failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Magic Link generation
    # ------------------------------------------------------------------

    def generate_magic_link(self, request_id: str) -> tuple[str, str]:
        """Return (token, full_url) for a Magic Link."""
        token = secrets.token_urlsafe(48)
        url = f"{_MAGIC_LINK_BASE}/api/v2/hitl/approve/{token}"
        return token, url

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_request(
        self,
        action_type: str,
        payload: dict[str, Any],
        level: HITLLevel,
        requested_by: str,
        context: dict[str, Any] | None,
        config: ActionConfig,
    ) -> HITLRequest:
        rid = str(uuid.uuid4())
        token, url = self.generate_magic_link(rid)
        now = datetime.now(timezone.utc)
        return HITLRequest(
            id=rid,
            action_type=action_type,
            action_payload=payload,
            level=level,
            status=HITLStatus.PENDING,
            requested_by=requested_by,
            magic_link_token=token,
            magic_link_url=url,
            created_at=now,
            expires_at=now + timedelta(seconds=config.timeout_seconds),
            approvals_required=config.required_approvals,
        )

    async def _resolve(
        self,
        request_id: str,
        status: str,
        reviewed_by: str,
        note: str,
    ) -> HITLRequest | None:
        now = datetime.now(timezone.utc)
        try:
            from backend.db.session import async_session
            from backend.db.models import HITLApprovalRequest
            from sqlalchemy import select
            async with async_session() as session:
                result = await session.execute(
                    select(HITLApprovalRequest).where(
                        HITLApprovalRequest.id == uuid.UUID(request_id)
                    )
                )
                row = result.scalar_one_or_none()
                if row:
                    row.status = status
                    row.reviewed_by = reviewed_by
                    row.review_note = note
                    row.resolved_at = now
                    await session.commit()
        except Exception as exc:
            logger.warning("Failed to update HITL in DB: %s", exc)

        # Unblock any waiting coroutine
        event = _pending_events.get(request_id)
        if event:
            event.set()

        logger.info("HITL request %s → %s by %s", request_id, status, reviewed_by)
        return await self._load_from_db(request_id)

    async def _get_config(self, action_type: str) -> ActionConfig:
        # Try memory cache first
        if action_type in self._configs:
            return self._configs[action_type]
        # Try DB
        try:
            from backend.db.session import async_session
            from backend.db.models import HITLActionConfig
            from sqlalchemy import select
            async with async_session() as session:
                result = await session.execute(
                    select(HITLActionConfig).where(
                        HITLActionConfig.action_type == action_type
                    )
                )
                row = result.scalar_one_or_none()
                if row:
                    cfg = ActionConfig(
                        action_type=row.action_type,
                        level=HITLLevel(row.level),
                        description=row.description,
                        notifications=NotificationChannels.from_dict(
                            row.notification_channels or {}
                        ),
                        auto_approve_after_seconds=row.auto_approve_after_seconds,
                        timeout_seconds=3600,
                    )
                    self._configs[action_type] = cfg
                    return cfg
        except Exception:
            pass
        # Fall back to L1 default
        return ActionConfig(
            action_type=action_type,
            level=HITLLevel.L1_SOFT,
            description=f"Approval required for: {action_type}",
            auto_approve_after_seconds=30,
        )

    async def _save_to_db(self, req: HITLRequest, config: ActionConfig) -> None:
        try:
            from backend.db.session import async_session
            from backend.db.models import HITLApprovalRequest
            async with async_session() as session:
                row = HITLApprovalRequest(
                    id=uuid.UUID(req.id),
                    action_type=req.action_type,
                    action_payload=req.action_payload,
                    level=int(req.level),
                    status=req.status,
                    requested_by=req.requested_by,
                    magic_link_token=req.magic_link_token,
                    magic_link_expires_at=req.expires_at,
                    notification_channels=config.notifications.to_dict(),
                    auto_approve_after_seconds=config.auto_approve_after_seconds,
                )
                session.add(row)
                await session.commit()
        except Exception as exc:
            logger.warning("Failed to persist HITL request to DB: %s", exc)

    async def _load_from_db(self, request_id: str) -> HITLRequest | None:
        try:
            from backend.db.session import async_session
            from backend.db.models import HITLApprovalRequest
            from sqlalchemy import select
            async with async_session() as session:
                result = await session.execute(
                    select(HITLApprovalRequest).where(
                        HITLApprovalRequest.id == uuid.UUID(request_id)
                    )
                )
                row = result.scalar_one_or_none()
                if row:
                    return self._db_to_request(row)
        except Exception as exc:
            logger.warning("Failed to load HITL from DB: %s", exc)
        return None

    async def _lookup_magic_link(self, token: str) -> str | None:
        try:
            from backend.db.session import async_session
            from backend.db.models import HITLApprovalRequest
            from sqlalchemy import select
            async with async_session() as session:
                result = await session.execute(
                    select(HITLApprovalRequest).where(
                        HITLApprovalRequest.magic_link_token == token
                    )
                )
                row = result.scalar_one_or_none()
                if row:
                    now = datetime.now(timezone.utc)
                    if row.magic_link_expires_at and row.magic_link_expires_at < now:
                        logger.warning("Magic link expired: %s", token[:16])
                        return None
                    if row.status != "pending":
                        return None
                    return str(row.id)
        except Exception as exc:
            logger.warning("Magic link lookup failed: %s", exc)
        return None

    async def _save_config_to_db(self, config: ActionConfig) -> None:
        try:
            from backend.db.session import async_session
            from backend.db.models import HITLActionConfig
            from sqlalchemy import text
            async with async_session() as session:
                await session.execute(
                    text("""
                        INSERT INTO hitl_action_configs
                            (action_type, level, description, notification_channels,
                             auto_approve_after_seconds, is_active, updated_at)
                        VALUES (:at, :level, :desc, :notif, :auto, true, NOW())
                        ON CONFLICT (action_type) DO UPDATE SET
                            level = EXCLUDED.level,
                            description = EXCLUDED.description,
                            notification_channels = EXCLUDED.notification_channels,
                            auto_approve_after_seconds = EXCLUDED.auto_approve_after_seconds,
                            updated_at = NOW()
                    """),
                    {
                        "at": config.action_type,
                        "level": int(config.level),
                        "desc": config.description,
                        "notif": str(config.notifications.to_dict()),
                        "auto": config.auto_approve_after_seconds,
                    },
                )
                await session.commit()
        except Exception as exc:
            logger.warning("Failed to save HITL config to DB: %s", exc)

    def _db_to_request(self, row: Any) -> HITLRequest:
        token = row.magic_link_token
        url = f"{_MAGIC_LINK_BASE}/api/v2/hitl/approve/{token}" if token else None
        return HITLRequest(
            id=str(row.id),
            action_type=row.action_type,
            action_payload=row.action_payload or {},
            level=HITLLevel(row.level),
            status=row.status,
            requested_by=row.requested_by or "agent",
            magic_link_token=token,
            magic_link_url=url,
            created_at=row.created_at,
            resolved_at=row.resolved_at,
            reviewed_by=row.reviewed_by,
            review_note=row.review_note or "",
        )

    async def _auto_approve_after(self, request_id: str, seconds: int) -> None:
        await asyncio.sleep(seconds)
        req = await self._load_from_db(request_id)
        if req and req.status == HITLStatus.PENDING:
            await self._resolve(request_id, HITLStatus.AUTO_APPROVED, "system",
                                f"Auto-approved after {seconds}s grace period")

    async def _expire_after(self, request_id: str, seconds: int) -> None:
        await asyncio.sleep(seconds)
        req = await self._load_from_db(request_id)
        if req and req.status == HITLStatus.PENDING:
            await self.expire(request_id)

    # ------------------------------------------------------------------
    # Notification dispatch
    # ------------------------------------------------------------------

    async def _send_notifications(self, req: HITLRequest, config: ActionConfig) -> None:
        """Fire-and-forget notifications — failures are logged, not raised."""
        nc = config.notifications
        tasks = []
        if nc.slack_channel or nc.slack_user_ids:
            tasks.append(self._notify_slack(req, nc))
        if nc.webhook_url:
            tasks.append(self._notify_webhook(req, nc.webhook_url))
        if nc.pagerduty_routing_key:
            tasks.append(self._notify_pagerduty(req, nc.pagerduty_routing_key))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    logger.warning("HITL notification failed: %s", r)

    async def _notify_slack(self, req: HITLRequest, nc: NotificationChannels) -> None:
        slack_token = os.environ.get("SLACK_BOT_TOKEN", "")
        if not slack_token:
            logger.debug("SLACK_BOT_TOKEN not set — skipping Slack notification")
            return

        import httpx
        level_emoji = {0: "🤖", 1: "⚠️", 2: "🔒", 3: "🚨"}.get(int(req.level), "⚠️")
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{level_emoji} *PurpleLab HITL Approval Required*\n"
                        f"*Action:* `{req.action_type}`\n"
                        f"*Level:* L{int(req.level)} — {req.level.name}\n"
                        f"*Requested by:* {req.requested_by}"
                    ),
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Approve"},
                        "style": "primary",
                        "url": req.magic_link_url or "",
                        "action_id": f"approve_{req.id}",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "❌ Reject"},
                        "style": "danger",
                        "url": (req.magic_link_url or "").replace("/approve/", "/reject/"),
                        "action_id": f"reject_{req.id}",
                    },
                ],
            },
        ]

        channels = [nc.slack_channel] if nc.slack_channel else []
        channels += nc.slack_user_ids

        async with httpx.AsyncClient() as client:
            for channel in channels:
                try:
                    await client.post(
                        "https://slack.com/api/chat.postMessage",
                        headers={"Authorization": f"Bearer {slack_token}"},
                        json={"channel": channel, "blocks": blocks},
                        timeout=10.0,
                    )
                except Exception as exc:
                    logger.warning("Slack notification to %s failed: %s", channel, exc)

    async def _notify_webhook(self, req: HITLRequest, webhook_url: str) -> None:
        import httpx
        async with httpx.AsyncClient() as client:
            await client.post(
                webhook_url,
                json={
                    "event": "hitl_approval_required",
                    "request": req.to_dict(),
                },
                timeout=10.0,
            )

    async def _notify_pagerduty(self, req: HITLRequest, routing_key: str) -> None:
        import httpx
        async with httpx.AsyncClient() as client:
            await client.post(
                "https://events.pagerduty.com/v2/enqueue",
                json={
                    "routing_key": routing_key,
                    "event_action": "trigger",
                    "dedup_key": f"hitl_{req.id}",
                    "payload": {
                        "summary": f"PurpleLab HITL: {req.action_type} requires approval",
                        "severity": "warning",
                        "source": "purplelab",
                        "custom_details": {
                            "action_type": req.action_type,
                            "level": int(req.level),
                            "magic_link": req.magic_link_url,
                            "requested_by": req.requested_by,
                        },
                    },
                    "links": [{"href": req.magic_link_url or "", "text": "Approve Now"}],
                },
                timeout=10.0,
            )


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine: HITLEngine | None = None


def get_hitl_engine() -> HITLEngine:
    global _engine
    if _engine is None:
        _engine = HITLEngine()
    return _engine
