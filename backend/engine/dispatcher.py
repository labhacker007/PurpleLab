"""Event dispatcher — extracted from engine.py.

Responsible for sending generated events to target platforms via HTTP.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

log = logging.getLogger(__name__)


class EventDispatcher:
    """Sends generated events to configured target endpoints.

    TODO: Add retry logic with exponential backoff.
    TODO: Add circuit breaker for failing targets.
    TODO: Support WebSocket push for real-time UI updates.
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self._http = httpx.AsyncClient(timeout=timeout)

    async def dispatch(
        self,
        event: dict[str, Any],
        target_url: str,
    ) -> tuple[int, bool]:
        """Send an event to the target URL.

        Returns:
            Tuple of (status_code, success_bool). status_code is 0 on connection error.
        """
        try:
            resp = await self._http.post(target_url, json=event, timeout=5.0)
            return resp.status_code, 200 <= resp.status_code < 300
        except Exception as e:
            log.debug("dispatch_failed url=%s error=%s", target_url, e)
            return 0, False

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._http.aclose()

    @staticmethod
    def resolve_target_url(
        product_config: Any,
        session_targets: list[Any],
    ) -> str:
        """Determine the target URL for event delivery.

        Checks product-level target_url first, then falls back to
        the first target node in the session.
        """
        if product_config.target_url:
            return product_config.target_url
        if session_targets:
            t = session_targets[0]
            token = product_config.webhook_token or "sim-token"
            return f"{t.base_url}{t.webhook_path.replace('{token}', token)}"
        return ""
