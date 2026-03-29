"""Event dispatcher — extracted from engine.py.

Responsible for sending generated events to target platforms via HTTP.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import httpx

log = logging.getLogger(__name__)

# ─── Circuit breaker ─────────────────────────────────────────────────────────

_FAILURE_THRESHOLD = 5       # consecutive failures before opening circuit
_RECOVERY_TIMEOUT  = 60.0    # seconds before trying half-open
_RETRY_DELAYS      = (1.0, 2.0, 4.0)  # exponential back-off delays

_circuit_breakers: dict[str, "CircuitBreakerState"] = {}


class CBState(str, Enum):
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half-open"


@dataclass
class CircuitBreakerState:
    failure_count:     int      = 0
    last_failure_time: float    = 0.0
    state:             CBState  = CBState.CLOSED


def _get_cb(url: str) -> CircuitBreakerState:
    if url not in _circuit_breakers:
        _circuit_breakers[url] = CircuitBreakerState()
    return _circuit_breakers[url]


def _record_success(url: str) -> None:
    cb = _get_cb(url)
    cb.failure_count = 0
    cb.state = CBState.CLOSED


def _record_failure(url: str) -> None:
    import time
    cb = _get_cb(url)
    cb.failure_count += 1
    cb.last_failure_time = time.monotonic()
    if cb.failure_count >= _FAILURE_THRESHOLD:
        cb.state = CBState.OPEN
        log.warning("circuit_breaker opened url=%s failures=%d", url, cb.failure_count)


def _check_cb(url: str) -> Optional[dict[str, Any]]:
    """Return an error dict if the circuit is open (or reopen after half-open failure),
    else return None and potentially flip to half-open."""
    import time
    cb = _get_cb(url)

    if cb.state == CBState.CLOSED:
        return None

    if cb.state == CBState.OPEN:
        elapsed = time.monotonic() - cb.last_failure_time
        if elapsed >= _RECOVERY_TIMEOUT:
            cb.state = CBState.HALF_OPEN
            log.info("circuit_breaker half-open url=%s", url)
            return None  # allow the test request through
        return {"error": "circuit_open", "target": url}

    # HALF_OPEN — allow one probe through (caller decides success/failure)
    return None


# ─── EventDispatcher ─────────────────────────────────────────────────────────

class EventDispatcher:
    """Sends generated events to configured target endpoints.

    Features:
      - Retry with exponential back-off on 5xx / connection errors (up to 3 retries).
      - Per-target circuit breaker: opens after 5 consecutive failures,
        half-opens after 60 s, closes on the first successful probe.
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self._http = httpx.AsyncClient(timeout=timeout)

    async def dispatch(
        self,
        event: dict[str, Any],
        target_url: str,
    ) -> tuple[int, bool]:
        """Send an event to the target URL with retry and circuit-breaker protection.

        Returns:
            Tuple of (status_code, success_bool). status_code is 0 on connection
            error; -1 when the circuit is open.
        """
        # ── Circuit-breaker check ────────────────────────────────────────────
        cb_error = _check_cb(target_url)
        if cb_error is not None:
            log.debug("circuit_open skipping dispatch url=%s", target_url)
            return -1, False

        # ── Attempt with retries ─────────────────────────────────────────────
        last_status = 0
        for attempt, delay in enumerate(
            [0.0] + list(_RETRY_DELAYS), start=0
        ):
            if delay > 0:
                log.debug("retry attempt=%d delay=%.1fs url=%s", attempt, delay, target_url)
                await asyncio.sleep(delay)

            try:
                resp = await self._http.post(target_url, json=event, timeout=5.0)
                last_status = resp.status_code

                if 200 <= resp.status_code < 300:
                    _record_success(target_url)
                    return resp.status_code, True

                if 400 <= resp.status_code < 500:
                    # Client error — don't retry, don't count as circuit failure
                    log.debug(
                        "dispatch_client_error url=%s status=%d",
                        target_url, resp.status_code,
                    )
                    return resp.status_code, False

                # 5xx — record failure, retry
                log.debug(
                    "dispatch_server_error url=%s status=%d attempt=%d",
                    target_url, resp.status_code, attempt,
                )
                _record_failure(target_url)

            except Exception as exc:
                last_status = 0
                log.debug(
                    "dispatch_failed url=%s attempt=%d error=%s",
                    target_url, attempt, exc,
                )
                _record_failure(target_url)

        return last_status, False

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
