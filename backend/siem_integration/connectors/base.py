"""Abstract base connector for SIEM platforms (new-style API).

All concrete connectors used by ConnectionManager inherit from
BaseSIEMConnector and implement the three abstract methods.

The older AbstractConnector (base_connector.py) is kept for backward
compatibility with connector_factory.py.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any


class BaseSIEMConnector(ABC):
    """Abstract SIEM connector for use with ConnectionManager.

    All network calls MUST be wrapped in try/except — never raise to callers.
    """

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def __aenter__(self) -> "BaseSIEMConnector":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Release any HTTP client resources."""

    # ── Abstract interface ────────────────────────────────────────────────────

    @abstractmethod
    async def test(self) -> dict[str, Any]:
        """Verify connectivity.

        Returns:
            {
                "success": bool,
                "message": str,
                "latency_ms": int,
                **extra_info,
            }
        """

    @abstractmethod
    async def push_logs(self, logs: list[dict[str, Any]]) -> int:
        """Push log events to the SIEM.

        Args:
            logs: List of log event dicts.

        Returns:
            Number of events accepted by the SIEM.
        """

    @abstractmethod
    async def push_rule(
        self,
        rule_text: str,
        rule_name: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Deploy a detection rule to the SIEM.

        Args:
            rule_text: The raw rule / query string.
            rule_name: Human-readable rule name.
            metadata:  Optional extra metadata (severity, tags, etc.).

        Returns:
            {"success": bool, "message": str}
        """

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _timer() -> float:
        """Return current monotonic time in seconds."""
        return time.monotonic()

    @staticmethod
    def _elapsed_ms(t0: float) -> int:
        """Return elapsed milliseconds since *t0*."""
        return int((time.monotonic() - t0) * 1000)
