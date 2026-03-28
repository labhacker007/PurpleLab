"""Firewall log source generator.

TODO: Generate firewall allow/deny events with realistic traffic patterns.
"""
from __future__ import annotations

from typing import Any

from backend.log_sources.base_log_source import AbstractLogSource


class FirewallSource(AbstractLogSource):
    source_type = "firewall"
    description = "Network firewall allow/deny log events"

    def generate(self, malicious: bool = False, technique_id: str = "") -> dict[str, Any]:
        raise NotImplementedError

    def generate_batch(self, count: int = 10, malicious_ratio: float = 0.1, technique_id: str = "") -> list[dict[str, Any]]:
        raise NotImplementedError
