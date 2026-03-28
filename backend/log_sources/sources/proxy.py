"""Web proxy log source generator.

TODO: Generate HTTP/HTTPS proxy events with realistic web traffic.
"""
from __future__ import annotations

from typing import Any

from backend.log_sources.base_log_source import AbstractLogSource


class ProxySource(AbstractLogSource):
    source_type = "proxy"
    description = "Web proxy HTTP/HTTPS log events"

    def generate(self, malicious: bool = False, technique_id: str = "") -> dict[str, Any]:
        raise NotImplementedError

    def generate_batch(self, count: int = 10, malicious_ratio: float = 0.1, technique_id: str = "") -> list[dict[str, Any]]:
        raise NotImplementedError
