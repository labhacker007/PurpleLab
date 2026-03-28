"""DNS log source generator.

TODO: Generate DNS query/response events with benign and malicious domains.
"""
from __future__ import annotations

from typing import Any

from backend.log_sources.base_log_source import AbstractLogSource


class DNSSource(AbstractLogSource):
    source_type = "dns"
    description = "DNS query and response log events"

    def generate(self, malicious: bool = False, technique_id: str = "") -> dict[str, Any]:
        raise NotImplementedError

    def generate_batch(self, count: int = 10, malicious_ratio: float = 0.1, technique_id: str = "") -> list[dict[str, Any]]:
        raise NotImplementedError
