"""Sysmon log source generator.

TODO: Generate events for key Sysmon Event IDs:
- 1 (Process Create), 3 (Network Connection), 7 (Image Loaded)
- 8 (CreateRemoteThread), 10 (Process Access), 11 (File Create)
- 12/13/14 (Registry), 17/18 (Pipe), 22 (DNS Query)
"""
from __future__ import annotations

from typing import Any

from backend.log_sources.base_log_source import AbstractLogSource


class SysmonSource(AbstractLogSource):
    source_type = "sysmon"
    description = "Microsoft Sysmon telemetry events"

    def generate(self, malicious: bool = False, technique_id: str = "") -> dict[str, Any]:
        raise NotImplementedError

    def generate_batch(self, count: int = 10, malicious_ratio: float = 0.1, technique_id: str = "") -> list[dict[str, Any]]:
        raise NotImplementedError
