"""AWS CloudTrail log source generator.

TODO: Generate CloudTrail API call events for AWS services.
"""
from __future__ import annotations

from typing import Any

from backend.log_sources.base_log_source import AbstractLogSource


class CloudTrailSource(AbstractLogSource):
    source_type = "cloud_trail"
    description = "AWS CloudTrail API activity log events"

    def generate(self, malicious: bool = False, technique_id: str = "") -> dict[str, Any]:
        raise NotImplementedError

    def generate_batch(self, count: int = 10, malicious_ratio: float = 0.1, technique_id: str = "") -> list[dict[str, Any]]:
        raise NotImplementedError
