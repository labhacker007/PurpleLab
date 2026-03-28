"""Elastic SIEM connector.

TODO: Implement Elasticsearch/Kibana API integration:
- Authentication via API key or basic auth
- Pull detection rules from Kibana Security
- Push events to Elasticsearch indices
- Query via ES|QL or DSL
"""
from __future__ import annotations

from typing import Any

from backend.siem_integration.connectors.base_connector import AbstractConnector


class ElasticConnector(AbstractConnector):
    platform = "elastic"

    async def connect(self, base_url: str, credentials: dict[str, str]) -> bool:
        raise NotImplementedError

    async def pull_rules(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def push_logs(self, events: list[dict[str, Any]], index: str = "") -> bool:
        raise NotImplementedError
