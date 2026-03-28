"""Microsoft Sentinel SIEM connector.

TODO: Implement Azure Sentinel API integration:
- Authentication via Azure AD (client credentials)
- Pull analytics rules
- Push events via Data Collector API / Log Analytics
- Query KQL via API
"""
from __future__ import annotations

from typing import Any

from backend.siem_integration.connectors.base_connector import AbstractConnector


class SentinelConnector(AbstractConnector):
    platform = "sentinel"

    async def connect(self, base_url: str, credentials: dict[str, str]) -> bool:
        raise NotImplementedError

    async def pull_rules(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def push_logs(self, events: list[dict[str, Any]], index: str = "") -> bool:
        raise NotImplementedError
