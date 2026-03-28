"""abuse.ch threat intelligence source.

TODO: Implement URLhaus, MalwareBazaar, and ThreatFox API integration.
"""
from __future__ import annotations

from typing import Any


class AbuseCHSource:
    """Connector for abuse.ch services.

    TODO: Implement URLhaus, MalwareBazaar, ThreatFox queries.
    """

    async def query_urlhaus(self, url: str) -> dict[str, Any]:
        raise NotImplementedError

    async def query_malwarebazaar(self, file_hash: str) -> dict[str, Any]:
        raise NotImplementedError

    async def query_threatfox(self, ioc: str) -> dict[str, Any]:
        raise NotImplementedError
