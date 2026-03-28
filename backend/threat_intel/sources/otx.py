"""AlienVault OTX threat intelligence source.

TODO: Implement OTX DirectConnect API integration.
TODO: Support pulse search and IOC lookups.
"""
from __future__ import annotations

from typing import Any


class OTXSource:
    """Connector for AlienVault OTX.

    TODO: Implement with OTX DirectConnect SDK or REST API.
    """

    async def search_pulses(self, query: str) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def get_indicators(self, pulse_id: str) -> list[dict[str, Any]]:
        raise NotImplementedError
