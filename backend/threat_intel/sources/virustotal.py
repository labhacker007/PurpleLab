"""VirusTotal threat intelligence source.

TODO: Implement VT API v3 integration for IOC lookups.
TODO: Support IP, domain, hash, and URL lookups.
TODO: Rate limit API calls per VT plan limits.
"""
from __future__ import annotations

from typing import Any


class VirusTotalSource:
    """Connector for VirusTotal API.

    TODO: Implement with httpx client and API key from settings.
    """

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        raise NotImplementedError

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        raise NotImplementedError

    async def lookup_hash(self, file_hash: str) -> dict[str, Any]:
        raise NotImplementedError
