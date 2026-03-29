"""AlienVault OTX DirectConnect API source.

Supports:
- Pulse subscriptions and search
- IOC indicator lookups (IPv4, domain, hostname, URL, file hashes, CVE)
- Malware sample analysis
- Threat actor / adversary profiling with MITRE TTP extraction
- Pagination for large result sets
"""
from __future__ import annotations

import logging
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_OTX_BASE = "https://otx.alienvault.com"

# Map OTX adversary / tag names to known MITRE group IDs (best-effort)
_ACTOR_TO_GROUP: dict[str, str] = {
    "apt28": "G0007", "fancy bear": "G0007",
    "apt29": "G0016", "cozy bear": "G0016",
    "lazarus": "G0032", "lazarus group": "G0032",
    "apt41": "G0096",
    "carbanak": "G0008",
    "fin7": "G0046",
    "turla": "G0010",
    "equation group": "G0020",
    "charming kitten": "G0058",
    "apt34": "G0049", "oilrig": "G0049",
    "sandworm": "G0034",
    "wizard spider": "G0102",
    "ta505": "G0092",
    "kimsuky": "G0094",
    "apt38": "G0082",
    "muddywater": "G0069",
}

# OTX indicator type to MITRE IOC type label
_OTX_TYPE_MAP = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "URI": "url",
    "FileHash-MD5": "hash",
    "FileHash-SHA1": "hash",
    "FileHash-SHA256": "hash",
    "CVE": "cve",
    "email": "email",
}


class OTXSource:
    """Connector for AlienVault OTX DirectConnect API.

    All methods return empty structures (not None) when the API key is
    missing, so callers can safely iterate results without None checks.
    """

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key.strip()
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=_OTX_BASE,
                headers={
                    "X-OTX-API-KEY": self.api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=httpx.Timeout(30.0),
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
        if not self.api_key:
            return None

        client = self._get_client()
        try:
            resp = await client.get(path, params=params or {})
        except httpx.RequestError as exc:
            logger.warning("OTX network error for %s: %s", path, exc)
            return None

        if resp.status_code == 403:
            logger.warning("OTX 403 Forbidden — check API key permissions for %s", path)
            return None
        if resp.status_code == 404:
            logger.debug("OTX 404 not found: %s", path)
            return {"found": False}
        if not resp.is_success:
            logger.warning("OTX HTTP %d for %s: %s", resp.status_code, path, resp.text[:200])
            return None

        try:
            return resp.json()
        except Exception as exc:
            logger.warning("OTX JSON parse error for %s: %s", path, exc)
            return None

    # ------------------------------------------------------------------
    # Pulse subscriptions
    # ------------------------------------------------------------------

    async def get_pulse_subscriptions(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return recent pulses from subscribed feeds.

        Each pulse includes title, description, tags, indicator counts, and TLP.
        """
        if not self.api_key:
            return []

        pulses: list[dict[str, Any]] = []
        page = 1

        while len(pulses) < limit:
            raw = await self._get("/api/v1/pulses/subscribed", params={"page": page, "limit": min(limit, 20)})
            if not raw:
                break

            for p in raw.get("results", []):
                pulses.append(_parse_pulse(p))
                if len(pulses) >= limit:
                    break

            if not raw.get("next"):
                break
            page += 1

        return pulses[:limit]

    # ------------------------------------------------------------------
    # Indicator lookups
    # ------------------------------------------------------------------

    async def get_indicator_details(
        self, indicator_type: str, indicator: str
    ) -> dict[str, Any]:
        """Look up an IOC indicator.

        indicator_type: one of IPv4, domain, hostname, URL, FileHash-MD5,
                        FileHash-SHA256, FileHash-SHA1, CVE
        Returns structured dict with pulse count, reputation, geo, tags.
        """
        if not self.api_key:
            return {"found": False, "ioc": indicator, "source": "otx"}

        raw = await self._get(f"/api/v1/indicators/{indicator_type}/{indicator}/general")
        if not raw or not raw.get("found", True):
            return {"source": "otx", "ioc": indicator, "ioc_type": _OTX_TYPE_MAP.get(indicator_type, indicator_type), "found": False}

        pulse_info = raw.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])

        # Collect TTP tags from associated pulses
        mitre_techniques = _extract_mitre_from_pulses(pulses)
        threat_actors = _extract_actors_from_pulses(pulses)

        result: dict[str, Any] = {
            "source": "otx",
            "ioc": indicator,
            "ioc_type": _OTX_TYPE_MAP.get(indicator_type, indicator_type),
            "found": True,
            "pulse_count": pulse_info.get("count", 0),
            "reputation": raw.get("reputation", 0),
            "tags": list({t for p in pulses for t in p.get("tags", [])}),
            "mitre_techniques": mitre_techniques,
            "threat_actors": threat_actors,
            "first_seen": raw.get("first_seen"),
            "last_seen": raw.get("last_seen"),
            "related_pulses": [
                {
                    "id": p.get("id", ""),
                    "name": p.get("name", ""),
                    "tlp": p.get("tlp", "white"),
                    "created": p.get("created", ""),
                    "author_name": p.get("author_name", ""),
                }
                for p in pulses[:5]
            ],
        }

        # Type-specific enrichment
        if indicator_type == "IPv4":
            result["country_code"] = raw.get("country_code", "")
            result["asn"] = raw.get("asn", "")
            result["city"] = raw.get("city", "")
        elif indicator_type in ("domain", "hostname"):
            result["alexa"] = raw.get("alexa", "")
            result["whois"] = raw.get("whois", "")

        return result

    # ------------------------------------------------------------------
    # Malware samples
    # ------------------------------------------------------------------

    async def get_malware_samples(self, hash_: str) -> dict[str, Any]:
        """Return analysis report for a file hash."""
        if not self.api_key:
            return {"found": False, "ioc": hash_, "source": "otx"}

        raw = await self._get(f"/api/v1/indicators/file/{hash_}/analysis")
        if not raw or not raw.get("found", True):
            return {"source": "otx", "ioc": hash_, "ioc_type": "hash", "found": False}

        analysis = raw.get("analysis", {})
        info = analysis.get("info", {})

        return {
            "source": "otx",
            "ioc": hash_,
            "ioc_type": "hash",
            "found": True,
            "file_type": info.get("results", {}).get("file_type", ""),
            "file_size": info.get("results", {}).get("file_size", ""),
            "malware_family": _extract_malware_family(analysis),
            "mitre_techniques": _extract_mitre_from_analysis(analysis),
            "network_indicators": _extract_network_iocs(analysis),
            "registry_keys": _extract_registry_keys(analysis),
            "tags": raw.get("tags", []),
        }

    # ------------------------------------------------------------------
    # Pulse search
    # ------------------------------------------------------------------

    async def search_pulses(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """Search OTX pulses by keyword.

        Returns a list of simplified pulse dicts with indicators preview.
        """
        if not self.api_key:
            return []

        raw = await self._get("/api/v1/search/pulses", params={"q": query, "limit": limit, "page": 1})
        if not raw:
            return []

        return [_parse_pulse(p) for p in raw.get("results", [])[:limit]]

    # ------------------------------------------------------------------
    # Actor profiling
    # ------------------------------------------------------------------

    async def get_actor_info(self, actor_name: str) -> dict[str, Any]:
        """Research a threat actor via OTX pulses.

        Searches pulses tagged with the actor name, then extracts:
        - Associated IOCs
        - MITRE technique IDs
        - TLP / confidence
        """
        if not self.api_key:
            return {"actor": actor_name, "source": "otx", "found": False}

        pulses = await self.search_pulses(actor_name, limit=20)
        if not pulses:
            return {"actor": actor_name, "source": "otx", "found": False, "pulses": []}

        # Aggregate TTPs across all matching pulses
        mitre_techniques = _extract_mitre_from_pulses(
            [{"attack_ids": p.get("attack_ids", []), "tags": p.get("tags", [])} for p in pulses]
        )
        ioc_types: dict[str, int] = {}
        for p in pulses:
            for ioc_type, count in p.get("indicator_type_counts", {}).items():
                ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + count

        # Map actor to MITRE group ID if known
        mitre_group_id = _ACTOR_TO_GROUP.get(actor_name.lower(), "")

        return {
            "actor": actor_name,
            "source": "otx",
            "found": True,
            "mitre_group_id": mitre_group_id,
            "pulse_count": len(pulses),
            "mitre_techniques": mitre_techniques,
            "ioc_type_distribution": ioc_types,
            "representative_pulses": pulses[:5],
            "tags": list({t for p in pulses for t in p.get("tags", [])}),
        }

    # ------------------------------------------------------------------
    # Pagination helper
    # ------------------------------------------------------------------

    async def get_paginated(self, path: str, limit: int = 50) -> list[dict[str, Any]]:
        """Fetch all pages from a paginated OTX endpoint."""
        if not self.api_key:
            return []

        results: list[dict[str, Any]] = []
        page = 1

        while len(results) < limit:
            raw = await self._get(path, params={"page": page, "limit": min(20, limit - len(results))})
            if not raw:
                break
            batch = raw.get("results", [])
            results.extend(batch)
            if not raw.get("next") or not batch:
                break
            page += 1

        return results[:limit]


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _parse_pulse(p: dict[str, Any]) -> dict[str, Any]:
    """Normalise a raw OTX pulse object."""
    indicator_counts: dict[str, int] = {}
    for ind in p.get("indicators", []):
        t = ind.get("type", "unknown")
        indicator_counts[t] = indicator_counts.get(t, 0) + 1

    return {
        "id": p.get("id", ""),
        "name": p.get("name", ""),
        "description": (p.get("description") or "")[:500],
        "tlp": p.get("tlp", "white"),
        "tags": p.get("tags", []),
        "attack_ids": [a.get("id", "") for a in p.get("attack_ids", [])],
        "created": p.get("created", ""),
        "modified": p.get("modified", ""),
        "author_name": p.get("author_name", ""),
        "indicator_count": p.get("indicator_count", 0),
        "indicator_type_counts": indicator_counts,
        "indicators_preview": [
            {"type": i.get("type"), "indicator": i.get("indicator")}
            for i in p.get("indicators", [])[:10]
        ],
    }


def _extract_mitre_from_pulses(pulses: list[dict[str, Any]]) -> list[str]:
    """Collect unique MITRE technique IDs from pulse attack_ids and tags."""
    techniques: set[str] = set()
    _tid_re = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

    for p in pulses:
        for attack_id in p.get("attack_ids", []):
            tid = str(attack_id).upper().strip()
            if _tid_re.match(tid):
                techniques.add(tid)
        for tag in p.get("tags", []):
            matches = _tid_re.findall(tag)
            for m in matches:
                techniques.add(m.upper())

    return sorted(techniques)


def _extract_actors_from_pulses(pulses: list[dict[str, Any]]) -> list[str]:
    """Extract potential threat actor names from pulse tags."""
    actors: list[str] = []
    seen: set[str] = set()
    apt_re = re.compile(r"\bapt[- ]?\d+\b", re.IGNORECASE)

    for p in pulses:
        for tag in p.get("tags", []):
            if apt_re.search(tag):
                norm = tag.lower().strip()
                if norm not in seen:
                    seen.add(norm)
                    actors.append(tag)
    return actors


def _extract_malware_family(analysis: dict[str, Any]) -> str:
    """Try to extract malware family name from OTX analysis block."""
    try:
        return analysis.get("plugins", {}).get("cuckoo", {}).get("summary", {}).get("category", "")
    except (AttributeError, TypeError):
        return ""


def _extract_mitre_from_analysis(analysis: dict[str, Any]) -> list[str]:
    """Extract MITRE technique IDs from OTX file analysis results."""
    techniques: set[str] = set()
    _tid_re = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

    def _scan(obj: Any) -> None:
        if isinstance(obj, str):
            for m in _tid_re.findall(obj):
                techniques.add(m.upper())
        elif isinstance(obj, dict):
            for v in obj.values():
                _scan(v)
        elif isinstance(obj, list):
            for item in obj:
                _scan(item)

    _scan(analysis)
    return sorted(techniques)


def _extract_network_iocs(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract network IOCs from OTX analysis."""
    try:
        network = analysis.get("plugins", {}).get("cuckoo", {}).get("network", {})
        iocs: list[dict[str, Any]] = []
        for host in (network.get("hosts") or [])[:10]:
            if isinstance(host, str):
                iocs.append({"type": "ip", "value": host})
            elif isinstance(host, dict):
                iocs.append({"type": "ip", "value": host.get("ip", ""), "hostname": host.get("hostname", "")})
        for dns in (network.get("dns") or [])[:10]:
            if isinstance(dns, dict):
                iocs.append({"type": "domain", "value": dns.get("hostname", ""), "answers": dns.get("answers", [])})
        return iocs
    except (AttributeError, TypeError):
        return []


def _extract_registry_keys(analysis: dict[str, Any]) -> list[str]:
    """Extract registry key artifacts from OTX analysis."""
    try:
        behavior = analysis.get("plugins", {}).get("cuckoo", {}).get("behavior", {})
        keys: set[str] = set()
        for proc in (behavior.get("processes") or []):
            for call in (proc.get("calls") or []):
                if "RegSetValue" in str(call.get("api", "")):
                    for arg in (call.get("arguments") or []):
                        if "key" in str(arg.get("name", "")).lower():
                            keys.add(str(arg.get("value", "")))
        return list(keys)[:20]
    except (AttributeError, TypeError):
        return []
