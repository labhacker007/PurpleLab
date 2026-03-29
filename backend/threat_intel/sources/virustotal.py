"""VirusTotal API v3 threat intelligence source.

Supports IP, domain, file hash, and IOC search lookups with:
- Rate limiting via token bucket (4 req/min free tier)
- Graceful 404 handling (not found = clean/unknown)
- Structured return dicts suitable for aggregation in ThreatResearcher
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"

# Free tier: 4 requests/minute = 1 request per 15 seconds
_FREE_TIER_RPM = 4
_TOKEN_INTERVAL = 60.0 / _FREE_TIER_RPM  # 15 seconds between requests


class VirusTotalSource:
    """Connector for VirusTotal API v3.

    Implements rate limiting via a token-bucket / last-request timestamp
    pattern using asyncio.Semaphore to serialise requests when needed.

    All lookup methods return ``None`` if the API key is not configured, and
    return a dict with ``found=False`` when VT returns 404 (unknown IOC).
    """

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key.strip()
        self._sem = asyncio.Semaphore(1)
        self._last_request: float = 0.0
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=_VT_BASE,
                headers={
                    "x-apikey": self.api_key,
                    "Accept": "application/json",
                },
                timeout=httpx.Timeout(30.0),
            )
        return self._client

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    async def _throttle(self) -> None:
        """Block until we can make another request within the rate limit."""
        async with self._sem:
            elapsed = time.monotonic() - self._last_request
            if elapsed < _TOKEN_INTERVAL:
                await asyncio.sleep(_TOKEN_INTERVAL - elapsed)
            self._last_request = time.monotonic()

    # ------------------------------------------------------------------
    # Core HTTP helper
    # ------------------------------------------------------------------

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
        """GET from VT API with rate limiting.

        Returns:
            Parsed JSON dict on success.
            ``{"found": False, "path": path}`` on 404.
            ``None`` on other HTTP/network errors (logged as warnings).
        """
        if not self.api_key:
            return None

        await self._throttle()
        client = self._get_client()

        try:
            resp = await client.get(path, params=params or {})
        except httpx.RequestError as exc:
            logger.warning("VT network error for %s: %s", path, exc)
            return None

        if resp.status_code == 404:
            logger.debug("VT 404 (not found): %s", path)
            return {"found": False, "path": path}

        if resp.status_code == 429:
            logger.warning("VT rate limit hit on %s; backing off 60s", path)
            await asyncio.sleep(60)
            return await self._get(path, params)  # single retry

        if not resp.is_success:
            logger.warning("VT HTTP %d for %s: %s", resp.status_code, path, resp.text[:200])
            return None

        try:
            return resp.json()
        except Exception as exc:
            logger.warning("VT JSON parse error for %s: %s", path, exc)
            return None

    async def _post(self, path: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """POST to VT API with rate limiting."""
        if not self.api_key:
            return None

        await self._throttle()
        client = self._get_client()

        try:
            resp = await client.post(path, json=data)
        except httpx.RequestError as exc:
            logger.warning("VT network error for POST %s: %s", path, exc)
            return None

        if resp.status_code == 429:
            logger.warning("VT rate limit hit on POST %s; backing off 60s", path)
            await asyncio.sleep(60)
            return await self._post(path, data)

        if not resp.is_success:
            logger.warning("VT HTTP %d for POST %s: %s", resp.status_code, path, resp.text[:200])
            return None

        try:
            return resp.json()
        except Exception as exc:
            logger.warning("VT JSON parse error for POST %s: %s", path, exc)
            return None

    # ------------------------------------------------------------------
    # IP lookup
    # ------------------------------------------------------------------

    async def lookup_ip(self, ip: str) -> dict[str, Any] | None:
        """Look up an IP address in VirusTotal.

        Returns structured dict or None if API key not set.
        Returns ``{"found": False}`` if IP is unknown to VT.
        """
        if not self.api_key:
            return None

        raw = await self._get(f"/ip_addresses/{ip}")
        if raw is None:
            return None
        if not raw.get("found", True):
            return {"source": "virustotal", "ioc": ip, "ioc_type": "ip", "found": False}

        attrs = raw.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        # Top 5 engines that detected it as malicious
        analysis_results = attrs.get("last_analysis_results", {})
        malicious_engines = [
            {"engine": k, "result": v.get("result"), "category": v.get("category")}
            for k, v in analysis_results.items()
            if v.get("category") in ("malicious", "suspicious")
        ][:5]

        return {
            "source": "virustotal",
            "ioc": ip,
            "ioc_type": "ip",
            "found": True,
            "reputation": attrs.get("reputation", 0),
            "country": attrs.get("country", ""),
            "as_owner": attrs.get("as_owner", ""),
            "asn": attrs.get("asn"),
            "malicious_votes": stats.get("malicious", 0),
            "suspicious_votes": stats.get("suspicious", 0),
            "harmless_votes": stats.get("harmless", 0),
            "undetected_votes": stats.get("undetected", 0),
            "detected_urls_count": len(attrs.get("last_https_certificate_date", [])),
            "top_detections": malicious_engines,
            "last_analysis_date": attrs.get("last_analysis_date"),
            "tags": attrs.get("tags", []),
            "regional_internet_registry": attrs.get("regional_internet_registry", ""),
            "network": attrs.get("network", ""),
            "threat_actors": _extract_threat_actors(attrs),
        }

    # ------------------------------------------------------------------
    # Domain lookup
    # ------------------------------------------------------------------

    async def lookup_domain(self, domain: str) -> dict[str, Any] | None:
        """Look up a domain in VirusTotal."""
        if not self.api_key:
            return None

        raw = await self._get(f"/domains/{domain}")
        if raw is None:
            return None
        if not raw.get("found", True):
            return {"source": "virustotal", "ioc": domain, "ioc_type": "domain", "found": False}

        attrs = raw.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        analysis_results = attrs.get("last_analysis_results", {})
        malicious_engines = [
            {"engine": k, "result": v.get("result"), "category": v.get("category")}
            for k, v in analysis_results.items()
            if v.get("category") in ("malicious", "suspicious")
        ][:5]

        # Last DNS records (compact)
        dns_records_raw = attrs.get("last_dns_records", [])
        dns_records = [
            {"type": r.get("type"), "value": r.get("value"), "ttl": r.get("ttl")}
            for r in dns_records_raw[:10]
        ]

        return {
            "source": "virustotal",
            "ioc": domain,
            "ioc_type": "domain",
            "found": True,
            "reputation": attrs.get("reputation", 0),
            "registrar": attrs.get("registrar", ""),
            "creation_date": attrs.get("creation_date"),
            "last_update_date": attrs.get("last_update_date"),
            "categories": attrs.get("categories", {}),
            "malicious_votes": stats.get("malicious", 0),
            "suspicious_votes": stats.get("suspicious", 0),
            "harmless_votes": stats.get("harmless", 0),
            "top_detections": malicious_engines,
            "last_dns_records": dns_records,
            "tld": attrs.get("tld", ""),
            "tags": attrs.get("tags", []),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "threat_actors": _extract_threat_actors(attrs),
        }

    # ------------------------------------------------------------------
    # File hash lookup
    # ------------------------------------------------------------------

    async def lookup_hash(self, file_hash: str) -> dict[str, Any] | None:
        """Look up a file hash (MD5/SHA1/SHA256) in VirusTotal."""
        if not self.api_key:
            return None

        raw = await self._get(f"/files/{file_hash}")
        if raw is None:
            return None
        if not raw.get("found", True):
            return {"source": "virustotal", "ioc": file_hash, "ioc_type": "hash", "found": False}

        attrs = raw.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        # Top 5 threat names from detections
        analysis_results = attrs.get("last_analysis_results", {})
        detections = [
            {"engine": k, "result": v.get("result"), "category": v.get("category")}
            for k, v in analysis_results.items()
            if v.get("category") in ("malicious", "suspicious") and v.get("result")
        ]
        threat_names = list({d["result"] for d in detections if d.get("result")})[:5]
        top_detections = detections[:5]

        # MITRE techniques from sigma_analysis_results or behavior summary
        mitre_techniques = _extract_mitre_from_file(attrs)

        return {
            "source": "virustotal",
            "ioc": file_hash,
            "ioc_type": "hash",
            "found": True,
            "meaningful_name": attrs.get("meaningful_name", ""),
            "file_type": attrs.get("type_description", attrs.get("type_tag", "")),
            "size": attrs.get("size"),
            "md5": attrs.get("md5", ""),
            "sha1": attrs.get("sha1", ""),
            "sha256": attrs.get("sha256", ""),
            "first_seen": attrs.get("first_submission_date"),
            "last_seen": attrs.get("last_submission_date"),
            "times_submitted": attrs.get("times_submitted", 0),
            "malicious_engine_count": stats.get("malicious", 0),
            "suspicious_engine_count": stats.get("suspicious", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "threat_names": threat_names,
            "top_detections": top_detections,
            "mitre_techniques": mitre_techniques,
            "tags": attrs.get("tags", []),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "magic": attrs.get("magic", ""),
        }

    # ------------------------------------------------------------------
    # IOC search (premium endpoint)
    # ------------------------------------------------------------------

    async def search_ioc(self, query: str, limit: int = 10) -> list[dict[str, Any]] | None:
        """Search VirusTotal intelligence (requires premium API key).

        Returns a list of matching IOC objects or None on error.
        Returns empty list if the account lacks premium access.
        """
        if not self.api_key:
            return None

        raw = await self._post("/intelligence/search", {"query": query, "limit": limit})
        if raw is None:
            return []

        results = []
        for item in raw.get("data", []):
            attrs = item.get("attributes", {})
            results.append({
                "source": "virustotal",
                "id": item.get("id", ""),
                "type": item.get("type", ""),
                "name": attrs.get("meaningful_name", attrs.get("name", "")),
                "reputation": attrs.get("reputation", 0),
                "malicious_votes": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                "tags": attrs.get("tags", []),
            })
        return results


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _extract_threat_actors(attrs: dict[str, Any]) -> list[str]:
    """Extract threat actor names from VT attributes if available."""
    actors: list[str] = []
    # VT crowdsourced context sometimes includes actor attribution
    for item in attrs.get("crowdsourced_context", []):
        if isinstance(item, dict):
            source = item.get("source", "")
            if source and source not in actors:
                actors.append(source)
    # Popular threat labels
    for label in attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "").split("/"):
        label = label.strip()
        if label and label not in actors:
            actors.append(label)
    return actors


def _extract_mitre_from_file(attrs: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract MITRE ATT&CK techniques from file analysis attributes."""
    techniques: list[dict[str, Any]] = []
    seen: set[str] = set()

    # sigma_analysis_results
    for sigma in attrs.get("sigma_analysis_results", []):
        for tag in sigma.get("tags", []):
            if tag.startswith("attack.t") or tag.startswith("attack.T"):
                tid = tag.split(".")[-1].upper()
                if tid.startswith("T") and tid not in seen:
                    seen.add(tid)
                    techniques.append({
                        "technique_id": tid,
                        "rule_title": sigma.get("rule_title", ""),
                        "source": "sigma",
                    })

    # crowdsourced_ids
    for cid in attrs.get("crowdsourced_ids_results", []):
        for alert in cid.get("alerts", []):
            for tag in alert.get("mitre_attack_tactics", []) + alert.get("mitre_attack_techniques", []):
                tid = tag.upper()
                if tid.startswith("T") and tid not in seen:
                    seen.add(tid)
                    techniques.append({
                        "technique_id": tid,
                        "rule_title": alert.get("alert_severity", ""),
                        "source": "crowdsourced_ids",
                    })

    return techniques
