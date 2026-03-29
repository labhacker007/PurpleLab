"""abuse.ch threat intelligence sources — URLhaus, MalwareBazaar, ThreatFox.

All three APIs are free and require no API key.  Rate limiting is light
(URLhaus asks for at most 1 request/second; MalwareBazaar and ThreatFox
have no stated limits but are courteous-use APIs).

All methods return structured dicts with consistent fields:
    source, confidence, tags, first_seen, last_seen, …
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1"
_BAZAAR_BASE = "https://mb-api.abuse.ch/api/v1"
_THREATFOX_BASE = "https://threatfox-api.abuse.ch/api/v1"

# Shared timeout for all abuse.ch calls
_TIMEOUT = httpx.Timeout(20.0)


class AbuseEHSource:
    """Connector for abuse.ch threat intelligence services.

    Covers:
    - URLhaus  — malicious URL / host lookups and recent URL feeds
    - MalwareBazaar — file hash lookups, recent samples, tag search
    - ThreatFox — IOC search, recent IOC feed, malware info

    No API key is required.  A single shared httpx.AsyncClient is reused
    across all requests for connection pooling.
    """

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=_TIMEOUT,
                follow_redirects=True,
            )
        return self._client

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Generic POST helpers
    # ------------------------------------------------------------------

    async def _post_form(self, url: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """POST form-encoded data and return parsed JSON."""
        client = self._get_client()
        try:
            resp = await client.post(url, data=data)
        except httpx.RequestError as exc:
            logger.warning("abuse.ch network error for %s: %s", url, exc)
            return None

        if not resp.is_success:
            logger.warning("abuse.ch HTTP %d for %s", resp.status_code, url)
            return None

        try:
            return resp.json()
        except Exception as exc:
            logger.warning("abuse.ch JSON parse error for %s: %s", url, exc)
            return None

    async def _post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        """POST JSON body (ThreatFox uses JSON)."""
        client = self._get_client()
        try:
            resp = await client.post(
                url,
                content=_json_bytes(payload),
                headers={"Content-Type": "application/json"},
            )
        except httpx.RequestError as exc:
            logger.warning("abuse.ch network error for %s: %s", url, exc)
            return None

        if not resp.is_success:
            logger.warning("abuse.ch HTTP %d for %s", resp.status_code, url)
            return None

        try:
            return resp.json()
        except Exception as exc:
            logger.warning("abuse.ch JSON parse error for %s: %s", url, exc)
            return None

    async def _get(self, url: str) -> dict[str, Any] | None:
        client = self._get_client()
        try:
            resp = await client.get(url, headers={"Accept": "application/json"})
        except httpx.RequestError as exc:
            logger.warning("abuse.ch GET error for %s: %s", url, exc)
            return None

        if not resp.is_success:
            logger.warning("abuse.ch HTTP %d for GET %s", resp.status_code, url)
            return None

        try:
            return resp.json()
        except Exception as exc:
            logger.warning("abuse.ch JSON parse error for GET %s: %s", url, exc)
            return None

    # ==================================================================
    # URLhaus
    # ==================================================================

    async def lookup_url(self, url: str) -> dict[str, Any]:
        """Look up a URL in URLhaus.

        POSTs form data ``url=<url>`` to the URLhaus query endpoint.
        Returns a structured dict indicating whether the URL is known-malicious.
        """
        raw = await self._post_form(f"{_URLHAUS_BASE}/url/", {"url": url})
        if raw is None:
            return _empty_result("urlhaus", url, "url")

        query_status = raw.get("query_status", "")
        if query_status == "no_results":
            return {
                "source": "urlhaus",
                "ioc": url,
                "ioc_type": "url",
                "found": False,
                "query_status": query_status,
                "confidence": 0,
                "tags": [],
                "first_seen": None,
                "last_seen": None,
            }

        urls_data = raw.get("urls", [raw]) if "urls" in raw else [raw]
        first = urls_data[0] if urls_data else raw

        return {
            "source": "urlhaus",
            "ioc": url,
            "ioc_type": "url",
            "found": True,
            "query_status": query_status,
            "url_status": first.get("url_status", ""),
            "threat": first.get("threat", ""),
            "tags": first.get("tags") or [],
            "confidence": _urlhaus_confidence(first),
            "first_seen": first.get("date_added"),
            "last_seen": first.get("last_online"),
            "reporter": first.get("reporter", ""),
            "urlhaus_reference": first.get("urlhaus_reference", ""),
            "payloads": [
                {
                    "file_type": p.get("file_type", ""),
                    "md5": p.get("response_md5", ""),
                    "sha256": p.get("response_sha256", ""),
                    "signature": p.get("signature", ""),
                    "size_bytes": p.get("response_size", 0),
                }
                for p in (first.get("payloads") or [])[:5]
            ],
        }

    async def lookup_host(self, host: str) -> dict[str, Any]:
        """Look up an IP or hostname in URLhaus.

        POSTs form data ``host=<host>``.
        """
        raw = await self._post_form(f"{_URLHAUS_BASE}/host/", {"host": host})
        if raw is None:
            return _empty_result("urlhaus", host, "host")

        query_status = raw.get("query_status", "")
        if query_status == "no_results":
            return {
                "source": "urlhaus",
                "ioc": host,
                "ioc_type": "host",
                "found": False,
                "query_status": query_status,
                "confidence": 0,
                "tags": [],
                "first_seen": None,
                "last_seen": None,
            }

        urls = raw.get("urls", [])
        all_tags = list({t for u in urls for t in (u.get("tags") or [])})
        threats = list({u.get("threat", "") for u in urls if u.get("threat")})

        return {
            "source": "urlhaus",
            "ioc": host,
            "ioc_type": "host",
            "found": True,
            "query_status": query_status,
            "url_count": len(urls),
            "urls_online": sum(1 for u in urls if u.get("url_status") == "online"),
            "threats": threats,
            "tags": all_tags,
            "confidence": _urlhaus_confidence(raw),
            "first_seen": min((u.get("date_added", "") for u in urls if u.get("date_added")), default=None),
            "last_seen": max((u.get("last_online", "") for u in urls if u.get("last_online")), default=None),
            "urlhaus_reference": raw.get("urlhaus_reference", ""),
            "blacklists": raw.get("blacklists", {}),
            "recent_urls": [
                {
                    "url": u.get("url", ""),
                    "status": u.get("url_status", ""),
                    "threat": u.get("threat", ""),
                    "date_added": u.get("date_added", ""),
                }
                for u in urls[:10]
            ],
        }

    async def get_recent_urls(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return the most recently added malicious URLs from URLhaus."""
        n = max(1, min(limit, 1000))
        raw = await self._get(f"{_URLHAUS_BASE}/urls/recent/limit/{n}/")
        if not raw:
            return []

        return [
            {
                "source": "urlhaus",
                "ioc": u.get("url", ""),
                "ioc_type": "url",
                "url_status": u.get("url_status", ""),
                "threat": u.get("threat", ""),
                "tags": u.get("tags") or [],
                "confidence": _urlhaus_confidence(u),
                "first_seen": u.get("date_added"),
                "last_seen": u.get("last_online"),
                "urlhaus_reference": u.get("urlhaus_reference", ""),
            }
            for u in raw.get("urls", [])[:limit]
        ]

    # ==================================================================
    # MalwareBazaar
    # ==================================================================

    async def lookup_hash(self, hash_: str) -> dict[str, Any]:
        """Look up a file hash in MalwareBazaar.

        Supports MD5, SHA1, and SHA256.
        """
        raw = await self._post_form(
            _BAZAAR_BASE,
            {"query": "get_info", "hash": hash_},
        )
        if raw is None:
            return _empty_result("malwarebazaar", hash_, "hash")

        if raw.get("query_status") != "ok" or not raw.get("data"):
            return {
                "source": "malwarebazaar",
                "ioc": hash_,
                "ioc_type": "hash",
                "found": False,
                "query_status": raw.get("query_status", "unknown"),
                "confidence": 0,
                "tags": [],
                "first_seen": None,
                "last_seen": None,
            }

        sample = raw["data"][0]

        return {
            "source": "malwarebazaar",
            "ioc": hash_,
            "ioc_type": "hash",
            "found": True,
            "md5": sample.get("md5_hash", ""),
            "sha1": sample.get("sha1_hash", ""),
            "sha256": sample.get("sha256_hash", ""),
            "file_name": sample.get("file_name", ""),
            "file_type": sample.get("file_type", ""),
            "file_size": sample.get("file_size"),
            "mime_type": sample.get("mime_type", ""),
            "signature": sample.get("signature", ""),
            "tags": sample.get("tags") or [],
            "confidence": 90,  # MalwareBazaar is analyst-vetted
            "first_seen": sample.get("first_seen"),
            "last_seen": sample.get("last_seen"),
            "reporter": sample.get("reporter", ""),
            "origin_country": sample.get("origin_country", ""),
            "intelligence": sample.get("intelligence", {}),
            "delivery_method": sample.get("delivery_method", ""),
            "vendor_intel": sample.get("vendor_intel", {}),
        }

    async def get_recent_samples(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return recently submitted malware samples from MalwareBazaar."""
        raw = await self._post_form(_BAZAAR_BASE, {"query": "get_recent", "selector": "time"})
        if not raw or raw.get("query_status") != "ok":
            return []

        return [
            {
                "source": "malwarebazaar",
                "ioc": s.get("sha256_hash", ""),
                "ioc_type": "hash",
                "file_name": s.get("file_name", ""),
                "file_type": s.get("file_type", ""),
                "signature": s.get("signature", ""),
                "tags": s.get("tags") or [],
                "confidence": 90,
                "first_seen": s.get("first_seen"),
                "last_seen": s.get("last_seen"),
                "reporter": s.get("reporter", ""),
            }
            for s in (raw.get("data") or [])[:limit]
        ]

    async def search_by_tag(self, tag: str) -> list[dict[str, Any]]:
        """Search MalwareBazaar for samples matching a tag (e.g. 'emotet', 'ransomware')."""
        raw = await self._post_form(_BAZAAR_BASE, {"query": "get_taginfo", "tag": tag, "limit": 50})
        if not raw or raw.get("query_status") != "ok":
            return []

        return [
            {
                "source": "malwarebazaar",
                "ioc": s.get("sha256_hash", ""),
                "ioc_type": "hash",
                "file_name": s.get("file_name", ""),
                "file_type": s.get("file_type", ""),
                "signature": s.get("signature", ""),
                "tags": s.get("tags") or [],
                "confidence": 90,
                "first_seen": s.get("first_seen"),
                "last_seen": s.get("last_seen"),
            }
            for s in (raw.get("data") or [])
        ]

    # ==================================================================
    # ThreatFox
    # ==================================================================

    async def search_ioc(self, ioc: str) -> dict[str, Any]:
        """Search ThreatFox for a specific IOC (IP, domain, URL, hash)."""
        raw = await self._post_json(_THREATFOX_BASE, {"query": "search_ioc", "search_term": ioc})
        if raw is None:
            return _empty_result("threatfox", ioc, "ioc")

        if raw.get("query_status") == "no_result":
            return {
                "source": "threatfox",
                "ioc": ioc,
                "ioc_type": "ioc",
                "found": False,
                "confidence": 0,
                "tags": [],
                "first_seen": None,
                "last_seen": None,
            }

        data = raw.get("data", [])
        if not data:
            return _empty_result("threatfox", ioc, "ioc")

        first = data[0]
        malware = first.get("malware", "")
        malware_printable = first.get("malware_printable", malware)
        confidence = int(first.get("confidence_level", 0))

        return {
            "source": "threatfox",
            "ioc": ioc,
            "ioc_type": first.get("ioc_type", "ioc"),
            "found": True,
            "threat_type": first.get("threat_type", ""),
            "malware": malware,
            "malware_printable": malware_printable,
            "malware_malpedia": first.get("malware_malpedia", ""),
            "confidence": confidence,
            "tags": first.get("tags") or [],
            "reporter": first.get("reporter", ""),
            "first_seen": first.get("first_seen"),
            "last_seen": first.get("last_seen"),
            "threatfox_reference": f"https://threatfox.abuse.ch/ioc/{first.get('id', '')}",
            "all_results": [
                {
                    "ioc_id": r.get("id"),
                    "ioc": r.get("ioc"),
                    "ioc_type": r.get("ioc_type"),
                    "threat_type": r.get("threat_type"),
                    "malware": r.get("malware_printable", r.get("malware", "")),
                    "confidence": int(r.get("confidence_level", 0)),
                    "first_seen": r.get("first_seen"),
                }
                for r in data[:10]
            ],
        }

    async def get_recent_iocs(self, days: int = 7) -> list[dict[str, Any]]:
        """Return IOCs added to ThreatFox in the last N days (max 90)."""
        days = max(1, min(days, 90))
        raw = await self._post_json(_THREATFOX_BASE, {"query": "get_iocs", "days": days})
        if not raw or raw.get("query_status") != "ok":
            return []

        return [
            {
                "source": "threatfox",
                "ioc": r.get("ioc", ""),
                "ioc_type": r.get("ioc_type", ""),
                "found": True,
                "threat_type": r.get("threat_type", ""),
                "malware": r.get("malware_printable", r.get("malware", "")),
                "confidence": int(r.get("confidence_level", 0)),
                "tags": r.get("tags") or [],
                "reporter": r.get("reporter", ""),
                "first_seen": r.get("first_seen"),
                "last_seen": r.get("last_seen"),
            }
            for r in (raw.get("data") or [])
        ]

    async def get_malware_info(self, malware_id: str) -> dict[str, Any]:
        """Return ThreatFox intel for a specific malware family ID.

        malware_id examples: 'Emotet', 'CobaltStrike', 'RedLineStealer'
        """
        raw = await self._post_json(_THREATFOX_BASE, {"query": "malware_info", "malware": malware_id})
        if not raw or raw.get("query_status") != "ok":
            return {
                "source": "threatfox",
                "malware_id": malware_id,
                "found": False,
            }

        data = raw.get("data", {})
        if isinstance(data, list):
            # Some endpoints return a list
            data = data[0] if data else {}

        return {
            "source": "threatfox",
            "malware_id": malware_id,
            "found": bool(data),
            "malware_printable": data.get("malware_printable", ""),
            "malware_alias": data.get("malware_alias", ""),
            "malware_malpedia": data.get("malware_malpedia", ""),
            "first_seen": data.get("first_seen"),
            "last_seen": data.get("last_seen"),
            "ioc_count": data.get("ioc_count", 0),
            "iocs_sample": [
                {
                    "ioc": r.get("ioc"),
                    "ioc_type": r.get("ioc_type"),
                    "confidence": int(r.get("confidence_level", 0)),
                    "first_seen": r.get("first_seen"),
                }
                for r in (data.get("iocs") or [])[:10]
            ],
        }


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

def _empty_result(source: str, ioc: str, ioc_type: str) -> dict[str, Any]:
    return {
        "source": source,
        "ioc": ioc,
        "ioc_type": ioc_type,
        "found": False,
        "confidence": 0,
        "tags": [],
        "first_seen": None,
        "last_seen": None,
        "error": "request_failed",
    }


def _urlhaus_confidence(data: dict[str, Any]) -> int:
    """Map URLhaus URL status to a rough confidence score."""
    status = data.get("url_status", "").lower()
    if status == "online":
        return 95
    if status == "offline":
        return 70  # was malicious, possibly expired
    return 50


def _json_bytes(obj: Any) -> bytes:
    """Serialise obj to UTF-8 JSON bytes."""
    import json
    return json.dumps(obj).encode("utf-8")
