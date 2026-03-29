"""Splunk connector — HEC ingestion + REST API for rule sync.

Supports:
- HTTP Event Collector (HEC) for high-throughput log ingest
- REST API for saved search management, SPL queries, index stats
- Retry logic with exponential backoff on 429/503
- Both token (HEC) and username/password (REST) auth
- Async context manager pattern
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from backend.siem_integration.connectors.base_connector import AbstractConnector

logger = logging.getLogger(__name__)

_RETRY_STATUSES = {429, 503}
_MAX_RETRIES = 3
_HEC_BATCH_SIZE = 100


@dataclass
class SplunkConfig:
    """Configuration for a Splunk instance.

    Supports dual-auth: HEC token for ingest, username/password for REST API.
    """

    hec_url: str           # e.g. "https://splunk:8088"
    hec_token: str         # HEC token (starts with "Splunk ")
    rest_url: str          # e.g. "https://splunk:8089"
    username: str
    password: str
    index: str = "main"
    sourcetype: str = "purplelab"
    verify_ssl: bool = True
    timeout: float = 30.0
    extra_fields: dict[str, Any] = field(default_factory=dict)


class SplunkConnector(AbstractConnector):
    """Production Splunk connector for HEC ingest and REST API operations.

    Usage as async context manager::

        config = SplunkConfig(hec_url=..., hec_token=..., rest_url=...,
                              username=..., password=...)
        async with SplunkConnector(config) as conn:
            await conn.send_events(events)
            results = await conn.search("index=main | head 10")
    """

    platform = "splunk"

    def __init__(self, config: SplunkConfig) -> None:
        self._config = config
        self._hec_client: httpx.AsyncClient | None = None
        self._rest_client: httpx.AsyncClient | None = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def __aenter__(self) -> "SplunkConnector":
        await self._init_clients()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.disconnect()

    async def _init_clients(self) -> None:
        cfg = self._config
        self._hec_client = httpx.AsyncClient(
            base_url=cfg.hec_url,
            headers={"Authorization": f"Splunk {cfg.hec_token}"},
            verify=cfg.verify_ssl,
            timeout=cfg.timeout,
        )
        self._rest_client = httpx.AsyncClient(
            base_url=cfg.rest_url,
            auth=(cfg.username, cfg.password),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify=cfg.verify_ssl,
            timeout=cfg.timeout,
        )

    async def disconnect(self) -> None:
        """Close underlying HTTP clients."""
        if self._hec_client:
            await self._hec_client.aclose()
            self._hec_client = None
        if self._rest_client:
            await self._rest_client.aclose()
            self._rest_client = None

    # ── AbstractConnector compat ───────────────────────────────────────────────

    async def connect(self, base_url: str, credentials: dict[str, str]) -> bool:
        """Initialise clients from generic credentials dict and verify connectivity."""
        cfg = self._config
        # Allow callers to inject credentials at connect time
        if "hec_token" in credentials:
            object.__setattr__(cfg, "hec_token", credentials["hec_token"])
        if "username" in credentials:
            object.__setattr__(cfg, "username", credentials["username"])
        if "password" in credentials:
            object.__setattr__(cfg, "password", credentials["password"])
        await self._init_clients()
        info = await self.test_connection()
        return info.get("healthy", False)

    async def pull_rules(self) -> list[dict[str, Any]]:
        """Return all saved searches as detection rules."""
        return await self.get_saved_searches()

    async def push_logs(self, events: list[dict[str, Any]], index: str = "") -> bool:
        """Push log events via HEC."""
        target_index = index or self._config.index
        sent = await self.send_events(events, index=target_index)
        return sent == len(events)

    async def health_check(self) -> bool:
        info = await self.test_connection()
        return info.get("healthy", False)

    # ── HEC Ingest ────────────────────────────────────────────────────────────

    async def send_events(
        self,
        events: list[dict[str, Any]],
        index: str | None = None,
        sourcetype: str | None = None,
    ) -> int:
        """POST events to HEC endpoint in batches of up to 100.

        Args:
            events: List of raw event dicts.
            index: Override target index (default: config.index).
            sourcetype: Override sourcetype (default: config.sourcetype).

        Returns:
            Number of events successfully accepted.
        """
        if not events:
            return 0

        cfg = self._config
        idx = index or cfg.index
        stype = sourcetype or cfg.sourcetype
        accepted = 0

        for batch_start in range(0, len(events), _HEC_BATCH_SIZE):
            batch = events[batch_start : batch_start + _HEC_BATCH_SIZE]
            # HEC raw batch: newline-delimited JSON objects
            payload_lines: list[str] = []
            for evt in batch:
                hec_event: dict[str, Any] = {
                    "index": idx,
                    "sourcetype": stype,
                    "event": evt,
                }
                if "timestamp" in evt:
                    hec_event["time"] = evt["timestamp"]
                if cfg.extra_fields:
                    hec_event["fields"] = cfg.extra_fields
                payload_lines.append(json.dumps(hec_event, default=str))

            payload = "\n".join(payload_lines)
            try:
                resp = await self._hec_request(
                    "POST",
                    "/services/collector/event",
                    content=payload,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200:
                    accepted += len(batch)
                    logger.debug("HEC accepted %d events (batch %d+)", len(batch), batch_start)
                else:
                    logger.warning(
                        "HEC rejected batch starting at %d: %s %s",
                        batch_start, resp.status_code, resp.text[:200],
                    )
            except Exception as exc:
                logger.error("HEC send_events error: %s", exc)

        return accepted

    # ── REST API ──────────────────────────────────────────────────────────────

    async def test_connection(self) -> dict[str, Any]:
        """GET /services/server/info to verify connectivity and return version/health.

        Returns:
            Dict with keys: healthy, version, build, serverName.
        """
        try:
            resp = await self._rest_request("GET", "/services/server/info?output_mode=json")
            data = resp.json()
            entry = data.get("entry", [{}])[0]
            content = entry.get("content", {})
            return {
                "healthy": True,
                "version": content.get("version", "unknown"),
                "build": content.get("build", "unknown"),
                "serverName": content.get("serverName", "unknown"),
                "os_name": content.get("os_name", "unknown"),
                "cpu_arch": content.get("cpu_arch", "unknown"),
                "numberOfCores": content.get("numberOfCores", 0),
            }
        except Exception as exc:
            logger.error("test_connection failed: %s", exc)
            return {"healthy": False, "error": str(exc)}

    async def search(
        self,
        query: str,
        earliest: str = "-15m",
        latest: str = "now",
        max_results: int = 100,
        timeout_secs: int = 30,
    ) -> list[dict[str, Any]]:
        """Run an SPL search via REST and return results.

        Follows the two-step Splunk search pattern:
        1. POST to /services/search/jobs to create the search job.
        2. Poll until done, then GET /services/search/jobs/{sid}/results.

        Args:
            query: SPL search string (leading "search " optional).
            earliest: Earliest time bound, e.g. "-1h" or "2024-01-01T00:00:00".
            latest: Latest time bound.
            max_results: Maximum number of results to return.
            timeout_secs: Maximum seconds to wait for job completion.

        Returns:
            List of result dicts.
        """
        spl = query if query.strip().startswith("search ") else f"search {query}"
        data = {
            "search": spl,
            "earliest_time": earliest,
            "latest_time": latest,
            "output_mode": "json",
            "exec_mode": "normal",
        }
        try:
            resp = await self._rest_request("POST", "/services/search/jobs", data=data)
            sid = resp.json().get("sid")
            if not sid:
                logger.error("Search job creation returned no SID: %s", resp.text[:300])
                return []
        except Exception as exc:
            logger.error("search job creation failed: %s", exc)
            return []

        # Poll for completion
        deadline = time.monotonic() + timeout_secs
        while time.monotonic() < deadline:
            try:
                status_resp = await self._rest_request(
                    "GET", f"/services/search/jobs/{sid}?output_mode=json"
                )
                job = status_resp.json()
                entry = job.get("entry", [{}])[0]
                dispatch_state = entry.get("content", {}).get("dispatchState", "")
                if dispatch_state in ("DONE", "FAILED", "FINALIZING"):
                    break
                await asyncio.sleep(1.0)
            except Exception as exc:
                logger.warning("search poll error for SID %s: %s", sid, exc)
                await asyncio.sleep(1.0)
        else:
            logger.warning("Search SID %s timed out after %ds", sid, timeout_secs)

        # Fetch results
        try:
            results_resp = await self._rest_request(
                "GET",
                f"/services/search/jobs/{sid}/results",
                params={"output_mode": "json", "count": str(max_results)},
            )
            return results_resp.json().get("results", [])
        except Exception as exc:
            logger.error("search results fetch failed for SID %s: %s", sid, exc)
            return []

    async def get_saved_searches(self) -> list[dict[str, Any]]:
        """GET /services/saved/searches and return all saved searches.

        Returns:
            List of dicts with keys: name, search, description, disabled, cron_schedule.
        """
        try:
            resp = await self._rest_request(
                "GET",
                "/services/saved/searches",
                params={"output_mode": "json", "count": "200"},
            )
            entries = resp.json().get("entry", [])
            results: list[dict[str, Any]] = []
            for entry in entries:
                content = entry.get("content", {})
                results.append(
                    {
                        "name": entry.get("name", ""),
                        "search": content.get("search", ""),
                        "description": content.get("description", ""),
                        "disabled": content.get("disabled", False),
                        "cron_schedule": content.get("cron_schedule", ""),
                        "is_scheduled": content.get("is_scheduled", False),
                        "alert_type": content.get("alert_type", ""),
                        "updated": entry.get("updated", ""),
                    }
                )
            return results
        except Exception as exc:
            logger.error("get_saved_searches failed: %s", exc)
            return []

    async def push_rule(
        self,
        rule_name: str,
        spl_query: str,
        description: str = "",
        cron_schedule: str = "*/5 * * * *",
        alert_severity: str = "medium",
    ) -> bool:
        """POST a new saved search / detection rule to Splunk.

        Args:
            rule_name: Unique name for the saved search.
            spl_query: SPL search string.
            description: Human-readable description.
            cron_schedule: Cron schedule for alerting runs.
            alert_severity: Severity label (low/medium/high/critical).

        Returns:
            True if rule was created/updated successfully.
        """
        data = {
            "name": rule_name,
            "search": spl_query,
            "description": description,
            "is_scheduled": "1",
            "cron_schedule": cron_schedule,
            "alert.severity": alert_severity,
            "output_mode": "json",
        }
        try:
            resp = await self._rest_request(
                "POST", "/services/saved/searches", data=data
            )
            if resp.status_code in (200, 201):
                logger.info("push_rule: saved search '%s' created/updated.", rule_name)
                return True
            logger.warning(
                "push_rule failed for '%s': %s %s", rule_name, resp.status_code, resp.text[:200]
            )
            return False
        except Exception as exc:
            logger.error("push_rule error for '%s': %s", rule_name, exc)
            return False

    async def get_index_stats(self) -> list[dict[str, Any]]:
        """GET /services/data/indexes and return index names + event counts.

        Returns:
            List of dicts with keys: name, totalEventCount, currentDBSizeMB, maxTotalDataSizeMB.
        """
        try:
            resp = await self._rest_request(
                "GET",
                "/services/data/indexes",
                params={"output_mode": "json", "count": "200"},
            )
            entries = resp.json().get("entry", [])
            return [
                {
                    "name": entry.get("name", ""),
                    "totalEventCount": entry.get("content", {}).get("totalEventCount", 0),
                    "currentDBSizeMB": entry.get("content", {}).get("currentDBSizeMB", 0),
                    "maxTotalDataSizeMB": entry.get("content", {}).get("maxTotalDataSizeMB", 0),
                    "disabled": entry.get("content", {}).get("disabled", False),
                    "frozenTimePeriodInSecs": entry.get("content", {}).get("frozenTimePeriodInSecs", 0),
                }
                for entry in entries
            ]
        except Exception as exc:
            logger.error("get_index_stats failed: %s", exc)
            return []

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _ensure_clients(self) -> None:
        """Initialise clients if not already open (supports standalone use)."""
        if self._hec_client is None or self._rest_client is None:
            await self._init_clients()

    async def _hec_request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> httpx.Response:
        await self._ensure_clients()
        return await self._request_with_retry(self._hec_client, method, path, **kwargs)  # type: ignore[arg-type]

    async def _rest_request(
        self,
        method: str,
        path: str,
        params: dict[str, str] | None = None,
        data: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        await self._ensure_clients()
        if "output_mode=json" not in path and (params is None or "output_mode" not in params):
            if params is None:
                params = {}
            params["output_mode"] = "json"
        return await self._request_with_retry(
            self._rest_client, method, path, params=params, data=data, **kwargs  # type: ignore[arg-type]
        )

    @staticmethod
    async def _request_with_retry(
        client: httpx.AsyncClient,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Execute an HTTP request with up to 3 retries and exponential backoff.

        Retries on 429 (respecting Retry-After header) and 503 status codes.
        """
        delay = 1.0
        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                resp = await client.request(method, path, **kwargs)
                if resp.status_code not in _RETRY_STATUSES:
                    resp.raise_for_status()
                    return resp
                # Honour Retry-After if present
                retry_after = resp.headers.get("Retry-After")
                wait = float(retry_after) if retry_after else delay
                logger.warning(
                    "Splunk %s %s → %d; retrying in %.1fs (attempt %d/%d)",
                    method, path, resp.status_code, wait, attempt + 1, _MAX_RETRIES,
                )
                if attempt < _MAX_RETRIES:
                    await asyncio.sleep(wait)
                    delay *= 2
                else:
                    resp.raise_for_status()
                    return resp
            except httpx.HTTPStatusError:
                raise
            except Exception as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES:
                    logger.warning(
                        "Splunk request error on attempt %d/%d: %s; retrying in %.1fs",
                        attempt + 1, _MAX_RETRIES, exc, delay,
                    )
                    await asyncio.sleep(delay)
                    delay *= 2
        # Should never reach here, but satisfy type checker
        raise last_exc or RuntimeError("Request failed after retries")
