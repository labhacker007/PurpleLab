"""Splunk connector for ConnectionManager.

Credentials dict keys (passed from ConnectionManager.get_connection):
    base_url   : Splunk REST base URL, e.g. "https://splunk:8089"
    hec_url    : Splunk HEC base URL, e.g. "https://splunk:8088" (optional,
                 defaults to base_url)
    hec_token  : HEC ingest token (with or without "Splunk " prefix)
    username   : REST API username
    password   : REST API password
    index      : Target index (default "main")
    sourcetype : Sourcetype label (default "purplelab")
    verify_ssl : bool (default True)
"""
from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from backend.siem_integration.connectors.base import BaseSIEMConnector

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(10.0)
_HEC_BATCH = 100


class SplunkConnector(BaseSIEMConnector):
    """Concrete Splunk connector backed by HEC + REST API."""

    def __init__(self, credentials: dict[str, Any]) -> None:
        self._creds = credentials
        self._base_url: str = (credentials.get("base_url") or "").rstrip("/")
        self._hec_url: str = (
            credentials.get("hec_url") or self._base_url
        ).rstrip("/")
        raw_token: str = credentials.get("hec_token", "")
        # Store without "Splunk " prefix; add it in request headers
        if raw_token.startswith("Splunk "):
            raw_token = raw_token[len("Splunk "):]
        self._hec_token = raw_token
        self._username: str = credentials.get("username", "")
        self._password: str = credentials.get("password", "")
        self._index: str = credentials.get("index", "main")
        self._sourcetype: str = credentials.get("sourcetype", "purplelab")
        verify_ssl = credentials.get("verify_ssl", True)
        self._hec_client = httpx.AsyncClient(
            base_url=self._hec_url,
            headers={"Authorization": f"Splunk {self._hec_token}"},
            verify=verify_ssl,
            timeout=_TIMEOUT,
        )
        self._rest_client = httpx.AsyncClient(
            base_url=self._base_url,
            auth=(self._username, self._password),
            verify=verify_ssl,
            timeout=_TIMEOUT,
        )

    async def close(self) -> None:
        await self._hec_client.aclose()
        await self._rest_client.aclose()

    # ── BaseSIEMConnector interface ───────────────────────────────────────────

    async def test(self) -> dict[str, Any]:
        """GET /services/server/info to verify REST API connectivity."""
        t0 = self._timer()
        try:
            resp = await self._rest_client.get(
                "/services/server/info",
                params={"output_mode": "json"},
            )
            resp.raise_for_status()
            data = resp.json()
            entry = data.get("entry", [{}])[0]
            content = entry.get("content", {})
            latency = self._elapsed_ms(t0)
            return {
                "success": True,
                "message": f"Connected to Splunk {content.get('version', 'unknown')}",
                "latency_ms": latency,
                "version": content.get("version", ""),
                "server_name": content.get("serverName", ""),
                "os_name": content.get("os_name", ""),
            }
        except Exception as exc:
            logger.warning("SplunkConnector.test failed: %s", exc)
            return {
                "success": False,
                "message": str(exc),
                "latency_ms": self._elapsed_ms(t0),
            }

    async def push_logs(self, logs: list[dict[str, Any]]) -> int:
        """POST events via Splunk HEC in batches of 100."""
        if not logs:
            return 0
        accepted = 0
        for start in range(0, len(logs), _HEC_BATCH):
            batch = logs[start : start + _HEC_BATCH]
            lines: list[str] = []
            for evt in batch:
                hec_event: dict[str, Any] = {
                    "index": self._index,
                    "sourcetype": self._sourcetype,
                    "event": evt,
                }
                if "timestamp" in evt:
                    hec_event["time"] = evt["timestamp"]
                lines.append(json.dumps(hec_event, default=str))
            try:
                resp = await self._hec_client.post(
                    "/services/collector/event",
                    content="\n".join(lines),
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200:
                    accepted += len(batch)
                else:
                    logger.warning(
                        "SplunkConnector.push_logs HEC %d: %s",
                        resp.status_code,
                        resp.text[:200],
                    )
            except Exception as exc:
                logger.error("SplunkConnector.push_logs error: %s", exc)
        return accepted

    async def push_rule(
        self,
        rule_text: str,
        rule_name: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """POST a saved search to /services/saved/searches."""
        meta = metadata or {}
        data = {
            "name": rule_name,
            "search": rule_text,
            "description": meta.get("description", f"PurpleLab rule: {rule_name}"),
            "is_scheduled": "1",
            "cron_schedule": meta.get("cron_schedule", "*/5 * * * *"),
            "alert.severity": meta.get("severity", "medium"),
            "output_mode": "json",
        }
        try:
            resp = await self._rest_client.post(
                "/services/saved/searches",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp.status_code in (200, 201):
                return {"success": True, "message": f"Rule '{rule_name}' created."}
            return {
                "success": False,
                "message": f"HTTP {resp.status_code}: {resp.text[:200]}",
            }
        except Exception as exc:
            logger.error("SplunkConnector.push_rule error: %s", exc)
            return {"success": False, "message": str(exc)}
