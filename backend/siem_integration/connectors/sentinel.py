"""Microsoft Sentinel connector for ConnectionManager.

Credentials dict keys:
    workspace_id     : Log Analytics workspace ID (GUID)
    workspace_key    : Primary shared key for HMAC-SHA256 signing
    tenant_id        : Azure AD tenant ID
    client_id        : Service principal app client ID
    client_secret    : Service principal client secret
    subscription_id  : Azure subscription ID
    resource_group   : Resource group containing the workspace
    workspace_name   : Workspace ARM resource name
    dce_endpoint     : (optional) Data Collection Endpoint URL
    dcr_immutable_id : (optional) Data Collection Rule immutable ID
    log_table        : Custom log table name (default "PurpleLabEvents_CL")
    verify_ssl       : bool (default True)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from backend.siem_integration.connectors.base import BaseSIEMConnector

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(10.0)
_ARM_BASE = "https://management.azure.com"
_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_TOKEN_BUFFER = 300  # seconds before expiry to refresh


class _TokenCache:
    def __init__(self) -> None:
        self._token = ""
        self._expires_at = 0.0

    def is_valid(self) -> bool:
        return bool(self._token) and time.monotonic() < self._expires_at

    def store(self, token: str, expires_in: int) -> None:
        self._token = token
        self._expires_at = time.monotonic() + expires_in - _TOKEN_BUFFER

    @property
    def token(self) -> str:
        return self._token


class SentinelConnector(BaseSIEMConnector):
    """Concrete Microsoft Sentinel connector."""

    def __init__(self, credentials: dict[str, Any]) -> None:
        self._c = credentials
        verify_ssl = credentials.get("verify_ssl", True)
        self._client = httpx.AsyncClient(
            verify=verify_ssl,
            timeout=_TIMEOUT,
            headers={"Content-Type": "application/json"},
        )
        self._arm_cache = _TokenCache()
        self._ingest_cache = _TokenCache()

    async def close(self) -> None:
        await self._client.aclose()

    # ── Token helpers ─────────────────────────────────────────────────────────

    async def _arm_token(self) -> str:
        if self._arm_cache.is_valid():
            return self._arm_cache.token
        return await self._fetch_token(
            "https://management.azure.com/.default", self._arm_cache
        )

    async def _ingest_token(self) -> str:
        if self._ingest_cache.is_valid():
            return self._ingest_cache.token
        return await self._fetch_token(
            "https://monitor.azure.com/.default", self._ingest_cache
        )

    async def _fetch_token(self, scope: str, cache: _TokenCache) -> str:
        c = self._c
        url = _TOKEN_URL.format(tenant_id=c.get("tenant_id", ""))
        data = {
            "grant_type": "client_credentials",
            "client_id": c.get("client_id", ""),
            "client_secret": c.get("client_secret", ""),
            "scope": scope,
        }
        resp = await self._client.post(url, data=data)
        resp.raise_for_status()
        body = resp.json()
        if "access_token" not in body:
            raise ValueError(f"Token response missing access_token: {body}")
        cache.store(body["access_token"], int(body.get("expires_in", 3600)))
        return cache.token

    # ── BaseSIEMConnector interface ───────────────────────────────────────────

    async def test(self) -> dict[str, Any]:
        """GET workspace info via ARM API to verify auth."""
        t0 = self._timer()
        try:
            token = await self._arm_token()
            c = self._c
            resource_id = self._workspace_resource_id()
            url = f"{_ARM_BASE}{resource_id}?api-version=2022-10-01"
            resp = await self._client.get(
                url, headers={"Authorization": f"Bearer {token}"}
            )
            resp.raise_for_status()
            body = resp.json()
            props = body.get("properties", {})
            latency = self._elapsed_ms(t0)
            return {
                "success": True,
                "message": f"Connected to Sentinel workspace {body.get('name', '')}",
                "latency_ms": latency,
                "workspace_id": props.get("customerId", c.get("workspace_id", "")),
                "location": body.get("location", ""),
                "sku": props.get("sku", {}).get("name", ""),
                "provisioning_state": props.get("provisioningState", ""),
            }
        except Exception as exc:
            logger.warning("SentinelConnector.test failed: %s", exc)
            return {
                "success": False,
                "message": str(exc),
                "latency_ms": self._elapsed_ms(t0),
            }

    async def push_logs(self, logs: list[dict[str, Any]]) -> int:
        """Push events via DCE (if configured) or legacy HMAC endpoint."""
        if not logs:
            return 0
        c = self._c
        stamped = self._stamp_events(logs)
        if c.get("dce_endpoint") and c.get("dcr_immutable_id"):
            return await self._send_dce(stamped)
        return await self._send_hmac(stamped)

    async def push_rule(
        self,
        rule_text: str,
        rule_name: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """PUT a Scheduled analytic rule via the SecurityInsights ARM API."""
        meta = metadata or {}
        try:
            token = await self._arm_token()
            c = self._c
            safe_name = rule_name.replace(" ", "-").replace("_", "-")[:260]
            url = (
                f"{_ARM_BASE}/subscriptions/{c.get('subscription_id', '')}"
                f"/resourceGroups/{c.get('resource_group', '')}"
                f"/providers/Microsoft.OperationalInsights/workspaces/{c.get('workspace_name', '')}"
                f"/providers/Microsoft.SecurityInsights/alertRules/{safe_name}"
                f"?api-version=2023-02-01"
            )
            payload: dict[str, Any] = {
                "kind": "Scheduled",
                "properties": {
                    "displayName": rule_name,
                    "description": meta.get(
                        "description", f"PurpleLab detection rule: {rule_name}"
                    ),
                    "severity": meta.get("severity", "Medium"),
                    "enabled": True,
                    "query": rule_text,
                    "queryFrequency": meta.get("query_frequency", "PT5M"),
                    "queryPeriod": meta.get("query_period", "PT5M"),
                    "triggerOperator": meta.get("trigger_operator", "GreaterThan"),
                    "triggerThreshold": meta.get("trigger_threshold", 0),
                    "suppressionDuration": "PT1H",
                    "suppressionEnabled": False,
                    "tactics": meta.get("tactics", []),
                    "techniques": [],
                    "alertDetailsOverride": None,
                    "customDetails": None,
                    "entityMappings": None,
                },
            }
            resp = await self._client.put(
                url,
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
            )
            if resp.status_code in (200, 201):
                return {"success": True, "message": f"Rule '{rule_name}' upserted."}
            return {
                "success": False,
                "message": f"HTTP {resp.status_code}: {resp.text[:200]}",
            }
        except Exception as exc:
            logger.error("SentinelConnector.push_rule error: %s", exc)
            return {"success": False, "message": str(exc)}

    # ── Ingest helpers ────────────────────────────────────────────────────────

    async def _send_dce(self, events: list[dict[str, Any]]) -> int:
        c = self._c
        try:
            token = await self._ingest_token()
            log_table = c.get("log_table", "PurpleLabEvents_CL")
            url = (
                f"{c['dce_endpoint']}/dataCollectionRules/{c['dcr_immutable_id']}"
                f"/streams/Custom-{log_table}?api-version=2023-01-01"
            )
            resp = await self._client.post(
                url,
                content=json.dumps(events, default=str),
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
            )
            if resp.status_code in (200, 204):
                return len(events)
            logger.warning("Sentinel DCE returned %d: %s", resp.status_code, resp.text[:300])
            return 0
        except Exception as exc:
            logger.error("SentinelConnector._send_dce error: %s", exc)
            return 0

    async def _send_hmac(self, events: list[dict[str, Any]]) -> int:
        c = self._c
        try:
            log_table = c.get("log_table", "PurpleLabEvents_CL")
            payload_bytes = json.dumps(events, default=str).encode("utf-8")
            rfc_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
            signature = self._hmac_signature(rfc_date, len(payload_bytes), log_table)
            url = (
                f"https://{c.get('workspace_id', '')}.ods.opinsights.azure.com"
                f"/api/logs?api-version=2016-04-01"
            )
            resp = await self._client.post(
                url,
                content=payload_bytes,
                headers={
                    "Authorization": signature,
                    "Log-Type": log_table.replace("_CL", ""),
                    "x-ms-date": rfc_date,
                    "time-generated-field": "TimeGenerated",
                    "Content-Type": "application/json",
                },
            )
            if resp.status_code == 200:
                return len(events)
            logger.warning("Sentinel HMAC returned %d: %s", resp.status_code, resp.text[:300])
            return 0
        except Exception as exc:
            logger.error("SentinelConnector._send_hmac error: %s", exc)
            return 0

    def _hmac_signature(self, date: str, content_length: int, log_type: str) -> str:
        c = self._c
        string_to_hash = (
            f"POST\n{content_length}\napplication/json\nx-ms-date:{date}\n/api/logs"
        )
        decoded_key = base64.b64decode(c.get("workspace_key", ""))
        digest = hmac.new(
            decoded_key, string_to_hash.encode("utf-8"), digestmod=hashlib.sha256
        ).digest()
        encoded_hash = base64.b64encode(digest).decode()
        return f"SharedKey {c.get('workspace_id', '')}:{encoded_hash}"

    def _workspace_resource_id(self) -> str:
        c = self._c
        return (
            f"/subscriptions/{c.get('subscription_id', '')}"
            f"/resourceGroups/{c.get('resource_group', '')}"
            f"/providers/Microsoft.OperationalInsights/workspaces"
            f"/{c.get('workspace_name', '')}"
        )

    @staticmethod
    def _stamp_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc).isoformat()
        return [{**e, "TimeGenerated": e.get("TimeGenerated", now)} for e in events]
