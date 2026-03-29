"""Microsoft Sentinel connector — DCE ingest, KQL queries, analytic rule management.

Supports:
- Data Collection Endpoint (DCE) ingest via DCR with HMAC-SHA256 signing
- Azure Monitor Log Analytics KQL query API
- ARM API for workspace metadata
- Microsoft Sentinel Analytic Rules (create/list/update)
- OAuth2 client credentials with automatic token refresh
- Async context manager pattern
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from backend.siem_integration.connectors.base_connector import AbstractConnector

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
# Token expiry buffer — refresh 5 minutes before actual expiry
_TOKEN_REFRESH_BUFFER_SECS = 300

_ARM_BASE = "https://management.azure.com"
_LOG_ANALYTICS_BASE = "https://api.loganalytics.io/v1"
_TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"


@dataclass
class SentinelConfig:
    """Configuration for a Microsoft Sentinel workspace.

    Auth uses OAuth2 client credentials flow (tenant_id + client_id + client_secret).
    DCE ingest uses HMAC-SHA256 (workspace_id + workspace_key) OR bearer token via DCE URL.
    """

    workspace_id: str
    workspace_key: str       # Primary key for HMAC-SHA256 DCE signing
    tenant_id: str
    client_id: str
    client_secret: str
    subscription_id: str
    resource_group: str
    workspace_name: str
    dce_endpoint: str = ""   # Data Collection Endpoint URL
    dcr_immutable_id: str = ""  # Data Collection Rule immutable ID
    log_table: str = "PurpleLabEvents_CL"  # Custom log table name
    verify_ssl: bool = True
    timeout: float = 30.0


class _TokenCache:
    """Thread-safe-ish OAuth2 bearer token cache."""

    def __init__(self) -> None:
        self._token: str = ""
        self._expires_at: float = 0.0

    def is_valid(self) -> bool:
        return bool(self._token) and time.monotonic() < self._expires_at

    def store(self, token: str, expires_in: int) -> None:
        self._token = token
        self._expires_at = time.monotonic() + expires_in - _TOKEN_REFRESH_BUFFER_SECS

    @property
    def token(self) -> str:
        return self._token


class SentinelConnector(AbstractConnector):
    """Production Microsoft Sentinel connector.

    Handles both the classic Workspace API (HMAC ingest) and the modern
    Data Collection Endpoint / Azure Monitor Ingestion API paths.

    Usage as async context manager::

        config = SentinelConfig(workspace_id=..., workspace_key=...,
                                tenant_id=..., client_id=..., client_secret=...,
                                subscription_id=..., resource_group=...,
                                workspace_name=...)
        async with SentinelConnector(config) as conn:
            await conn.send_events(events)
            results = await conn.run_kql_query("PurpleLabEvents_CL | take 10", workspace_id)
    """

    platform = "sentinel"

    def __init__(self, config: SentinelConfig) -> None:
        self._config = config
        self._client: httpx.AsyncClient | None = None
        self._arm_token_cache = _TokenCache()
        self._ingest_token_cache = _TokenCache()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def __aenter__(self) -> "SentinelConnector":
        await self._init_client()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.disconnect()

    async def _init_client(self) -> None:
        cfg = self._config
        self._client = httpx.AsyncClient(
            verify=cfg.verify_ssl,
            timeout=cfg.timeout,
            headers={"Content-Type": "application/json"},
        )

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # ── AbstractConnector compat ───────────────────────────────────────────────

    async def connect(self, base_url: str, credentials: dict[str, str]) -> bool:
        cfg = self._config
        for field in ("tenant_id", "client_id", "client_secret", "workspace_id", "workspace_key"):
            if field in credentials:
                object.__setattr__(cfg, field, credentials[field])
        await self._init_client()
        info = await self.test_connection()
        return info.get("healthy", False)

    async def pull_rules(self) -> list[dict[str, Any]]:
        return await self.list_analytic_rules()

    async def push_logs(self, events: list[dict[str, Any]], index: str = "") -> bool:
        sent = await self.send_events(events)
        return sent == len(events)

    async def health_check(self) -> bool:
        info = await self.test_connection()
        return info.get("healthy", False)

    # ── Token Management ──────────────────────────────────────────────────────

    async def _get_arm_token(self) -> str:
        """Obtain or refresh an ARM management bearer token."""
        if self._arm_token_cache.is_valid():
            return self._arm_token_cache.token
        return await self._fetch_token(
            scope="https://management.azure.com/.default",
            cache=self._arm_token_cache,
        )

    async def _get_ingest_token(self) -> str:
        """Obtain or refresh a token for Azure Monitor Ingestion (DCE)."""
        if self._ingest_token_cache.is_valid():
            return self._ingest_token_cache.token
        return await self._fetch_token(
            scope="https://monitor.azure.com/.default",
            cache=self._ingest_token_cache,
        )

    async def _fetch_token(self, scope: str, cache: _TokenCache) -> str:
        cfg = self._config
        url = _TOKEN_URL_TEMPLATE.format(tenant_id=cfg.tenant_id)
        data = {
            "grant_type": "client_credentials",
            "client_id": cfg.client_id,
            "client_secret": cfg.client_secret,
            "scope": scope,
        }
        try:
            resp = await self._raw_request("POST", url, data=data)
            body = resp.json()
            if "access_token" not in body:
                raise ValueError(f"Token response missing access_token: {body}")
            cache.store(body["access_token"], int(body.get("expires_in", 3600)))
            logger.debug("Fetched OAuth2 token for scope '%s'.", scope)
            return cache.token
        except Exception as exc:
            logger.error("_fetch_token failed for scope '%s': %s", scope, exc)
            raise

    # ── DCE / Log Analytics Ingest ────────────────────────────────────────────

    async def send_events(self, events: list[dict[str, Any]]) -> int:
        """POST events to a Data Collection Endpoint or the legacy HMAC endpoint.

        Falls back to the legacy Log Analytics Data Collector API
        (HMAC-SHA256 signed) when no DCE endpoint / DCR is configured.

        Args:
            events: List of event dicts.

        Returns:
            Number of events successfully accepted (all-or-nothing per batch).
        """
        if not events:
            return 0

        cfg = self._config
        if cfg.dce_endpoint and cfg.dcr_immutable_id:
            return await self._send_via_dce(events)
        return await self._send_via_hmac(events)

    async def _send_via_dce(self, events: list[dict[str, Any]]) -> int:
        """Send events via the Azure Monitor Ingestion API (DCE + DCR)."""
        cfg = self._config
        token = await self._get_ingest_token()
        url = (
            f"{cfg.dce_endpoint}/dataCollectionRules/{cfg.dcr_immutable_id}"
            f"/streams/Custom-{cfg.log_table}?api-version=2023-01-01"
        )
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        # Ensure TimeGenerated is present
        stamped_events = self._stamp_events(events)
        payload = json.dumps(stamped_events, default=str)
        try:
            resp = await self._request_with_retry("POST", url, content=payload, headers=headers)
            if resp.status_code in (200, 204):
                logger.debug("DCE accepted %d events.", len(events))
                return len(events)
            logger.warning("DCE ingest returned %d: %s", resp.status_code, resp.text[:300])
            return 0
        except Exception as exc:
            logger.error("_send_via_dce failed: %s", exc)
            return 0

    async def _send_via_hmac(self, events: list[dict[str, Any]]) -> int:
        """Send events via the legacy Log Analytics HTTP Data Collector API.

        Uses HMAC-SHA256 signature with the workspace primary key.
        """
        cfg = self._config
        stamped_events = self._stamp_events(events)
        payload = json.dumps(stamped_events, default=str)
        payload_bytes = payload.encode("utf-8")
        rfc1123_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        content_length = len(payload_bytes)
        signature = self._build_hmac_signature(rfc1123_date, content_length, cfg.log_table)

        url = (
            f"https://{cfg.workspace_id}.ods.opinsights.azure.com"
            f"/api/logs?api-version=2016-04-01"
        )
        headers = {
            "Authorization": signature,
            "Log-Type": cfg.log_table.replace("_CL", ""),  # API strips _CL suffix
            "x-ms-date": rfc1123_date,
            "x-ms-AzureResourceId": self._workspace_resource_id(),
            "time-generated-field": "TimeGenerated",
            "Content-Type": "application/json",
        }
        try:
            resp = await self._request_with_retry(
                "POST", url, content=payload_bytes, headers=headers
            )
            if resp.status_code == 200:
                logger.debug("HMAC ingest accepted %d events.", len(events))
                return len(events)
            logger.warning(
                "HMAC ingest returned %d: %s", resp.status_code, resp.text[:300]
            )
            return 0
        except Exception as exc:
            logger.error("_send_via_hmac failed: %s", exc)
            return 0

    def _build_hmac_signature(
        self, date: str, content_length: int, log_type: str
    ) -> str:
        """Build the Shared Key Authorization header for Log Analytics."""
        cfg = self._config
        string_to_hash = (
            f"POST\n{content_length}\napplication/json\n"
            f"x-ms-date:{date}\n/api/logs"
        )
        bytes_to_hash = string_to_hash.encode("utf-8")
        decoded_key = base64.b64decode(cfg.workspace_key)
        encoded_hash = base64.b64encode(
            hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
        ).decode("utf-8")
        return f"SharedKey {cfg.workspace_id}:{encoded_hash}"

    def _workspace_resource_id(self) -> str:
        cfg = self._config
        return (
            f"/subscriptions/{cfg.subscription_id}/resourceGroups/{cfg.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{cfg.workspace_name}"
        )

    @staticmethod
    def _stamp_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Ensure every event has a TimeGenerated field."""
        now = datetime.now(timezone.utc).isoformat()
        stamped = []
        for evt in events:
            if "TimeGenerated" not in evt:
                evt = {**evt, "TimeGenerated": now}
            stamped.append(evt)
        return stamped

    # ── KQL Query ─────────────────────────────────────────────────────────────

    async def run_kql_query(
        self,
        query: str,
        workspace_id: str | None = None,
        timespan: str = "P1D",
    ) -> list[dict[str, Any]]:
        """POST a KQL query to the Log Analytics Query API.

        Args:
            query: KQL query string.
            workspace_id: Workspace ID (default: config.workspace_id).
            timespan: ISO 8601 duration, e.g. "P1D", "PT1H".

        Returns:
            List of result row dicts.
        """
        wsid = workspace_id or self._config.workspace_id
        token = await self._get_arm_token()
        url = f"{_LOG_ANALYTICS_BASE}/workspaces/{wsid}/query"
        headers = {"Authorization": f"Bearer {token}"}
        payload = {"query": query, "timespan": timespan}
        try:
            resp = await self._request_with_retry("POST", url, json=payload, headers=headers)
            body = resp.json()
            tables = body.get("tables", [])
            if not tables:
                return []
            table = tables[0]
            columns = [c["name"] for c in table.get("columns", [])]
            return [dict(zip(columns, row)) for row in table.get("rows", [])]
        except Exception as exc:
            logger.error("run_kql_query failed: %s", exc)
            return []

    # ── Workspace Info ────────────────────────────────────────────────────────

    async def test_connection(self) -> dict[str, Any]:
        """GET workspace details via ARM API and verify token auth.

        Returns:
            Dict with keys: healthy, workspace_id, location, sku, retention_days.
        """
        try:
            cfg = self._config
            token = await self._get_arm_token()
            resource_id = self._workspace_resource_id()
            url = f"{_ARM_BASE}{resource_id}?api-version=2022-10-01"
            headers = {"Authorization": f"Bearer {token}"}
            resp = await self._request_with_retry("GET", url, headers=headers)
            body = resp.json()
            props = body.get("properties", {})
            return {
                "healthy": True,
                "workspace_id": props.get("customerId", cfg.workspace_id),
                "location": body.get("location", "unknown"),
                "sku": props.get("sku", {}).get("name", "unknown"),
                "retention_days": props.get("retentionInDays", 30),
                "workspace_name": body.get("name", cfg.workspace_name),
                "provisioning_state": props.get("provisioningState", "unknown"),
            }
        except Exception as exc:
            logger.error("test_connection failed: %s", exc)
            return {"healthy": False, "error": str(exc)}

    # ── Analytic Rules ────────────────────────────────────────────────────────

    async def list_analytic_rules(self) -> list[dict[str, Any]]:
        """GET all Sentinel analytic rules for the workspace.

        Returns:
            List of rule dicts with name, kind, query, severity, tactics.
        """
        try:
            cfg = self._config
            token = await self._get_arm_token()
            url = (
                f"{_ARM_BASE}/subscriptions/{cfg.subscription_id}"
                f"/resourceGroups/{cfg.resource_group}"
                f"/providers/Microsoft.OperationalInsights/workspaces/{cfg.workspace_name}"
                f"/providers/Microsoft.SecurityInsights/alertRules"
                f"?api-version=2023-02-01"
            )
            headers = {"Authorization": f"Bearer {token}"}
            resp = await self._request_with_retry("GET", url, headers=headers)
            rules_raw = resp.json().get("value", [])
            return [
                {
                    "name": r.get("name", ""),
                    "display_name": r.get("properties", {}).get("displayName", ""),
                    "kind": r.get("kind", ""),
                    "severity": r.get("properties", {}).get("severity", ""),
                    "enabled": r.get("properties", {}).get("enabled", False),
                    "query": r.get("properties", {}).get("query", ""),
                    "tactics": r.get("properties", {}).get("tactics", []),
                    "techniques": r.get("properties", {}).get("techniques", []),
                    "query_period": r.get("properties", {}).get("queryPeriod", ""),
                    "query_frequency": r.get("properties", {}).get("queryFrequency", ""),
                    "trigger_operator": r.get("properties", {}).get("triggerOperator", ""),
                    "trigger_threshold": r.get("properties", {}).get("triggerThreshold", 0),
                }
                for r in rules_raw
            ]
        except Exception as exc:
            logger.error("list_analytic_rules failed: %s", exc)
            return []

    async def push_analytic_rule(
        self,
        rule_name: str,
        kql_query: str,
        mitre_tactics: list[str] | None = None,
        severity: str = "Medium",
        description: str = "",
        query_period: str = "PT5M",
        query_frequency: str = "PT5M",
        trigger_threshold: int = 0,
        trigger_operator: str = "GreaterThan",
    ) -> bool:
        """PUT a Scheduled analytic rule to Microsoft Sentinel.

        Args:
            rule_name: Unique rule name (used as the ARM resource name).
            kql_query: KQL detection query.
            mitre_tactics: List of MITRE ATT&CK tactic names.
            severity: Informational / Low / Medium / High.
            description: Rule description.
            query_period: ISO 8601 duration for query lookback window.
            query_frequency: ISO 8601 duration for schedule frequency.
            trigger_threshold: Alert when result count exceeds this value.
            trigger_operator: GreaterThan / LessThan / Equal / NotEqual.

        Returns:
            True if rule was created/updated successfully.
        """
        try:
            cfg = self._config
            token = await self._get_arm_token()
            safe_name = rule_name.replace(" ", "-").replace("_", "-")[:260]
            url = (
                f"{_ARM_BASE}/subscriptions/{cfg.subscription_id}"
                f"/resourceGroups/{cfg.resource_group}"
                f"/providers/Microsoft.OperationalInsights/workspaces/{cfg.workspace_name}"
                f"/providers/Microsoft.SecurityInsights/alertRules/{safe_name}"
                f"?api-version=2023-02-01"
            )
            headers = {"Authorization": f"Bearer {token}"}
            payload: dict[str, Any] = {
                "kind": "Scheduled",
                "properties": {
                    "displayName": rule_name,
                    "description": description or f"PurpleLab detection rule: {rule_name}",
                    "severity": severity,
                    "enabled": True,
                    "query": kql_query,
                    "queryFrequency": query_frequency,
                    "queryPeriod": query_period,
                    "triggerOperator": trigger_operator,
                    "triggerThreshold": trigger_threshold,
                    "suppressionDuration": "PT1H",
                    "suppressionEnabled": False,
                    "tactics": mitre_tactics or [],
                    "techniques": [],
                    "alertDetailsOverride": None,
                    "customDetails": None,
                    "entityMappings": None,
                },
            }
            resp = await self._request_with_retry("PUT", url, json=payload, headers=headers)
            if resp.status_code in (200, 201):
                logger.info("push_analytic_rule: rule '%s' upserted.", rule_name)
                return True
            logger.warning(
                "push_analytic_rule failed for '%s': %d %s",
                rule_name, resp.status_code, resp.text[:300],
            )
            return False
        except Exception as exc:
            logger.error("push_analytic_rule error for '%s': %s", rule_name, exc)
            return False

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _ensure_client(self) -> None:
        if self._client is None:
            await self._init_client()

    async def _raw_request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        await self._ensure_client()
        resp = await self._client.request(method, url, **kwargs)  # type: ignore[union-attr]
        resp.raise_for_status()
        return resp

    async def _request_with_retry(
        self, method: str, url: str, **kwargs: Any
    ) -> httpx.Response:
        """Execute request with exponential backoff on 429/503."""
        await self._ensure_client()
        delay = 1.0
        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                resp = await self._client.request(method, url, **kwargs)  # type: ignore[union-attr]
                if resp.status_code == 429:
                    retry_after = resp.headers.get("Retry-After") or resp.headers.get("x-ms-retry-after-ms")
                    wait = (
                        float(retry_after) / 1000
                        if retry_after and "." not in retry_after and int(retry_after) > 60
                        else float(retry_after or delay)
                    )
                    logger.warning(
                        "Sentinel 429 on %s; retrying in %.1fs (attempt %d/%d)",
                        url, wait, attempt + 1, _MAX_RETRIES,
                    )
                    if attempt < _MAX_RETRIES:
                        await asyncio.sleep(wait)
                        delay *= 2
                        continue
                if resp.status_code == 503 and attempt < _MAX_RETRIES:
                    logger.warning(
                        "Sentinel 503 on %s; retrying in %.1fs (attempt %d/%d)",
                        url, delay, attempt + 1, _MAX_RETRIES,
                    )
                    await asyncio.sleep(delay)
                    delay *= 2
                    continue
                resp.raise_for_status()
                return resp
            except httpx.HTTPStatusError:
                raise
            except Exception as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES:
                    logger.warning(
                        "Sentinel request error attempt %d/%d: %s; retrying in %.1fs",
                        attempt + 1, _MAX_RETRIES, exc, delay,
                    )
                    await asyncio.sleep(delay)
                    delay *= 2
        raise last_exc or RuntimeError("Request failed after retries")
