"""Elasticsearch / Kibana connector — bulk ingest, DSL search, rule management.

Supports:
- /_bulk endpoint for high-throughput event ingest
- DSL search with aggregations
- Cluster health and index introspection
- Kibana Detection Engine for pushing KQL/EQL rules
- API key or username/password auth
- Retry on 429 with Retry-After header respect
- Async context manager pattern
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
from dataclasses import dataclass
from typing import Any

import httpx

from backend.siem_integration.connectors.base_connector import AbstractConnector

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_BULK_BATCH_SIZE = 500  # Elastic bulk can handle larger batches than Splunk HEC

# Default index mappings for PurpleLab events
_PURPLELAB_MAPPINGS: dict[str, Any] = {
    "mappings": {
        "dynamic": "true",
        "properties": {
            "@timestamp": {"type": "date"},
            "event": {
                "properties": {
                    "kind": {"type": "keyword"},
                    "category": {"type": "keyword"},
                    "type": {"type": "keyword"},
                    "outcome": {"type": "keyword"},
                    "severity": {"type": "integer"},
                    "dataset": {"type": "keyword"},
                }
            },
            "host": {
                "properties": {
                    "name": {"type": "keyword"},
                    "hostname": {"type": "keyword"},
                }
            },
            "source": {"properties": {"ip": {"type": "ip"}}},
            "destination": {"properties": {"ip": {"type": "ip"}}},
            "user": {"properties": {"name": {"type": "keyword"}}},
            "process": {
                "properties": {
                    "name": {"type": "keyword"},
                    "pid": {"type": "long"},
                    "command_line": {"type": "text"},
                }
            },
            "message": {"type": "text"},
            "purplelab": {
                "properties": {
                    "source_id": {"type": "keyword"},
                    "scenario_id": {"type": "keyword"},
                    "session_id": {"type": "keyword"},
                }
            },
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "5s",
    },
}


@dataclass
class ElasticConfig:
    """Configuration for an Elasticsearch / Kibana instance.

    Supports API key (preferred) or username/password auth.
    api_key format: "key_id:api_key_value"
    """

    url: str               # e.g. "https://elastic:9200"
    api_key: str = ""      # id:key format
    username: str = ""
    password: str = ""
    index: str = "purplelab-logs"
    kibana_url: str = ""   # Kibana URL for rule management (defaults to url:5601)
    verify_ssl: bool = True
    timeout: float = 30.0


class ElasticConnector(AbstractConnector):
    """Production Elasticsearch connector for bulk ingest and detection rule management.

    Usage as async context manager::

        config = ElasticConfig(url="https://elastic:9200", api_key="id:key")
        async with ElasticConnector(config) as conn:
            await conn.send_events(events)
            results = await conn.search({"query": {"match_all": {}}})
    """

    platform = "elastic"

    def __init__(self, config: ElasticConfig) -> None:
        self._config = config
        self._es_client: httpx.AsyncClient | None = None
        self._kibana_client: httpx.AsyncClient | None = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def __aenter__(self) -> "ElasticConnector":
        await self._init_clients()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.disconnect()

    async def _init_clients(self) -> None:
        cfg = self._config
        headers = self._build_auth_headers()

        self._es_client = httpx.AsyncClient(
            base_url=cfg.url,
            headers={**headers, "Content-Type": "application/json"},
            verify=cfg.verify_ssl,
            timeout=cfg.timeout,
        )

        kibana_base = cfg.kibana_url or cfg.url.replace(":9200", ":5601")
        self._kibana_client = httpx.AsyncClient(
            base_url=kibana_base,
            headers={
                **headers,
                "Content-Type": "application/json",
                "kbn-xsrf": "true",
            },
            verify=cfg.verify_ssl,
            timeout=cfg.timeout,
        )

    def _build_auth_headers(self) -> dict[str, str]:
        cfg = self._config
        if cfg.api_key:
            encoded = base64.b64encode(cfg.api_key.encode()).decode()
            return {"Authorization": f"ApiKey {encoded}"}
        if cfg.username and cfg.password:
            creds = base64.b64encode(f"{cfg.username}:{cfg.password}".encode()).decode()
            return {"Authorization": f"Basic {creds}"}
        return {}

    async def disconnect(self) -> None:
        """Close underlying HTTP clients."""
        if self._es_client:
            await self._es_client.aclose()
            self._es_client = None
        if self._kibana_client:
            await self._kibana_client.aclose()
            self._kibana_client = None

    # ── AbstractConnector compat ───────────────────────────────────────────────

    async def connect(self, base_url: str, credentials: dict[str, str]) -> bool:
        cfg = self._config
        if "api_key" in credentials:
            object.__setattr__(cfg, "api_key", credentials["api_key"])
        if "username" in credentials:
            object.__setattr__(cfg, "username", credentials["username"])
        if "password" in credentials:
            object.__setattr__(cfg, "password", credentials["password"])
        await self._init_clients()
        info = await self.test_connection()
        return info.get("healthy", False)

    async def pull_rules(self) -> list[dict[str, Any]]:
        """Return Kibana detection rules."""
        return await self._list_kibana_rules()

    async def push_logs(self, events: list[dict[str, Any]], index: str = "") -> bool:
        idx = index or self._config.index
        sent = await self.send_events(events, index=idx)
        return sent == len(events)

    async def health_check(self) -> bool:
        info = await self.test_connection()
        return info.get("healthy", False)

    # ── Ingest ────────────────────────────────────────────────────────────────

    async def send_events(
        self,
        events: list[dict[str, Any]],
        index: str | None = None,
    ) -> int:
        """POST events to /_bulk endpoint in batches.

        Each event is indexed with an "index" action. Events that already contain
        an "_id" field will use it; otherwise Elasticsearch auto-generates IDs.

        Args:
            events: List of event dicts.
            index: Target index (default: config.index).

        Returns:
            Number of events successfully indexed.
        """
        if not events:
            return 0

        cfg = self._config
        idx = index or cfg.index
        await self.create_index_if_missing(idx)

        accepted = 0
        for batch_start in range(0, len(events), _BULK_BATCH_SIZE):
            batch = events[batch_start : batch_start + _BULK_BATCH_SIZE]
            lines: list[str] = []
            for evt in batch:
                doc_id = evt.pop("_id", None)
                action: dict[str, Any] = {"_index": idx}
                if doc_id:
                    action["_id"] = doc_id
                lines.append(json.dumps({"index": action}, default=str))
                lines.append(json.dumps(evt, default=str))
            # Bulk payload must end with newline
            payload = "\n".join(lines) + "\n"

            try:
                resp = await self._es_request(
                    "POST",
                    "/_bulk",
                    content=payload,
                    headers={"Content-Type": "application/x-ndjson"},
                )
                body = resp.json()
                if body.get("errors"):
                    errors = [
                        item["index"]["error"]
                        for item in body.get("items", [])
                        if "error" in item.get("index", {})
                    ]
                    logger.warning(
                        "Bulk batch %d had %d errors (first: %s)",
                        batch_start, len(errors),
                        errors[0] if errors else "unknown",
                    )
                    accepted += len(batch) - len(errors)
                else:
                    accepted += len(batch)
                    logger.debug("Bulk accepted %d events (batch %d+)", len(batch), batch_start)
            except Exception as exc:
                logger.error("send_events bulk error: %s", exc)

        return accepted

    # ── Search ────────────────────────────────────────────────────────────────

    async def search(
        self,
        query_dsl: dict[str, Any],
        index: str | None = None,
        size: int = 100,
    ) -> dict[str, Any]:
        """POST a DSL search and return the full response.

        Args:
            query_dsl: Elasticsearch Query DSL dict.
            index: Index pattern to search (default: config.index).
            size: Maximum hits to return.

        Returns:
            Full Elasticsearch response dict including hits, aggregations, etc.
        """
        idx = index or self._config.index
        body = {**query_dsl}
        if "size" not in body:
            body["size"] = size

        try:
            resp = await self._es_request("POST", f"/{idx}/_search", json=body)
            return resp.json()
        except Exception as exc:
            logger.error("search failed on index '%s': %s", idx, exc)
            return {"error": str(exc), "hits": {"total": {"value": 0}, "hits": []}}

    # ── Cluster / Index Management ────────────────────────────────────────────

    async def test_connection(self) -> dict[str, Any]:
        """GET / for cluster info and health.

        Returns:
            Dict with keys: healthy, cluster_name, version, status.
        """
        try:
            resp = await self._es_request("GET", "/")
            body = resp.json()
            health_resp = await self._es_request("GET", "/_cluster/health")
            health = health_resp.json()
            return {
                "healthy": True,
                "cluster_name": body.get("cluster_name", "unknown"),
                "version": body.get("version", {}).get("number", "unknown"),
                "tagline": body.get("tagline", ""),
                "status": health.get("status", "unknown"),
                "number_of_nodes": health.get("number_of_nodes", 0),
                "active_shards": health.get("active_shards", 0),
            }
        except Exception as exc:
            logger.error("test_connection failed: %s", exc)
            return {"healthy": False, "error": str(exc)}

    async def get_indices(self) -> list[dict[str, Any]]:
        """GET /_cat/indices and return parsed index information.

        Returns:
            List of dicts with keys: index, health, status, docs_count, store_size.
        """
        try:
            resp = await self._es_request(
                "GET", "/_cat/indices", params={"format": "json", "bytes": "mb"}
            )
            indices = resp.json()
            return [
                {
                    "index": idx.get("index", ""),
                    "health": idx.get("health", ""),
                    "status": idx.get("status", ""),
                    "docs_count": idx.get("docs.count", 0),
                    "docs_deleted": idx.get("docs.deleted", 0),
                    "store_size_mb": idx.get("store.size", "0"),
                    "pri": idx.get("pri", 0),
                    "rep": idx.get("rep", 0),
                }
                for idx in indices
                if isinstance(idx, dict)
            ]
        except Exception as exc:
            logger.error("get_indices failed: %s", exc)
            return []

    async def create_index_if_missing(self, index: str) -> bool:
        """PUT /{index} with PurpleLab mappings if it does not already exist.

        Args:
            index: Index name to create.

        Returns:
            True if index exists (or was created), False on error.
        """
        await self._ensure_clients()
        try:
            head_resp = await self._es_client.head(f"/{index}")  # type: ignore[union-attr]
            if head_resp.status_code == 200:
                return True  # already exists
        except Exception:
            pass  # fall through to create

        try:
            resp = await self._es_request("PUT", f"/{index}", json=_PURPLELAB_MAPPINGS)
            if resp.status_code in (200, 201):
                logger.info("Created index '%s'.", index)
                return True
            logger.warning(
                "create_index_if_missing '%s': unexpected status %d %s",
                index, resp.status_code, resp.text[:200],
            )
            return False
        except Exception as exc:
            logger.error("create_index_if_missing '%s' failed: %s", index, exc)
            return False

    # ── Kibana Detection Rules ────────────────────────────────────────────────

    async def push_rule(
        self,
        rule_name: str,
        kql_query: str,
        index_pattern: str | None = None,
        severity: str = "medium",
        risk_score: int = 47,
        description: str = "",
        tags: list[str] | None = None,
        mitre_tactics: list[str] | None = None,
    ) -> bool:
        """Create or update a Kibana detection rule via the Detection Engine API.

        Args:
            rule_name: Human-readable rule name.
            kql_query: KQL query string for the rule.
            index_pattern: Index patterns to search (default: config.index).
            severity: low / medium / high / critical.
            risk_score: 0–100 Kibana risk score.
            description: Rule description.
            tags: Optional list of tags.
            mitre_tactics: Optional list of MITRE tactic strings.

        Returns:
            True if rule was created/updated successfully.
        """
        rule_id = rule_name.lower().replace(" ", "-").replace("_", "-")
        idx_patterns = [index_pattern or self._config.index]
        payload: dict[str, Any] = {
            "type": "query",
            "language": "kuery",
            "query": kql_query,
            "name": rule_name,
            "description": description or f"PurpleLab detection rule: {rule_name}",
            "risk_score": risk_score,
            "severity": severity,
            "enabled": True,
            "index": idx_patterns,
            "rule_id": rule_id,
            "tags": tags or ["purplelab"],
            "from": "now-6m",
            "interval": "5m",
        }
        if mitre_tactics:
            payload["threat"] = [
                {"framework": "MITRE ATT&CK", "tactic": {"name": t, "id": "", "reference": ""}}
                for t in mitre_tactics
            ]

        try:
            # Try update first (PUT), fall back to create (POST)
            put_resp = await self._kibana_request(
                "PUT",
                f"/api/detection_engine/rules?rule_id={rule_id}",
                json=payload,
            )
            if put_resp.status_code in (200, 201):
                logger.info("push_rule: Kibana rule '%s' upserted.", rule_name)
                return True

            # Rule doesn't exist yet — create it
            post_resp = await self._kibana_request(
                "POST", "/api/detection_engine/rules", json=payload
            )
            if post_resp.status_code in (200, 201):
                logger.info("push_rule: Kibana rule '%s' created.", rule_name)
                return True

            logger.warning(
                "push_rule failed for '%s': %s %s",
                rule_name, post_resp.status_code, post_resp.text[:200],
            )
            return False
        except Exception as exc:
            logger.error("push_rule error for '%s': %s", rule_name, exc)
            return False

    async def _list_kibana_rules(self) -> list[dict[str, Any]]:
        """List all Kibana detection rules."""
        try:
            resp = await self._kibana_request(
                "GET",
                "/api/detection_engine/rules/_find",
                params={"per_page": "200"},
            )
            body = resp.json()
            return [
                {
                    "name": r.get("name", ""),
                    "rule_id": r.get("rule_id", ""),
                    "type": r.get("type", ""),
                    "query": r.get("query", ""),
                    "severity": r.get("severity", ""),
                    "risk_score": r.get("risk_score", 0),
                    "enabled": r.get("enabled", False),
                    "tags": r.get("tags", []),
                    "updated_at": r.get("updated_at", ""),
                }
                for r in body.get("data", [])
            ]
        except Exception as exc:
            logger.error("_list_kibana_rules failed: %s", exc)
            return []

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _ensure_clients(self) -> None:
        if self._es_client is None or self._kibana_client is None:
            await self._init_clients()

    async def _es_request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        await self._ensure_clients()
        return await self._request_with_retry(self._es_client, method, path, **kwargs)  # type: ignore[arg-type]

    async def _kibana_request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        await self._ensure_clients()
        return await self._request_with_retry(self._kibana_client, method, path, **kwargs)  # type: ignore[arg-type]

    @staticmethod
    async def _request_with_retry(
        client: httpx.AsyncClient,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Execute request with up to 3 retries, honouring Retry-After on 429."""
        delay = 1.0
        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                resp = await client.request(method, path, **kwargs)
                if resp.status_code == 429:
                    retry_after = resp.headers.get("Retry-After")
                    wait = float(retry_after) if retry_after else delay
                    logger.warning(
                        "Elastic 429 on %s %s; retrying in %.1fs (attempt %d/%d)",
                        method, path, wait, attempt + 1, _MAX_RETRIES,
                    )
                    if attempt < _MAX_RETRIES:
                        await asyncio.sleep(wait)
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
                        "Elastic request error attempt %d/%d: %s; retrying in %.1fs",
                        attempt + 1, _MAX_RETRIES, exc, delay,
                    )
                    await asyncio.sleep(delay)
                    delay *= 2
        raise last_exc or RuntimeError("Request failed after retries")
