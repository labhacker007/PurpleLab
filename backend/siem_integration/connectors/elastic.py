"""Elasticsearch connector for ConnectionManager.

Credentials dict keys:
    base_url   : Elasticsearch URL, e.g. "https://elastic:9200"
    api_key    : API key in "id:key" format (preferred)
    username   : Basic auth username
    password   : Basic auth password
    index      : Target index (default "purplelab-logs")
    kibana_url : Kibana URL for rule management (default: base_url:5601)
    verify_ssl : bool (default True)
"""
from __future__ import annotations

import base64
import json
import logging
from typing import Any

import httpx

from backend.siem_integration.connectors.base import BaseSIEMConnector

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(10.0)
_BULK_BATCH = 500


def _auth_headers(creds: dict[str, Any]) -> dict[str, str]:
    api_key = creds.get("api_key", "")
    if api_key:
        encoded = base64.b64encode(api_key.encode()).decode()
        return {"Authorization": f"ApiKey {encoded}"}
    username = creds.get("username", "")
    password = creds.get("password", "")
    if username and password:
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {"Authorization": f"Basic {encoded}"}
    return {}


class ElasticConnector(BaseSIEMConnector):
    """Concrete Elasticsearch / Kibana connector."""

    def __init__(self, credentials: dict[str, Any]) -> None:
        self._creds = credentials
        base_url = (credentials.get("base_url") or "").rstrip("/")
        kibana_url = (
            credentials.get("kibana_url") or base_url.replace(":9200", ":5601")
        ).rstrip("/")
        self._index: str = credentials.get("index", "purplelab-logs")
        verify_ssl = credentials.get("verify_ssl", True)
        auth = _auth_headers(credentials)
        self._es_client = httpx.AsyncClient(
            base_url=base_url,
            headers={**auth, "Content-Type": "application/json"},
            verify=verify_ssl,
            timeout=_TIMEOUT,
        )
        self._kibana_client = httpx.AsyncClient(
            base_url=kibana_url,
            headers={**auth, "Content-Type": "application/json", "kbn-xsrf": "true"},
            verify=verify_ssl,
            timeout=_TIMEOUT,
        )

    async def close(self) -> None:
        await self._es_client.aclose()
        await self._kibana_client.aclose()

    # ── BaseSIEMConnector interface ───────────────────────────────────────────

    async def test(self) -> dict[str, Any]:
        """GET /_cluster/health to verify Elasticsearch connectivity."""
        t0 = self._timer()
        try:
            resp = await self._es_client.get("/_cluster/health")
            resp.raise_for_status()
            health = resp.json()
            # Also grab version info
            info_resp = await self._es_client.get("/")
            info = info_resp.json() if info_resp.status_code == 200 else {}
            latency = self._elapsed_ms(t0)
            version = info.get("version", {}).get("number", "")
            return {
                "success": True,
                "message": f"Connected to Elasticsearch {version}",
                "latency_ms": latency,
                "cluster_name": health.get("cluster_name", ""),
                "status": health.get("status", ""),
                "number_of_nodes": health.get("number_of_nodes", 0),
                "version": version,
            }
        except Exception as exc:
            logger.warning("ElasticConnector.test failed: %s", exc)
            return {
                "success": False,
                "message": str(exc),
                "latency_ms": self._elapsed_ms(t0),
            }

    async def push_logs(self, logs: list[dict[str, Any]]) -> int:
        """POST events via Elasticsearch _bulk API."""
        if not logs:
            return 0
        accepted = 0
        for start in range(0, len(logs), _BULK_BATCH):
            batch = logs[start : start + _BULK_BATCH]
            lines: list[str] = []
            for evt in batch:
                doc_id = evt.pop("_id", None)
                action: dict[str, Any] = {"_index": self._index}
                if doc_id:
                    action["_id"] = doc_id
                lines.append(json.dumps({"index": action}, default=str))
                lines.append(json.dumps(evt, default=str))
            payload = "\n".join(lines) + "\n"
            try:
                resp = await self._es_client.post(
                    "/_bulk",
                    content=payload,
                    headers={"Content-Type": "application/x-ndjson"},
                )
                body = resp.json()
                if body.get("errors"):
                    error_items = [
                        item["index"]["error"]
                        for item in body.get("items", [])
                        if "error" in item.get("index", {})
                    ]
                    accepted += len(batch) - len(error_items)
                    logger.warning(
                        "ElasticConnector.push_logs: %d errors in batch",
                        len(error_items),
                    )
                else:
                    accepted += len(batch)
            except Exception as exc:
                logger.error("ElasticConnector.push_logs error: %s", exc)
        return accepted

    async def push_rule(
        self,
        rule_text: str,
        rule_name: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """PUT/POST a detection rule via the Kibana Detection Engine API."""
        meta = metadata or {}
        rule_id = rule_name.lower().replace(" ", "-").replace("_", "-")
        payload: dict[str, Any] = {
            "type": "query",
            "language": "kuery",
            "query": rule_text,
            "name": rule_name,
            "description": meta.get(
                "description", f"PurpleLab detection rule: {rule_name}"
            ),
            "risk_score": meta.get("risk_score", 47),
            "severity": meta.get("severity", "medium"),
            "enabled": True,
            "index": [self._index],
            "rule_id": rule_id,
            "tags": meta.get("tags", ["purplelab"]),
            "from": "now-6m",
            "interval": "5m",
        }
        try:
            # Try update first, then create
            put_resp = await self._kibana_client.put(
                f"/api/detection_engine/rules?rule_id={rule_id}",
                json=payload,
            )
            if put_resp.status_code in (200, 201):
                return {"success": True, "message": f"Rule '{rule_name}' upserted."}

            post_resp = await self._kibana_client.post(
                "/api/detection_engine/rules",
                json=payload,
            )
            if post_resp.status_code in (200, 201):
                return {"success": True, "message": f"Rule '{rule_name}' created."}

            return {
                "success": False,
                "message": f"HTTP {post_resp.status_code}: {post_resp.text[:200]}",
            }
        except Exception as exc:
            logger.error("ElasticConnector.push_rule error: %s", exc)
            return {"success": False, "message": str(exc)}
