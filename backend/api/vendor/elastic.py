"""Elastic Security / Elasticsearch API emulation.

Mimics the Elastic REST API so Joti's Elastic SIEM connector can
search events and manage detection rules.

Key endpoints:
  GET  /                             cluster info (auth check)
  POST /_security/oauth2/token       API key auth
  POST /{index}/_search              search events
  GET  /api/detection_engine/rules   list detection rules
  POST /api/detection_engine/rules   create rule
  DELETE /api/detection_engine/rules delete rule
  POST /api/detection_engine/rules/_bulk_create bulk create
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional, Any

from fastapi import APIRouter, Body, Header, Query

router = APIRouter(prefix="/api/vendor/elastic", tags=["vendor:elastic"])

_FAKE_API_KEY = "ZWxhc3RpYy1zaW0ta2V5OmZha2U=" + uuid.uuid4().hex[:8]

_deployed_rules: dict[str, dict] = {}


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sample_hit(technique_id: str = "T1059.001", source_type: str = "endpoint") -> dict:
    return {
        "_index": f"logs-{source_type}.events",
        "_id": uuid.uuid4().hex,
        "_score": 1.0,
        "_source": {
            "@timestamp": _ts(),
            "event.category": ["process"],
            "event.type": ["start"],
            "process.name": "powershell.exe",
            "process.command_line": "powershell -enc <base64>",
            "host.hostname": "CORP-WS-01",
            "user.name": "jsmith",
            "threat.technique.id": [technique_id],
            "agent.type": "endpoint",
        },
    }


# ── Cluster / Auth ────────────────────────────────────────────────────────────

@router.get("/")
async def cluster_info():
    return {
        "name": "purplelab-sim",
        "cluster_name": "purplelab",
        "cluster_uuid": str(uuid.uuid4()),
        "version": {"number": "8.13.0", "lucene_version": "9.10.0"},
        "tagline": "You Know, for Search",
    }


@router.post("/_security/oauth2/token")
async def get_token():
    return {
        "access_token": _FAKE_API_KEY,
        "type": "Bearer",
        "expires_in": 1200,
    }


@router.post("/_security/api_key")
async def create_api_key(body: dict = Body(default={})):
    return {
        "id": uuid.uuid4().hex[:16],
        "name": body.get("name", "sim-key"),
        "api_key": uuid.uuid4().hex,
        "encoded": _FAKE_API_KEY,
    }


# ── Event search ──────────────────────────────────────────────────────────────

@router.post("/{index}/_search")
async def search_events(
    index: str,
    body: dict = Body(default={}),
    session_id: Optional[str] = Query(None),
):
    """KQL/EQL/Lucene search against simulated events."""
    from backend.db.session import async_session
    from backend.db.models import GeneratedEvent
    from sqlalchemy import select as _select
    import uuid as _uuid

    query_val = body.get("query", {})
    size = body.get("size", 20)
    hits: list[dict] = []

    # Extract keyword from query object (simplified)
    keyword = ""
    if isinstance(query_val, dict):
        match = query_val.get("match_all") or query_val.get("match") or {}
        keyword = str(match).lower() if match else ""
        # Check for term/match_phrase
        for key in ("query_string", "term", "match_phrase"):
            if key in query_val:
                keyword = str(query_val[key]).lower()
                break

    if session_id:
        try:
            async with async_session() as db:
                q = (_select(GeneratedEvent)
                     .where(GeneratedEvent.session_id == _uuid.UUID(session_id))
                     .order_by(GeneratedEvent.created_at.desc())
                     .limit(size * 3))
                rows = (await db.execute(q)).scalars().all()

            for row in rows:
                payload = row.payload or {}
                text = (row.title or "") + str(payload)
                if not keyword or keyword in text.lower():
                    hits.append({
                        "_index": index,
                        "_id": str(row.id),
                        "_score": 1.0,
                        "_source": {
                            "@timestamp": row.created_at.isoformat() if row.created_at else _ts(),
                            "event.category": [row.product_type or "generic"],
                            "event.severity_label": row.severity,
                            "host.hostname": payload.get("ComputerName", payload.get("Computer", "CORP-WS-01")),
                            "threat.technique.id": [row.title] if row.title and row.title.startswith("T") else [],
                            "message": payload.get("event_title", row.title or ""),
                            "labels": payload,
                        },
                    })
                    if len(hits) >= size:
                        break
        except Exception:
            pass

    # Seed synthetic hits if empty
    if not hits:
        hits = [_sample_hit()]

    return {
        "took": 5,
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "failed": 0},
        "hits": {
            "total": {"value": len(hits), "relation": "eq"},
            "hits": hits[:size],
        },
    }


# ── Detection rules (Kibana Security API) ────────────────────────────────────

@router.get("/api/detection_engine/rules/_find")
async def list_rules(page: int = 1, per_page: int = 20):
    rules = list(_deployed_rules.values())
    return {
        "page": page, "per_page": per_page,
        "total": len(rules),
        "data": rules[(page - 1) * per_page: page * per_page],
    }


@router.get("/api/detection_engine/rules")
async def get_rule(rule_id: Optional[str] = Query(None)):
    if rule_id and rule_id in _deployed_rules:
        return _deployed_rules[rule_id]
    return {"message": "Rule not found", "status_code": 404}


@router.post("/api/detection_engine/rules")
async def create_rule(body: dict = Body(default={})):
    rule_id = str(uuid.uuid4())
    rule = {
        "id": rule_id,
        "rule_id": body.get("rule_id", f"purplelab-{rule_id[:8]}"),
        "name": body.get("name", "Unnamed Rule"),
        "description": body.get("description", ""),
        "type": body.get("type", "eql"),
        "query": body.get("query", ""),
        "language": body.get("language", "eql"),
        "severity": body.get("severity", "medium"),
        "risk_score": body.get("risk_score", 47),
        "enabled": body.get("enabled", True),
        "tags": body.get("tags", []),
        "threat": body.get("threat", []),
        "created_at": _ts(),
        "updated_at": _ts(),
        "created_by": "purplelab",
        "updated_by": "purplelab",
        "version": 1,
        "immutable": False,
    }
    _deployed_rules[rule_id] = rule
    return rule


@router.put("/api/detection_engine/rules")
async def update_rule(body: dict = Body(default={})):
    rule_id = body.get("id") or body.get("rule_id")
    existing = _deployed_rules.get(rule_id)
    if not existing:
        return create_rule(body)
    existing.update({k: v for k, v in body.items() if k not in ("id", "created_at")})
    existing["updated_at"] = _ts()
    existing["version"] = existing.get("version", 1) + 1
    return existing


@router.delete("/api/detection_engine/rules")
async def delete_rule(rule_id: Optional[str] = Query(None)):
    if rule_id and rule_id in _deployed_rules:
        del _deployed_rules[rule_id]
        return {"id": rule_id}
    return {"message": "Rule not found"}


@router.post("/api/detection_engine/rules/_bulk_create")
async def bulk_create_rules(body: list = Body(default=[])):
    created = []
    for rule_def in body:
        rule_id = str(uuid.uuid4())
        rule = {**rule_def, "id": rule_id, "created_at": _ts(),
                "updated_at": _ts(), "version": 1, "immutable": False}
        _deployed_rules[rule_id] = rule
        created.append(rule)
    return {"rules": created, "errors": []}


@router.post("/api/detection_engine/rules/preview")
async def preview_rule(body: dict = Body(default={})):
    return {
        "preview_id": uuid.uuid4().hex,
        "logs": [{"duration_ms": 42, "hits": 3, "message": "Rule preview complete"}],
    }
