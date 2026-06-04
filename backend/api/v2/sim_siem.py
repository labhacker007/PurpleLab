"""Simulated SIEM API — vendor-agnostic detection testing ground.

Provides:
  POST /sim-siem/search              — run SPL/KQL/AQL query against session events
  POST /sim-siem/deploy-detection    — push Sigma rule, auto-validate against running scenario
  GET  /sim-siem/deployed-detections — list rules deployed to a session
  DELETE /sim-siem/deployed-detections/{id} — remove a rule
  POST /sim-siem/test-detection      — run a specific detection against existing events
  GET  /sim-siem/coverage            — MITRE technique coverage heatmap for deployed rules
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from fastapi import APIRouter, Body, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(prefix="/api/v2/sim-siem", tags=["sim-siem"])


# ── Models ────────────────────────────────────────────────────────────────────

class SearchRequest(BaseModel):
    session_id: str
    query: str
    query_language: str = "spl"   # spl | kql | aql | xql | eql
    earliest_time: str = "-60m"
    latest_time: str = "now"
    limit: int = 100


class DeployDetectionRequest(BaseModel):
    session_id: Optional[str] = None
    environment_id: Optional[str] = None
    name: str
    sigma_yaml: Optional[str] = None
    query_spl: Optional[str] = None
    query_kql: Optional[str] = None
    technique_ids: list[str] = []
    run_validation: bool = True   # immediately test against existing events
    deployed_by: str = "system"


class ValidationResult(BaseModel):
    fired: bool
    matched_event_count: int
    false_positive_count: int
    tested_at: str
    matched_techniques: list[str] = []
    match_rate: float = 0.0
    details: list[dict] = []


# ── Search ────────────────────────────────────────────────────────────────────

@router.post("/search")
async def search_events(req: SearchRequest):
    """Run a vendor-agnostic search query against simulated events.

    Supports simplified SPL, KQL, AQL, and XQL — extracts keywords,
    filters by sourcetype/host, and returns matching events in a
    vendor-neutral format.
    """
    from backend.db.models import GeneratedEvent
    from backend.db.session import async_session
    from sqlalchemy import select

    minutes = _parse_time_range(req.earliest_time)
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)

    async with async_session() as db:
        q = (select(GeneratedEvent)
             .where(GeneratedEvent.session_id == uuid.UUID(req.session_id))
             .where(GeneratedEvent.created_at >= cutoff.replace(tzinfo=None))
             .order_by(GeneratedEvent.created_at.desc())
             .limit(req.limit * 3))
        rows = (await db.execute(q)).scalars().all()

    # Extract filter terms from query
    filters = _parse_query_filters(req.query, req.query_language)
    results = []
    for row in rows:
        payload = row.payload or {}
        if not _matches_filters(row, payload, filters):
            continue
        results.append(_format_event(row, payload, req.query_language))
        if len(results) >= req.limit:
            break

    return {
        "query": req.query,
        "query_language": req.query_language,
        "total_results": len(results),
        "session_id": req.session_id,
        "time_range": {"earliest": req.earliest_time, "latest": req.latest_time},
        "results": results,
    }


# ── Detection Deployment + Validation ────────────────────────────────────────

@router.post("/deploy-detection")
async def deploy_detection(req: DeployDetectionRequest):
    """Deploy a detection rule to the simulated SIEM and optionally validate it.

    If run_validation=True, immediately evaluates the rule against
    existing session events and returns whether it would have fired.
    """
    import json as _json
    from backend.db.session import async_session
    from sqlalchemy import text

    det_id = str(uuid.uuid4())
    techniques = req.technique_ids or _extract_techniques_from_sigma(req.sigma_yaml or "")

    # Parse sigma_yaml to extract SPL/KQL if not provided
    query_spl = req.query_spl
    query_kql = req.query_kql
    if req.sigma_yaml and not query_spl:
        query_spl = _sigma_to_spl_keywords(req.sigma_yaml)
    if req.sigma_yaml and not query_kql:
        query_kql = _sigma_to_kql_keywords(req.sigma_yaml)

    # Store in DB
    try:
        async with async_session() as db:
            await db.execute(text("""
                INSERT INTO deployed_detections
                    (id, session_id, environment_id, name, sigma_yaml, query_spl, query_kql, technique_ids, status, deployed_by, created_at, updated_at)
                VALUES
                    (:id::uuid, :session_id, :env_id, :name, :sigma_yaml, :query_spl, :query_kql, :technique_ids::jsonb, 'deployed', :deployed_by, now(), now())
            """), {
                "id": det_id,
                "session_id": req.session_id,
                "env_id": req.environment_id,
                "name": req.name,
                "sigma_yaml": req.sigma_yaml or "",
                "query_spl": query_spl or "",
                "query_kql": query_kql or "",
                "technique_ids": _json.dumps(techniques),
                "deployed_by": req.deployed_by,
            })
            await db.commit()
    except Exception as exc:
        pass  # non-fatal if table not yet migrated

    validation: Optional[ValidationResult] = None
    if req.run_validation and req.session_id:
        validation = await _validate_detection(
            det_id=det_id,
            session_id=req.session_id,
            sigma_yaml=req.sigma_yaml,
            query_spl=query_spl,
            technique_ids=techniques,
        )
        # Persist validation result
        try:
            async with async_session() as db:
                await db.execute(text("""
                    UPDATE deployed_detections
                    SET validation = :val::jsonb, updated_at = now()
                    WHERE id = :id::uuid
                """), {
                    "id": det_id,
                    "val": _json.dumps(validation.dict() if validation else {}),
                })
                await db.commit()
        except Exception:
            pass

    return {
        "id": det_id,
        "name": req.name,
        "technique_ids": techniques,
        "query_spl": query_spl,
        "query_kql": query_kql,
        "session_id": req.session_id,
        "validation": validation.dict() if validation else None,
        "deployed_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/deployed-detections")
async def list_deployed_detections(
    session_id: Optional[str] = Query(None),
    environment_id: Optional[str] = Query(None),
    limit: int = Query(50),
):
    from backend.db.session import async_session
    from sqlalchemy import text

    try:
        async with async_session() as db:
            filters = []
            params: dict[str, Any] = {"limit": limit}
            if session_id:
                filters.append("session_id = :session_id::uuid")
                params["session_id"] = session_id
            if environment_id:
                filters.append("environment_id = :env_id::uuid")
                params["env_id"] = environment_id

            where = ("WHERE " + " AND ".join(filters)) if filters else ""
            rows = (await db.execute(text(f"""
                SELECT id, name, technique_ids, sigma_yaml, query_spl, status, validation, deployed_by, created_at
                FROM deployed_detections {where}
                ORDER BY created_at DESC LIMIT :limit
            """), params)).fetchall()

            return {
                "detections": [
                    {
                        "id": str(r[0]),
                        "name": r[1],
                        "technique_ids": r[2] or [],
                        "has_sigma": bool(r[3]),
                        "has_spl": bool(r[4]),
                        "status": r[5],
                        "validation": r[6],
                        "deployed_by": r[7],
                        "deployed_at": r[8].isoformat() if r[8] else None,
                    }
                    for r in rows
                ],
                "total": len(rows),
            }
    except Exception as exc:
        return {"detections": [], "total": 0, "error": str(exc)}


@router.post("/test-detection/{detection_id}")
async def test_detection(
    detection_id: str,
    session_id: str = Query(...),
):
    """Re-run validation of an already-deployed detection rule."""
    from backend.db.session import async_session
    from sqlalchemy import text

    try:
        async with async_session() as db:
            row = (await db.execute(text("""
                SELECT sigma_yaml, query_spl, technique_ids FROM deployed_detections WHERE id = :id::uuid
            """), {"id": detection_id})).fetchone()
    except Exception:
        row = None

    if not row:
        raise HTTPException(404, detail="Detection not found")

    validation = await _validate_detection(
        det_id=detection_id,
        session_id=session_id,
        sigma_yaml=row[0],
        query_spl=row[1],
        technique_ids=row[2] or [],
    )
    return {"detection_id": detection_id, "session_id": session_id, "validation": validation.dict()}


@router.get("/coverage")
async def get_coverage(session_id: Optional[str] = Query(None)):
    """MITRE technique coverage heatmap from deployed detections."""
    from backend.db.session import async_session
    from sqlalchemy import text

    if not session_id:
        return {"coverage": {}, "covered_techniques": [], "total_deployed": 0}

    try:
        async with async_session() as db:
            rows = (await db.execute(text("""
                SELECT technique_ids, validation FROM deployed_detections
                WHERE session_id = :sid::uuid AND status = 'deployed'
            """), {"sid": session_id})).fetchall()
    except Exception:
        return {"coverage": {}, "covered_techniques": [], "total_deployed": 0}

    coverage: dict[str, dict] = {}
    for r in rows:
        techs = r[0] or []
        val = r[1] or {}
        for t in techs:
            if t not in coverage:
                coverage[t] = {"detected": False, "detection_count": 0, "rules": []}
            coverage[t]["detection_count"] += 1
            if val.get("fired"):
                coverage[t]["detected"] = True

    return {
        "coverage": coverage,
        "covered_techniques": list(coverage.keys()),
        "detected_techniques": [t for t, v in coverage.items() if v["detected"]],
        "total_deployed": len(rows),
    }


# ── Internal validation engine ────────────────────────────────────────────────

async def _validate_detection(
    det_id: str,
    session_id: str,
    sigma_yaml: Optional[str],
    query_spl: Optional[str],
    technique_ids: list[str],
) -> ValidationResult:
    """Test a detection rule against stored session events."""
    from backend.db.models import GeneratedEvent
    from backend.db.session import async_session
    from sqlalchemy import select

    cutoff = datetime.now(timezone.utc) - timedelta(hours=2)

    async with async_session() as db:
        rows = (await db.execute(
            select(GeneratedEvent)
            .where(GeneratedEvent.session_id == uuid.UUID(session_id))
            .where(GeneratedEvent.created_at >= cutoff.replace(tzinfo=None))
            .limit(500)
        )).scalars().all()

    # Extract keywords from Sigma or SPL
    keywords: list[str] = []
    if sigma_yaml:
        keywords = _extract_sigma_keywords(sigma_yaml)
    elif query_spl:
        keywords = _extract_spl_keywords(query_spl)

    matched_events = []
    fp_events = []
    matched_techniques: set[str] = set()

    for row in rows:
        payload = row.payload or {}
        row_text = str(payload).lower() + " " + (row.title or "").lower()

        # Check if keywords match
        if keywords:
            keyword_match = all(k.lower() in row_text for k in keywords[:5])  # match up to 5 key terms
        else:
            # Technique-based match
            keyword_match = row.title in technique_ids if technique_ids else True

        if not keyword_match:
            continue

        is_attack = payload.get("_type") in ("attack", "injected_alert") or (
            row.title and row.title.startswith("T") and len(row.title) >= 5
        )

        if is_attack:
            matched_events.append({
                "id": str(row.id),
                "technique": row.title or "",
                "source": row.product_type or "",
                "severity": row.severity or "info",
                "title": payload.get("event_title", row.title or ""),
            })
            if row.title:
                matched_techniques.add(row.title)
        else:
            fp_events.append({"id": str(row.id)})

    fired = len(matched_events) > 0
    match_rate = len(matched_events) / max(len(rows), 1)

    return ValidationResult(
        fired=fired,
        matched_event_count=len(matched_events),
        false_positive_count=len(fp_events),
        tested_at=datetime.now(timezone.utc).isoformat(),
        matched_techniques=list(matched_techniques),
        match_rate=round(match_rate, 3),
        details=matched_events[:20],
    )


# ── Query parsing helpers ──────────────────────────────────────────────────────

def _parse_time_range(earliest: str) -> int:
    """Parse '-60m', '-2h', '-1d' → minutes."""
    try:
        if earliest.endswith("m"):
            return abs(int(earliest[1:-1]))
        elif earliest.endswith("h"):
            return abs(int(earliest[1:-1])) * 60
        elif earliest.endswith("d"):
            return abs(int(earliest[1:-1])) * 1440
    except Exception:
        pass
    return 60


def _parse_query_filters(query: str, lang: str) -> dict[str, Any]:
    """Extract simple filter terms from a vendor query string."""
    filters: dict[str, Any] = {}
    q = query.lower()

    # Keywords in quotes
    filters["keywords"] = re.findall(r'"([^"]+)"', q)

    # SPL: sourcetype=X, host=X, index=X
    for field in ("sourcetype", "host", "index", "source"):
        m = re.search(rf'\b{field}\s*=\s*"?([^\s"]+)"?', q)
        if m:
            filters[field] = m.group(1)

    # KQL/AQL: technique-like patterns
    t_matches = re.findall(r"t\d{4}(?:\.\d{3})?", q, re.IGNORECASE)
    if t_matches:
        filters["techniques"] = [t.upper() for t in t_matches]

    # Severity filter
    for sev in ("critical", "high", "medium", "low"):
        if sev in q:
            filters.setdefault("severity", sev)

    return filters


def _matches_filters(row: Any, payload: dict, filters: dict) -> bool:
    text = str(payload).lower() + " " + (row.title or "").lower() + " " + (row.product_type or "").lower()

    # Keyword filter
    for kw in filters.get("keywords", []):
        if kw.lower() not in text:
            return False

    # Sourcetype filter
    if "sourcetype" in filters:
        if filters["sourcetype"] not in (row.product_type or "").lower():
            return False

    # Host filter
    if "host" in filters:
        host = payload.get("hostname") or payload.get("ComputerName") or payload.get("host") or ""
        if filters["host"].lower() not in host.lower() and filters["host"] != "*":
            return False

    # Technique filter
    for t in filters.get("techniques", []):
        if t not in (row.title or ""):
            return False

    return True


def _format_event(row: Any, payload: dict, lang: str) -> dict:
    ts = row.created_at.isoformat() if row.created_at else ""
    base = {
        "id": str(row.id),
        "timestamp": ts,
        "source_type": row.product_type or "",
        "severity": row.severity or "info",
        "technique": row.title or "",
        "title": payload.get("event_title") or payload.get("alert_name") or row.title or "",
        "hostname": payload.get("hostname") or payload.get("ComputerName") or "",
        "user": payload.get("user") or payload.get("UserName") or "",
    }
    if lang == "spl":
        base.update({"_time": ts, "host": base["hostname"], "sourcetype": row.product_type, "_raw": str(payload)})
    elif lang == "kql":
        base.update({"TimeGenerated": ts, "Computer": base["hostname"], "AlertSeverity": row.severity})
    elif lang == "aql":
        base.update({"startTime": ts, "sourceIP": payload.get("src_ip", ""), "QIDNAME": base["title"]})
    return base


def _extract_techniques_from_sigma(sigma_yaml: str) -> list[str]:
    techs = re.findall(r"T\d{4}(?:\.\d{3})?", sigma_yaml)
    return list(dict.fromkeys(techs))


def _extract_sigma_keywords(sigma_yaml: str) -> list[str]:
    """Extract detection keywords from Sigma YAML detection block."""
    keywords: list[str] = []
    in_detection = False
    for line in sigma_yaml.splitlines():
        if line.strip().startswith("detection:"):
            in_detection = True
        if in_detection and (":" in line or "-" in line):
            # Extract quoted values
            found = re.findall(r"['\"]([^'\"]{3,})['\"]", line)
            keywords.extend(found)
            # Extract unquoted values after colon
            m = re.search(r":\s+([^\s#{}]+)", line)
            if m and len(m.group(1)) > 3 and not m.group(1).startswith("$"):
                keywords.append(m.group(1))
    return [k for k in keywords[:10] if len(k) >= 3]


def _extract_spl_keywords(spl: str) -> list[str]:
    return re.findall(r'"([^"]{3,})"', spl)


def _sigma_to_spl_keywords(sigma_yaml: str) -> str:
    kws = _extract_sigma_keywords(sigma_yaml)
    techs = _extract_techniques_from_sigma(sigma_yaml)
    parts = [f'"{k}"' for k in kws[:5]]
    if techs:
        parts.append(f'technique="{techs[0]}"')
    return f"search {' '.join(parts)}" if parts else "search *"


def _sigma_to_kql_keywords(sigma_yaml: str) -> str:
    kws = _extract_sigma_keywords(sigma_yaml)
    techs = _extract_techniques_from_sigma(sigma_yaml)
    if not kws and not techs:
        return "SecurityAlert | take 100"
    parts = [f'EventData contains "{k}"' for k in kws[:3]]
    if techs:
        parts.append(f'Technique == "{techs[0]}"')
    return "SecurityEvent\n| where " + " and ".join(parts) if parts else "SecurityAlert | take 100"
