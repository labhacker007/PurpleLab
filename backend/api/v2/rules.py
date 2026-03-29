"""Detection rule endpoints for v2 API.

Manages imported detection rules -- import from file upload or direct
text input, test rules against log datasets, and analyze MITRE coverage.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import yaml
from fastapi import APIRouter, HTTPException, UploadFile, File, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from backend.core.schemas import StatusResponse
from backend.detection.coverage import CoverageAnalyzer
from backend.detection.rule_manager import RuleManager

log = logging.getLogger(__name__)

router = APIRouter(prefix="/rules", tags=["rules"])

# ── In-memory storage (will be replaced by DB in production) ────────────
_rule_store: dict[str, dict[str, Any]] = {}
_test_runs: dict[str, dict[str, Any]] = {}

# Shared instances
_rule_manager = RuleManager()
_coverage_analyzer = CoverageAnalyzer()


# ── Request/Response Models ─────────────────────────────────────────────

class RuleImportRequest(BaseModel):
    """Request to import detection rules from text."""
    content: str
    language: str = "auto"  # "sigma", "spl", "kql", "esql", or "auto"
    name: str = ""
    description: str = ""
    severity: str = ""


class BulkRuleItem(BaseModel):
    """Single rule entry for bulk import."""
    name: str = ""
    content: str
    format: str = "auto"


class BulkImportRequest(BaseModel):
    """Request to import up to 100 rules at once."""
    rules: list[BulkRuleItem] = Field(max_length=100)


class RuleTestRequest(BaseModel):
    """Request to test rules against log data."""
    rule_ids: list[str] = Field(default_factory=list)
    logs: list[dict[str, Any]] = Field(default_factory=list)
    field_mapping: dict[str, str] = Field(default_factory=dict)


class SingleEventTestRequest(BaseModel):
    """Request to test a single rule against one event."""
    event: dict[str, Any]


class BatchValidateRequest(BaseModel):
    """Request to validate rules without importing."""
    rule_ids: list[str] = Field(default_factory=list)
    rules: list[BulkRuleItem] = Field(default_factory=list)


class CoverageRequest(BaseModel):
    """Request for coverage analysis."""
    rule_ids: list[str] = Field(default_factory=list)
    actor_techniques: list[str] = Field(default_factory=list)


# ── Helpers ─────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rule_from_parsed(rule, rule_id: str | None = None) -> dict[str, Any]:
    """Convert a ParsedRule to the stored dict format."""
    rid = rule_id or str(uuid.uuid4())
    return {
        "id": rid,
        "name": rule.name or f"Rule-{rid[:8]}",
        "language": rule.source_language,
        "severity": rule.severity,
        "description": rule.description,
        "mitre_techniques": rule.mitre_techniques,
        "data_sources": rule.data_sources,
        "tags": rule.tags,
        "referenced_fields": sorted(rule.referenced_fields),
        "raw_text": rule.raw_text,
        "has_filter": rule.filter is not None,
        "has_aggregation": rule.aggregation is not None,
        "enabled": True,
        "created_at": _now_iso(),
    }


def _apply_list_filters(
    rules: list[dict[str, Any]],
    language: str | None,
    severity: str | None,
    technique: str | None,
    tag: str | None,
    technique_id: str | None,
    has_mitre: bool | None,
    sort: str,
) -> list[dict[str, Any]]:
    """Apply all filter and sort params to a list of rule dicts."""
    if language:
        rules = [r for r in rules if r.get("language") == language]
    if severity:
        rules = [r for r in rules if r.get("severity") == severity]
    if technique:
        tech_upper = technique.upper()
        rules = [
            r for r in rules
            if tech_upper in [t.upper() for t in r.get("mitre_techniques", [])]
        ]
    if tag:
        rules = [r for r in rules if tag.lower() in [t.lower() for t in r.get("tags", [])]]
    if technique_id:
        tid_upper = technique_id.upper()
        rules = [
            r for r in rules
            if tid_upper in [t.upper() for t in r.get("mitre_techniques", [])]
        ]
    if has_mitre is not None:
        if has_mitre:
            rules = [r for r in rules if r.get("mitre_techniques")]
        else:
            rules = [r for r in rules if not r.get("mitre_techniques")]

    # Sort
    if sort == "name_asc":
        rules = sorted(rules, key=lambda r: r.get("name", "").lower())
    elif sort == "severity_desc":
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        rules = sorted(rules, key=lambda r: sev_order.get(r.get("severity", ""), 99))
    else:
        # created_at_desc (default)
        rules = sorted(rules, key=lambda r: r.get("created_at", ""), reverse=True)

    return rules


# ── Endpoints ───────────────────────────────────────────────────────────

@router.get("")
async def list_rules(
    language: str | None = None,
    severity: str | None = None,
    technique: str | None = None,
    tag: str | None = None,
    technique_id: str | None = None,
    has_mitre: bool | None = None,
    sort: str = "created_at_desc",
    offset: int = 0,
    limit: int = 50,
):
    """List all imported detection rules.

    Supports filtering by language, severity, MITRE technique, tag, and more.
    Returns paginated results.

    Args:
        language: Filter by rule language (sigma, spl, kql, esql).
        severity: Filter by severity (low, medium, high, critical).
        technique: Filter by MITRE technique ID (e.g., T1059.001).
        tag: Filter by tag value (exact match, case-insensitive).
        technique_id: Alias for technique -- checks mitre_techniques list.
        has_mitre: True = only rules with MITRE tags; False = rules without.
        sort: Sort order: created_at_desc (default), name_asc, severity_desc.
        offset: Pagination offset.
        limit: Max results per page.

    Returns:
        Dict with rules list and total count.
    """
    rules = list(_rule_store.values())
    rules = _apply_list_filters(rules, language, severity, technique, tag, technique_id, has_mitre, sort)
    total = len(rules)
    rules = rules[offset: offset + limit]
    return {"rules": rules, "total": total, "offset": offset, "limit": limit}


@router.get("/stats")
async def get_rule_stats():
    """Return aggregate statistics for the rule store.

    Returns:
        Dict with counts broken down by format, severity, enabled status,
        and MITRE tag presence.
    """
    rules = list(_rule_store.values())
    total = len(rules)

    by_format: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    enabled_count = 0
    with_mitre = 0

    for r in rules:
        lang = r.get("language", "unknown")
        by_format[lang] = by_format.get(lang, 0) + 1

        sev = r.get("severity", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1

        if r.get("enabled", True):
            enabled_count += 1
        if r.get("mitre_techniques"):
            with_mitre += 1

    return {
        "total": total,
        "by_format": by_format,
        "by_severity": by_severity,
        "enabled_count": enabled_count,
        "with_mitre_tags": with_mitre,
    }


@router.get("/export")
async def export_rules(
    format: str = Query("sigma", pattern="^(sigma|json|csv)$"),
    ids: str | None = None,
):
    """Export rules as a downloadable file.

    Args:
        format: Output format -- sigma (YAML array), json (JSON array), or csv.
        ids: Comma-separated rule IDs. Defaults to all enabled rules.

    Returns:
        Streaming file download with Content-Disposition attachment header.
    """
    if ids:
        id_list = [i.strip() for i in ids.split(",") if i.strip()]
        rules = [_rule_store[rid] for rid in id_list if rid in _rule_store]
    else:
        rules = [r for r in _rule_store.values() if r.get("enabled", True)]

    if not rules:
        raise HTTPException(status_code=404, detail="No matching rules found for export")

    if format == "sigma":
        # Build YAML documents separated by ---
        docs = []
        for r in rules:
            # If we have the raw Sigma text, use it directly
            if r.get("language") == "sigma" and r.get("raw_text"):
                docs.append(r["raw_text"].strip())
            else:
                # Synthesise a minimal Sigma-shaped YAML
                doc = {
                    "title": r.get("name", ""),
                    "description": r.get("description", ""),
                    "level": r.get("severity", "medium"),
                    "tags": r.get("tags", []),
                    "detection": {"selection": {}, "condition": "selection"},
                }
                docs.append(yaml.dump(doc, default_flow_style=False).strip())
        content = "\n---\n".join(docs)
        media_type = "application/x-yaml"
        filename = "rules_export.yml"

    elif format == "json":
        content = json.dumps(rules, indent=2, default=str)
        media_type = "application/json"
        filename = "rules_export.json"

    else:  # csv
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["id", "name", "format", "severity", "tags", "created_at"])
        for r in rules:
            writer.writerow([
                r.get("id", ""),
                r.get("name", ""),
                r.get("language", ""),
                r.get("severity", ""),
                "|".join(r.get("tags", [])),
                r.get("created_at", ""),
            ])
        content = buf.getvalue()
        media_type = "text/csv"
        filename = "rules_export.csv"

    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(
        io.BytesIO(content.encode("utf-8")),
        media_type=media_type,
        headers=headers,
    )


@router.post("/import")
async def import_rules(request: RuleImportRequest):
    """Import detection rules from text content.

    Parses the provided rule text using the specified (or auto-detected)
    language parser. Rules are stored in memory and assigned unique IDs.

    Args:
        request: Import request with rule content and language.

    Returns:
        Dict with imported rule count, errors, and rule details.
    """
    try:
        kwargs = {}
        if request.name:
            kwargs["name"] = request.name
        if request.description:
            kwargs["description"] = request.description
        if request.severity:
            kwargs["severity"] = request.severity

        parsed_rules = await _rule_manager.import_rules(
            request.content, request.language, **kwargs
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    imported: list[dict[str, Any]] = []
    for rule in parsed_rules:
        rule_data = _rule_from_parsed(rule)
        _rule_store[rule_data["id"]] = rule_data
        imported.append(rule_data)

    return {
        "imported": len(imported),
        "errors": [],
        "rules": imported,
    }


@router.post("/import/bulk")
async def import_rules_bulk(request: BulkImportRequest):
    """Import up to 100 rules at once from an array payload.

    Each item must have a content field. The format (language) can be
    "auto" (default) or an explicit language name.

    Args:
        request: Bulk import request with list of {name, content, format}.

    Returns:
        Dict with imported count and per-index failures.
    """
    if len(request.rules) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 rules per bulk import")

    imported_count = 0
    failed: list[dict[str, Any]] = []

    for idx, item in enumerate(request.rules):
        try:
            kwargs: dict[str, str] = {}
            if item.name:
                kwargs["name"] = item.name
            parsed_rules = await _rule_manager.import_rules(item.content, item.format, **kwargs)
            for rule in parsed_rules:
                rule_data = _rule_from_parsed(rule)
                _rule_store[rule_data["id"]] = rule_data
                imported_count += 1
        except Exception as exc:
            failed.append({"index": idx, "error": str(exc)})

    return {"imported": imported_count, "failed": failed}


@router.post("/import/file")
async def import_rules_file(file: UploadFile = File(...)):
    """Import rules from a multipart file upload.

    Accepts .yml/.yaml (Sigma), .json (array of rule objects or raw strings),
    .txt (sections separated by ---). Format is auto-detected from the file
    extension and content.

    Args:
        file: Uploaded file.

    Returns:
        Dict with imported, failed, and total counts.
    """
    filename = file.filename or ""
    raw_bytes = await file.read()
    try:
        content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded")

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    imported_count = 0
    failed: list[dict[str, Any]] = []
    sections: list[str] = []

    if ext in ("yml", "yaml"):
        # YAML file -- split on document separators
        sections = [s.strip() for s in content.split("---") if s.strip()]
    elif ext == "json":
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}")
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    sections.append(item)
                elif isinstance(item, dict):
                    # Allow {content: "...", format: "..."}
                    sections.append(item.get("content", json.dumps(item)))
        elif isinstance(data, dict):
            sections = [json.dumps(data)]
        else:
            raise HTTPException(status_code=400, detail="JSON must be an array or object")
    else:
        # Plain text -- split on --- separators
        sections = [s.strip() for s in content.split("---") if s.strip()]

    total = len(sections)

    for idx, section in enumerate(sections):
        try:
            parsed_rules = await _rule_manager.import_rules(section, "auto")
            for rule in parsed_rules:
                rule_data = _rule_from_parsed(rule)
                _rule_store[rule_data["id"]] = rule_data
                imported_count += 1
        except Exception as exc:
            failed.append({"index": idx, "error": str(exc)})

    return {"imported": imported_count, "failed": failed, "total": total}


@router.post("/validate/batch")
async def validate_rules_batch(request: BatchValidateRequest):
    """Validate rules without importing them.

    Accepts either a list of existing rule IDs or inline {content, format}
    objects. Each rule is run through the parser and the result is returned
    per-rule.

    Args:
        request: Validation request with rule_ids OR rules list.

    Returns:
        List of per-rule {valid, errors, warnings} dicts.
    """
    results: list[dict[str, Any]] = []

    if request.rule_ids:
        for rid in request.rule_ids:
            rule_data = _rule_store.get(rid)
            if not rule_data:
                results.append({"rule_id": rid, "valid": False, "errors": ["Rule not found"], "warnings": []})
                continue
            try:
                await _rule_manager.import_rules(rule_data["raw_text"], rule_data["language"])
                results.append({"rule_id": rid, "name": rule_data.get("name"), "valid": True, "errors": [], "warnings": []})
            except Exception as exc:
                results.append({"rule_id": rid, "name": rule_data.get("name"), "valid": False, "errors": [str(exc)], "warnings": []})

    elif request.rules:
        for idx, item in enumerate(request.rules):
            try:
                await _rule_manager.import_rules(item.content, item.format)
                results.append({"index": idx, "name": item.name or None, "valid": True, "errors": [], "warnings": []})
            except Exception as exc:
                results.append({"index": idx, "name": item.name or None, "valid": False, "errors": [str(exc)], "warnings": []})
    else:
        raise HTTPException(status_code=400, detail="Provide rule_ids or rules")

    valid_count = sum(1 for r in results if r["valid"])
    return {
        "results": results,
        "valid": valid_count,
        "invalid": len(results) - valid_count,
    }


@router.post("/test")
async def test_rules(request: RuleTestRequest):
    """Test detection rules against provided log data.

    Evaluates each specified rule (or all rules if none specified)
    against the provided log entries. Returns per-rule match results
    and aggregate statistics.

    Args:
        request: Test request with rule IDs and log entries.

    Returns:
        Test run results with per-rule details and coverage metrics.
    """
    if not request.logs:
        raise HTTPException(status_code=400, detail="No log data provided")

    # Determine which rules to test
    if request.rule_ids:
        rules_to_test = []
        for rid in request.rule_ids:
            rule_data = _rule_store.get(rid)
            if not rule_data:
                raise HTTPException(status_code=404, detail=f"Rule {rid} not found")
            rules_to_test.append(rule_data)
    else:
        rules_to_test = list(_rule_store.values())

    if not rules_to_test:
        raise HTTPException(status_code=400, detail="No rules to test")

    # Re-parse rules from stored raw text
    manager = RuleManager(field_mapping=request.field_mapping or None)
    parsed_rules = []
    for rule_data in rules_to_test:
        try:
            parsed = await manager.import_rules(
                rule_data["raw_text"], rule_data["language"]
            )
            parsed_rules.extend(parsed)
        except Exception as exc:
            log.warning("Could not re-parse rule %s: %s", rule_data["id"], exc)

    if not parsed_rules:
        raise HTTPException(status_code=400, detail="No rules could be parsed for testing")

    # Run evaluation
    batch_result = await manager.batch_evaluate(parsed_rules, request.logs)

    # Store test run
    test_run_id = str(uuid.uuid4())
    test_run = {
        "id": test_run_id,
        "status": "completed",
        "total_rules": batch_result.total_rules,
        "rules_fired": batch_result.rules_fired,
        "rules_silent": batch_result.rules_silent,
        "total_time_ms": batch_result.total_time_ms,
        "results": [
            {
                "rule_name": r.rule_name,
                "fired": r.fired,
                "matched_count": r.matched_count,
                "total_logs": r.total_logs,
                "evaluation_time_ms": r.evaluation_time_ms,
                "details": r.details,
                "aggregation_result": r.aggregation_result,
            }
            for r in batch_result.results
        ],
        "coverage": {
            "total_techniques_covered": batch_result.coverage.total_techniques_covered,
            "overall_coverage_pct": batch_result.coverage.overall_coverage_pct,
            "tactic_coverage": batch_result.coverage.tactic_coverage,
        } if batch_result.coverage else None,
    }
    _test_runs[test_run_id] = test_run

    return test_run


@router.get("/test/{test_run_id}")
async def get_test_run(test_run_id: str):
    """Get test run results.

    Args:
        test_run_id: The test run identifier.

    Returns:
        Full test run details.

    Raises:
        HTTPException: 404 if test run not found.
    """
    run = _test_runs.get(test_run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Test run {test_run_id} not found")
    return run


@router.post("/coverage")
async def analyze_coverage(request: CoverageRequest):
    """Analyze MITRE ATT&CK coverage for the current rule set.

    Optionally compare against a threat actor's known techniques
    to identify detection gaps.

    Args:
        request: Coverage request with optional rule IDs and actor techniques.

    Returns:
        Coverage matrix and optional gap analysis.
    """
    # Get rules to analyze
    if request.rule_ids:
        rules_to_analyze = [
            _rule_store[rid] for rid in request.rule_ids
            if rid in _rule_store
        ]
    else:
        rules_to_analyze = list(_rule_store.values())

    if not rules_to_analyze:
        return {
            "coverage": {"total_techniques_covered": 0, "overall_coverage_pct": 0},
            "gap_analysis": None,
        }

    # Re-parse rules for coverage analysis
    parsed_rules = []
    for rule_data in rules_to_analyze:
        try:
            parsed = await _rule_manager.import_rules(
                rule_data["raw_text"], rule_data["language"]
            )
            parsed_rules.extend(parsed)
        except Exception:
            pass

    matrix = _coverage_analyzer.compute_coverage(parsed_rules)

    response: dict[str, Any] = {
        "coverage": {
            "total_techniques_covered": matrix.total_techniques_covered,
            "total_rules": matrix.total_rules,
            "overall_coverage_pct": matrix.overall_coverage_pct,
            "tactic_coverage": matrix.tactic_coverage,
            "techniques": {
                tid: {
                    "technique_id": tc.technique_id,
                    "tactics": tc.tactics,
                    "rule_count": tc.rule_count,
                    "rule_names": tc.rule_names,
                }
                for tid, tc in matrix.techniques.items()
            },
        },
        "gap_analysis": None,
    }

    # Optional gap analysis
    if request.actor_techniques:
        gaps = _coverage_analyzer.identify_gaps(parsed_rules, request.actor_techniques)
        response["gap_analysis"] = {
            "actor_techniques": gaps.actor_techniques,
            "covered_techniques": gaps.covered_techniques,
            "uncovered_techniques": gaps.uncovered_techniques,
            "coverage_pct": gaps.coverage_pct,
            "recommendations": gaps.recommendations,
        }

    return response


@router.post("/detect-language")
async def detect_language(body: dict[str, str]):
    """Auto-detect the language of a detection rule.

    Args:
        body: Dict with "content" key containing the rule text.

    Returns:
        Dict with detected "language" string.
    """
    content = body.get("content", "")
    if not content:
        raise HTTPException(status_code=400, detail="No content provided")

    try:
        language = await _rule_manager.detect_language(content)
        return {"language": language}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── Per-rule CRUD (parameterised routes — must come after all literal paths) ─

@router.get("/{rule_id}")
async def get_rule(rule_id: str):
    """Get a detection rule with full details.

    Args:
        rule_id: The unique rule identifier.

    Returns:
        Full rule details including parsed metadata.

    Raises:
        HTTPException: 404 if rule not found.
    """
    rule = _rule_store.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    return rule


@router.put("/{rule_id}")
async def update_rule(rule_id: str, updates: dict[str, Any]):
    """Update a detection rule's metadata.

    Args:
        rule_id: The unique rule identifier.
        updates: Dict of fields to update (name, severity, etc.).

    Returns:
        Updated rule details.

    Raises:
        HTTPException: 404 if rule not found.
    """
    rule = _rule_store.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

    allowed_fields = {"name", "severity", "description", "tags", "mitre_techniques", "enabled"}
    for key, value in updates.items():
        if key in allowed_fields:
            rule[key] = value

    return rule


@router.delete("/{rule_id}")
async def delete_rule(rule_id: str):
    """Delete a detection rule.

    Args:
        rule_id: The unique rule identifier.

    Returns:
        Status confirmation.

    Raises:
        HTTPException: 404 if rule not found.
    """
    if rule_id not in _rule_store:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

    del _rule_store[rule_id]
    return StatusResponse(status="deleted", message=f"Rule {rule_id} deleted")


@router.post("/{rule_id}/test")
async def test_single_rule(rule_id: str, request: SingleEventTestRequest):
    """Test a single rule against one event dict.

    The event is wrapped in a single-item list and evaluated by the
    rule evaluator. This is useful for quick spot-checks without needing
    a full log dataset.

    Args:
        rule_id: The unique rule identifier.
        request: Request body containing the event dict.

    Returns:
        Dict with matched bool and detail string.

    Raises:
        HTTPException: 404 if rule not found. 400 if rule cannot be parsed.
    """
    rule_data = _rule_store.get(rule_id)
    if not rule_data:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

    try:
        parsed_rules = await _rule_manager.import_rules(
            rule_data["raw_text"], rule_data["language"]
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Rule cannot be parsed: {exc}")

    if not parsed_rules:
        raise HTTPException(status_code=400, detail="No parseable rule content")

    parsed = parsed_rules[0]
    logs = [request.event]

    try:
        results = await _rule_manager.test_rules([parsed], logs)
        result = results[0]
        return {
            "matched": result.fired,
            "match_count": result.matched_count,
            "details": result.details,
            "evaluation_time_ms": result.evaluation_time_ms,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Evaluation error: {exc}")
