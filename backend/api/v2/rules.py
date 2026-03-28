"""Detection rule endpoints for v2 API.

Manages imported detection rules -- import from file upload or direct
text input, test rules against log datasets, and analyze MITRE coverage.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException
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


class RuleTestRequest(BaseModel):
    """Request to test rules against log data."""
    rule_ids: list[str] = Field(default_factory=list)
    logs: list[dict[str, Any]] = Field(default_factory=list)
    field_mapping: dict[str, str] = Field(default_factory=dict)


class CoverageRequest(BaseModel):
    """Request for coverage analysis."""
    rule_ids: list[str] = Field(default_factory=list)
    actor_techniques: list[str] = Field(default_factory=list)


# ── Endpoints ───────────────────────────────────────────────────────────

@router.get("")
async def list_rules(
    language: str | None = None,
    severity: str | None = None,
    technique: str | None = None,
    offset: int = 0,
    limit: int = 50,
):
    """List all imported detection rules.

    Supports filtering by language, severity, and MITRE technique.
    Returns paginated results.

    Args:
        language: Filter by rule language (sigma, spl, kql, esql).
        severity: Filter by severity (low, medium, high, critical).
        technique: Filter by MITRE technique ID (e.g., T1059.001).
        offset: Pagination offset.
        limit: Max results per page.

    Returns:
        Dict with rules list and total count.
    """
    rules = list(_rule_store.values())

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

    total = len(rules)
    rules = rules[offset : offset + limit]

    return {"rules": rules, "total": total, "offset": offset, "limit": limit}


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
        rule_id = str(uuid.uuid4())
        rule_data = {
            "id": rule_id,
            "name": rule.name or f"Rule-{rule_id[:8]}",
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
        }
        _rule_store[rule_id] = rule_data
        imported.append(rule_data)

    return {
        "imported": len(imported),
        "errors": [],
        "rules": imported,
    }


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

    allowed_fields = {"name", "severity", "description", "tags", "mitre_techniques"}
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
