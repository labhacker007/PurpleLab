"""Detection rule tools for the agent orchestrator.

Provides tools for importing, parsing, testing, and analyzing
detection rules across multiple languages (Sigma, SPL, KQL, ES|QL).
"""
from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Any

from backend.agent.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


def register_tools(registry: ToolRegistry) -> None:
    """Register all detection rule tools."""

    registry.register(
        name="import_detection_rules",
        description=(
            "Import detection rules from text. Supports Sigma (YAML), SPL, KQL, "
            "and ES|QL. Multiple rules can be provided separated by '---' (Sigma) "
            "or double newlines. Returns the parsed rules with their AST details."
        ),
        parameters={
            "type": "object",
            "properties": {
                "rules_text": {
                    "type": "string",
                    "description": "Raw detection rule text (may contain multiple rules).",
                },
                "language": {
                    "type": "string",
                    "description": "Rule language: 'sigma', 'spl', 'kql', 'esql', or 'auto' for auto-detection.",
                    "enum": ["sigma", "spl", "kql", "esql", "auto"],
                },
            },
            "required": ["rules_text", "language"],
        },
        handler=_import_detection_rules,
    )

    registry.register(
        name="parse_detection_rule",
        description=(
            "Parse a single detection rule, auto-detecting its language. "
            "Returns the parsed AST, detected language, name, severity, "
            "MITRE technique mappings, and referenced fields."
        ),
        parameters={
            "type": "object",
            "properties": {
                "rule_text": {
                    "type": "string",
                    "description": "Raw detection rule text.",
                },
            },
            "required": ["rule_text"],
        },
        handler=_parse_detection_rule,
    )

    registry.register(
        name="test_rules_against_logs",
        description=(
            "Test detection rules against log data. Evaluates each rule "
            "independently against the full log set and reports which rules "
            "fired, match counts, and details. Rules must be provided as "
            "rule text strings that will be parsed first."
        ),
        parameters={
            "type": "object",
            "properties": {
                "rule_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "List of rule text strings to evaluate. Each string is "
                        "a complete detection rule that will be parsed and tested."
                    ),
                },
                "logs": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "List of log entry dicts to test the rules against.",
                },
            },
            "required": ["rule_ids", "logs"],
        },
        handler=_test_rules_against_logs,
    )

    registry.register(
        name="get_coverage_matrix",
        description=(
            "Get a MITRE ATT&CK coverage analysis showing which tactics and "
            "techniques are covered by specified technique IDs. Returns a "
            "per-tactic breakdown with coverage percentages."
        ),
        parameters={
            "type": "object",
            "properties": {
                "technique_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "List of MITRE technique IDs that are 'covered' "
                        "(e.g., ['T1059', 'T1003.001', 'T1486'])."
                    ),
                },
            },
            "required": ["technique_ids"],
        },
        handler=_get_coverage_matrix,
    )


def _build_rule_manager() -> Any:
    """Lazily construct a RuleManager."""
    from backend.detection.rule_manager import RuleManager
    return RuleManager()


def _parsed_rule_to_dict(rule: Any) -> dict[str, Any]:
    """Convert a ParsedRule dataclass to a JSON-safe dict."""
    return {
        "source_language": rule.source_language,
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "mitre_techniques": rule.mitre_techniques,
        "referenced_fields": sorted(rule.referenced_fields),
        "data_sources": rule.data_sources,
        "tags": rule.tags,
        "has_filter": rule.filter is not None,
        "has_aggregation": rule.aggregation is not None,
    }


async def _import_detection_rules(
    rules_text: str, language: str
) -> dict[str, Any]:
    """Import and parse detection rules from text."""
    try:
        manager = _build_rule_manager()
        rules = await manager.import_rules(rules_text, language)
        return {
            "status": "success",
            "language": language,
            "rules_imported": len(rules),
            "rules": [_parsed_rule_to_dict(r) for r in rules],
        }
    except ValueError as exc:
        return {"error": str(exc)}
    except Exception as exc:
        logger.exception("import_detection_rules failed")
        return {"error": f"Failed to import rules: {exc}"}


async def _parse_detection_rule(rule_text: str) -> dict[str, Any]:
    """Parse a single detection rule with auto-detection."""
    try:
        manager = _build_rule_manager()
        detected_lang = await manager.detect_language(rule_text)
        rules = await manager.import_rules(rule_text, detected_lang)
        if not rules:
            return {"error": "No rules could be parsed from the provided text."}
        rule = rules[0]
        result = _parsed_rule_to_dict(rule)
        result["detected_language"] = detected_lang
        result["status"] = "success"
        return result
    except ValueError as exc:
        return {"error": str(exc)}
    except Exception as exc:
        logger.exception("parse_detection_rule failed")
        return {"error": f"Failed to parse rule: {exc}"}


async def _test_rules_against_logs(
    rule_ids: list[str], logs: list[dict]
) -> dict[str, Any]:
    """Test rules against log data.

    rule_ids are treated as raw rule text strings that are parsed first.
    """
    try:
        manager = _build_rule_manager()

        # Parse all rule texts
        all_parsed = []
        parse_errors = []
        for i, rule_text in enumerate(rule_ids):
            try:
                parsed = await manager.import_rules(rule_text, "auto")
                all_parsed.extend(parsed)
            except Exception as exc:
                parse_errors.append(f"Rule {i + 1}: {exc}")

        if not all_parsed:
            return {
                "error": "No rules could be parsed.",
                "parse_errors": parse_errors,
            }

        # Evaluate
        batch_result = await manager.batch_evaluate(all_parsed, logs)

        results = []
        for r in batch_result.results:
            results.append({
                "rule_name": r.rule_name,
                "fired": r.fired,
                "matched_count": r.matched_count,
                "total_logs": r.total_logs,
                "evaluation_time_ms": r.evaluation_time_ms,
                "details": r.details,
            })

        coverage_dict = None
        if batch_result.coverage:
            cov = batch_result.coverage
            coverage_dict = {
                "total_techniques_covered": cov.total_techniques_covered,
                "total_rules": cov.total_rules,
                "overall_coverage_pct": cov.overall_coverage_pct,
                "tactic_coverage": cov.tactic_coverage,
            }

        return {
            "status": "success",
            "total_rules": batch_result.total_rules,
            "rules_fired": batch_result.rules_fired,
            "rules_silent": batch_result.rules_silent,
            "total_time_ms": batch_result.total_time_ms,
            "results": results,
            "coverage": coverage_dict,
            "parse_errors": parse_errors if parse_errors else None,
        }
    except Exception as exc:
        logger.exception("test_rules_against_logs failed")
        return {"error": f"Failed to test rules: {exc}"}


async def _get_coverage_matrix(technique_ids: list[str]) -> dict[str, Any]:
    """Get MITRE ATT&CK coverage matrix for the given technique IDs."""
    try:
        from backend.threat_intel.mitre_service import MITREService

        mitre = MITREService()
        matrix = await mitre.get_coverage_matrix(technique_ids)
        return {
            "status": "success",
            **matrix,
        }
    except Exception as exc:
        logger.exception("get_coverage_matrix failed")
        return {"error": f"Failed to compute coverage matrix: {exc}"}
