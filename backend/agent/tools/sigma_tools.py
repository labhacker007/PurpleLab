"""Sigma rule translation tools for the agent orchestrator.

Uses the configurable LLM router (SIGMA_TRANSLATION function) to translate
Sigma rules into platform-native query languages:
  - Splunk SPL
  - Elastic ES|QL / Lucene / EQL
  - Microsoft Sentinel KQL (ASIM / legacy MMA)
  - Google Chronicle YARA-L 2.0
  - Palo Alto XSIAM XQL
  - AWS OpenSearch PPL

The LLM is prompted with the full Sigma specification context so it can
handle edge cases (aggregations, near-conditions, field mappings, etc.)
that rule-compilers often miss.
"""
from __future__ import annotations

import logging
from typing import Any

from backend.agent.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)

# Supported target platforms and their descriptions
SIGMA_TARGETS = {
    "splunk_spl": "Splunk Search Processing Language (SPL) for use with Splunk HEC/REST",
    "elastic_esql": "Elastic ES|QL — the new Elastic query language (v8.11+)",
    "elastic_eql": "Elastic Event Query Language (EQL) for event sequences and correlations",
    "elastic_lucene": "Elasticsearch Lucene query string (classic, widest compatibility)",
    "kql": "Microsoft Sentinel / Defender KQL (Kusto Query Language)",
    "kql_asim": "Microsoft Sentinel KQL using ASIM normalized schema parsers",
    "yara_l": "Google Chronicle / SIEM YARA-L 2.0 detection rule",
    "xql": "Palo Alto Cortex XSIAM XQL (extended query language)",
    "ppl": "AWS OpenSearch / OpenSearch Dashboards PPL (Piped Processing Language)",
    "qradar_aql": "IBM QRadar AQL (Ariel Query Language)",
}

# System prompt fragment to ensure high-quality translation
_SIGMA_SYSTEM = """You are an expert SOC engineer and detection engineering specialist.
Your task is to translate Sigma detection rules into platform-native query languages.

Sigma specification knowledge:
- logsource: product/category/service maps to specific indexes/tables per platform
- detection: selection criteria use key-value, wildcards (*/?), CIDR, regex (|re), and list semantics
- condition: Boolean algebra on named selections (selection, filter, keywords)
- aggregation: count, sum, min, max, avg — with grouping and comparison operators
- timeframe: sliding window applied to aggregation conditions
- near: temporal proximity of multiple conditions (not supported on all platforms)
- field modifiers: contains, startswith, endswith, re, cidr, all, windash, base64

Translation guidelines:
1. Map Sigma logsource to the most specific index/table for the target platform
2. Expand wildcards/case-insensitive matches correctly per platform syntax
3. Apply field name mapping (e.g., CommandLine → process.command_line in ECS)
4. Preserve the full boolean logic of the condition statement
5. Add a comment block at the top noting: original rule title, author, MITRE techniques
6. If the rule uses unsupported features, add a NOTE comment explaining limitations
7. Return ONLY the translated rule code — no markdown fences, no explanation prose

For field mappings, use:
- ECS (Elastic): process.name, process.command_line, source.ip, destination.port, etc.
- ASIM (Sentinel): Process, CommandLine, SrcIpAddr, DstPort, etc.
- Splunk CIM: process_name, parent_process_name, src_ip, dest_port, etc.
"""


def register_tools(registry: ToolRegistry) -> None:
    """Register all Sigma translation tools."""

    registry.register(
        name="translate_sigma_rule",
        description=(
            "Translate a Sigma detection rule into a platform-native query language. "
            "Supports Splunk SPL, Elastic ES|QL/EQL/Lucene, Microsoft Sentinel KQL "
            "(including ASIM), Google Chronicle YARA-L 2.0, Palo Alto XQL, AWS OpenSearch PPL, "
            "and IBM QRadar AQL. The translation is LLM-powered and handles edge cases "
            "like aggregations, field mappings, and logsource resolution."
        ),
        parameters={
            "type": "object",
            "properties": {
                "sigma_rule": {
                    "type": "string",
                    "description": "The Sigma rule in YAML format.",
                },
                "target": {
                    "type": "string",
                    "description": (
                        "Target query language. One of: "
                        + ", ".join(SIGMA_TARGETS.keys())
                    ),
                    "enum": list(SIGMA_TARGETS.keys()),
                },
                "field_mapping": {
                    "type": "object",
                    "description": (
                        "Optional custom field mapping overrides. Keys are Sigma field names, "
                        "values are target platform field names. "
                        "E.g., {\"CommandLine\": \"process.args\"}."
                    ),
                },
                "index_override": {
                    "type": "string",
                    "description": (
                        "Optional index/table name override. Replaces the automatic "
                        "logsource-based index selection. E.g., 'windows*' for Splunk."
                    ),
                },
            },
            "required": ["sigma_rule", "target"],
        },
        handler=_translate_sigma_rule,
    )

    registry.register(
        name="translate_sigma_batch",
        description=(
            "Translate multiple Sigma rules to a target platform in a single call. "
            "More efficient than calling translate_sigma_rule repeatedly. "
            "Rules separated by '---' (YAML document separator) or provided as a list."
        ),
        parameters={
            "type": "object",
            "properties": {
                "sigma_rules_yaml": {
                    "type": "string",
                    "description": "One or more Sigma rules in YAML, separated by '---'.",
                },
                "target": {
                    "type": "string",
                    "description": "Target query language (same options as translate_sigma_rule).",
                    "enum": list(SIGMA_TARGETS.keys()),
                },
                "field_mapping": {
                    "type": "object",
                    "description": "Optional custom field mapping overrides applied to all rules.",
                },
            },
            "required": ["sigma_rules_yaml", "target"],
        },
        handler=_translate_sigma_batch,
    )

    registry.register(
        name="validate_sigma_rule",
        description=(
            "Validate a Sigma rule for correctness: check YAML syntax, required fields, "
            "condition references, and MITRE technique ID format. Returns a validation "
            "report with errors, warnings, and improvement suggestions."
        ),
        parameters={
            "type": "object",
            "properties": {
                "sigma_rule": {
                    "type": "string",
                    "description": "The Sigma rule in YAML format.",
                },
            },
            "required": ["sigma_rule"],
        },
        handler=_validate_sigma_rule,
    )

    registry.register(
        name="explain_sigma_rule",
        description=(
            "Explain a Sigma rule in plain language. Describes what attacker behavior "
            "the rule detects, which log sources and fields it queries, the MITRE "
            "technique it maps to, and potential false positive scenarios."
        ),
        parameters={
            "type": "object",
            "properties": {
                "sigma_rule": {
                    "type": "string",
                    "description": "The Sigma rule in YAML format.",
                },
                "audience": {
                    "type": "string",
                    "description": "Target audience for the explanation: 'analyst', 'engineer', or 'executive'.",
                    "enum": ["analyst", "engineer", "executive"],
                },
            },
            "required": ["sigma_rule"],
        },
        handler=_explain_sigma_rule,
    )


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

async def _translate_sigma_rule(
    sigma_rule: str,
    target: str,
    field_mapping: dict[str, str] | None = None,
    index_override: str | None = None,
) -> dict[str, Any]:
    """Translate a single Sigma rule via LLM."""
    try:
        from backend.llm.router import get_llm_router
        from backend.llm.config import LLMFunction

        router = get_llm_router()

        target_desc = SIGMA_TARGETS.get(target, target)
        mapping_note = ""
        if field_mapping:
            pairs = ", ".join(f"{k} → {v}" for k, v in field_mapping.items())
            mapping_note = f"\n\nCustom field mapping to apply: {pairs}"
        if index_override:
            mapping_note += f"\n\nOverride the logsource index/table with: {index_override}"

        user_prompt = (
            f"Translate the following Sigma rule to **{target}** "
            f"({target_desc}).{mapping_note}\n\n"
            f"```yaml\n{sigma_rule}\n```"
        )

        response = await router.complete(
            fn=LLMFunction.SIGMA_TRANSLATION,
            messages=[{"role": "user", "content": user_prompt}],
            system=_SIGMA_SYSTEM,
        )

        translated = response.strip()

        # Extract rule metadata for response context
        rule_meta = _extract_sigma_metadata(sigma_rule)

        return {
            "status": "success",
            "target": target,
            "target_description": target_desc,
            "translated_rule": translated,
            "source_rule_name": rule_meta.get("title", "Unknown"),
            "source_mitre": rule_meta.get("tags", []),
            "field_mapping_applied": field_mapping or {},
            "index_override": index_override,
        }
    except Exception as exc:
        logger.exception("translate_sigma_rule failed")
        return {"error": f"Translation failed: {exc}"}


async def _translate_sigma_batch(
    sigma_rules_yaml: str,
    target: str,
    field_mapping: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Translate multiple Sigma rules in a single LLM call."""
    try:
        from backend.llm.router import get_llm_router
        from backend.llm.config import LLMFunction

        router = get_llm_router()

        # Split on YAML document separators
        raw_rules = [r.strip() for r in sigma_rules_yaml.split("---") if r.strip()]
        if not raw_rules:
            return {"error": "No Sigma rules found in input."}

        target_desc = SIGMA_TARGETS.get(target, target)
        mapping_note = ""
        if field_mapping:
            pairs = ", ".join(f"{k} → {v}" for k, v in field_mapping.items())
            mapping_note = f"\n\nCustom field mapping to apply to all rules: {pairs}"

        user_prompt = (
            f"Translate the following {len(raw_rules)} Sigma rule(s) to **{target}** "
            f"({target_desc}). Separate each translated rule with '# --- RULE BOUNDARY ---'.{mapping_note}\n\n"
            + "\n---\n".join(f"```yaml\n{r}\n```" for r in raw_rules)
        )

        response = await router.complete(
            fn=LLMFunction.SIGMA_TRANSLATION,
            messages=[{"role": "user", "content": user_prompt}],
            system=_SIGMA_SYSTEM,
        )

        # Split translated output back into individual rules
        boundary = "# --- RULE BOUNDARY ---"
        translated_parts = [p.strip() for p in response.split(boundary) if p.strip()]

        results = []
        for i, (raw, translated) in enumerate(
            zip(raw_rules, translated_parts + [""] * max(0, len(raw_rules) - len(translated_parts)))
        ):
            meta = _extract_sigma_metadata(raw)
            results.append({
                "index": i,
                "rule_name": meta.get("title", f"Rule {i + 1}"),
                "mitre_tags": meta.get("tags", []),
                "translated_rule": translated or "# Translation not generated",
            })

        return {
            "status": "success",
            "target": target,
            "total_rules": len(raw_rules),
            "translated_count": len(translated_parts),
            "results": results,
        }
    except Exception as exc:
        logger.exception("translate_sigma_batch failed")
        return {"error": f"Batch translation failed: {exc}"}


async def _validate_sigma_rule(sigma_rule: str) -> dict[str, Any]:
    """Validate a Sigma rule for correctness."""
    try:
        import yaml

        errors: list[str] = []
        warnings: list[str] = []
        suggestions: list[str] = []

        # --- YAML parse check ---
        try:
            data = yaml.safe_load(sigma_rule)
            if not isinstance(data, dict):
                return {"valid": False, "errors": ["Rule YAML does not parse to a mapping."]}
        except yaml.YAMLError as exc:
            return {"valid": False, "errors": [f"YAML syntax error: {exc}"]}

        # --- Required fields ---
        for req in ("title", "detection", "logsource"):
            if req not in data:
                errors.append(f"Missing required field: '{req}'")

        # --- Recommended fields ---
        for rec in ("description", "status", "level"):
            if rec not in data:
                warnings.append(f"Missing recommended field: '{rec}'")

        # --- Status values ---
        valid_statuses = {"stable", "test", "experimental", "deprecated", "unsupported"}
        if "status" in data and data["status"] not in valid_statuses:
            warnings.append(
                f"Unknown status '{data['status']}'. Expected one of: {', '.join(sorted(valid_statuses))}"
            )

        # --- Level values ---
        valid_levels = {"informational", "low", "medium", "high", "critical"}
        if "level" in data and data["level"] not in valid_levels:
            warnings.append(
                f"Unknown level '{data['level']}'. Expected one of: {', '.join(sorted(valid_levels))}"
            )

        # --- Detection condition references ---
        detection = data.get("detection", {})
        if isinstance(detection, dict):
            condition = detection.get("condition", "")
            named_selections = {k for k in detection if k != "condition"}
            # Simple check: any word in condition that looks like a selection name
            import re
            referenced = set(re.findall(r"\b([a-z_][a-z0-9_]*)\b", str(condition).lower()))
            # Filter out keywords
            reserved = {"all", "of", "them", "and", "or", "not", "near", "by", "1", "count", ">", "<"}
            referenced -= reserved
            for ref in referenced:
                if ref not in {s.lower() for s in named_selections} and len(ref) > 1:
                    warnings.append(
                        f"Condition references '{ref}' which is not a named selection in detection block."
                    )
            if not condition:
                errors.append("'detection.condition' is missing or empty.")

        # --- MITRE tags format ---
        tags = data.get("tags", [])
        if isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, str) and tag.startswith("attack."):
                    technique_part = tag[len("attack."):]
                    # Check T-number format
                    if re.match(r"^t\d{4}(\.\d{3})?$", technique_part.lower()):
                        pass  # valid
                    elif technique_part.lower() in {
                        "reconnaissance", "resource_development", "initial_access",
                        "execution", "persistence", "privilege_escalation",
                        "defense_evasion", "credential_access", "discovery",
                        "lateral_movement", "collection", "command_and_control",
                        "exfiltration", "impact",
                    }:
                        pass  # valid tactic
                    else:
                        warnings.append(
                            f"Tag '{tag}' does not match expected MITRE format (attack.TXXX or attack.tactic_name)."
                        )

        # --- Suggestions ---
        if not data.get("author"):
            suggestions.append("Add an 'author' field for attribution and maintenance tracking.")
        if not data.get("date"):
            suggestions.append("Add a 'date' field (format: YYYY/MM/DD) for versioning.")
        if not data.get("falsepositives"):
            suggestions.append("Add 'falsepositives' to document known benign trigger scenarios.")
        if not data.get("references"):
            suggestions.append("Add 'references' (URLs) linking to threat reports or CVEs.")
        if not data.get("id"):
            suggestions.append("Add a UUID 'id' field for unique rule identification.")

        valid = len(errors) == 0
        meta = _extract_sigma_metadata(sigma_rule)

        return {
            "valid": valid,
            "rule_title": meta.get("title", "Unknown"),
            "errors": errors,
            "warnings": warnings,
            "suggestions": suggestions,
            "mitre_tags": meta.get("tags", []),
            "logsource": data.get("logsource", {}),
            "detection_selections": list(detection.keys()) if isinstance(detection, dict) else [],
        }
    except Exception as exc:
        logger.exception("validate_sigma_rule failed")
        return {"error": f"Validation failed: {exc}"}


async def _explain_sigma_rule(
    sigma_rule: str,
    audience: str = "analyst",
) -> dict[str, Any]:
    """Explain a Sigma rule in plain language."""
    try:
        from backend.llm.router import get_llm_router
        from backend.llm.config import LLMFunction

        router = get_llm_router()

        audience_guidance = {
            "analyst": "Write for a SOC analyst. Focus on: what attacker behavior this catches, "
                       "which fields are key indicators, expected false positive rate, and triage tips.",
            "engineer": "Write for a detection engineer. Focus on: log source requirements, "
                        "field semantics, condition logic, known tuning points, and deployment notes.",
            "executive": "Write for a CISO/executive. Use plain non-technical language. Focus on: "
                         "what threat is mitigated, business risk reduced, and compliance alignment.",
        }.get(audience, "Write a clear explanation for a technical SOC audience.")

        user_prompt = (
            f"Explain this Sigma detection rule. {audience_guidance}\n\n"
            f"```yaml\n{sigma_rule}\n```\n\n"
            "Structure your response as:\n"
            "**What it detects:** (1-2 sentences)\n"
            "**Attacker technique:** (MITRE ATT&CK reference)\n"
            "**Key indicators:** (bullet list of field/value pairs)\n"
            "**Log sources required:** (what must be enabled/collected)\n"
            "**False positives:** (common benign scenarios)\n"
            "**Severity:** (and rationale)\n"
            "**Recommended response:** (analyst action when this fires)"
        )

        response = await router.complete(
            fn=LLMFunction.SIGMA_TRANSLATION,
            messages=[{"role": "user", "content": user_prompt}],
        )

        meta = _extract_sigma_metadata(sigma_rule)

        return {
            "status": "success",
            "rule_title": meta.get("title", "Unknown"),
            "audience": audience,
            "explanation": response.strip(),
            "mitre_tags": meta.get("tags", []),
            "severity": meta.get("level", "unknown"),
        }
    except Exception as exc:
        logger.exception("explain_sigma_rule failed")
        return {"error": f"Explanation failed: {exc}"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_sigma_metadata(sigma_yaml: str) -> dict[str, Any]:
    """Extract key fields from a Sigma YAML string without raising."""
    try:
        import yaml
        data = yaml.safe_load(sigma_yaml)
        if not isinstance(data, dict):
            return {}
        return {
            "title": data.get("title", ""),
            "description": data.get("description", ""),
            "author": data.get("author", ""),
            "level": data.get("level", ""),
            "status": data.get("status", ""),
            "tags": [t for t in data.get("tags", []) if isinstance(t, str)],
        }
    except Exception:
        return {}
