"""Validates a use case by simulating attack logs and testing detection rules."""
from __future__ import annotations

import logging
from typing import Any

from backend.db import models

logger = logging.getLogger(__name__)

# Map platform log source IDs used in use cases to agentic generator source IDs.
# The agentic generator uses its own registry IDs; this bridges the two naming spaces.
_LOG_SOURCE_ALIAS: dict[str, str] = {
    "sysmon": "windows_sysmon",
    "windows_powershell": "windows_security",
    "wmi": "windows_security",
    "active_directory": "windows_security",
    "email_gateway": "cloudflare",
    "proxy": "cloudflare",
    "firewall": "palo_alto_panos",
    "crowdstrike": "windows_sysmon",
    "okta": "windows_security",
    "azure_ad": "azure_activity",
    "kubernetes": "kubernetes_audit",
}

# Known valid source IDs in the agentic generator registry
_VALID_GENERATOR_SOURCES = {
    "windows_security",
    "windows_sysmon",
    "linux_auditd",
    "aws_cloudtrail",
    "aws_guardduty",
    "gcp_audit",
    "azure_activity",
    "palo_alto_panos",
    "kubernetes_audit",
    "dns",
    "cloudflare",
    "wiz",
}


def _resolve_source_id(raw_id: str) -> str | None:
    """Resolve a use case log source ID to a valid agentic generator source ID."""
    if raw_id in _VALID_GENERATOR_SOURCES:
        return raw_id
    alias = _LOG_SOURCE_ALIAS.get(raw_id)
    if alias and alias in _VALID_GENERATOR_SOURCES:
        return alias
    return None


class UseCaseValidator:
    """Validates a use case by simulating attack logs and testing detection rules.

    Validation cycle:
    1. Generate attack logs via AgenticLogGenerator for each technique_id
    2. Load all enabled ImportedRule from DB
    3. Use RuleManager.batch_evaluate(rules, events) to test rules
    4. Determine which rules are "expected" (their mitre_techniques overlap with use_case.technique_ids)
    5. Compute pass_rate, status, and per-rule results
    """

    async def validate(self, use_case: models.UseCase) -> dict[str, Any]:
        """Run full validation cycle for a use case.

        Args:
            use_case: The UseCase ORM object to validate.

        Returns:
            dict with keys: status, events_generated, rules_tested, rules_fired,
            expected_rules_fired, pass_rate, rule_results.
        """
        technique_ids: list[str] = list(use_case.technique_ids or [])
        expected_log_sources: list[str] = list(use_case.expected_log_sources or [])

        # Step 1: Generate attack logs
        all_events: list[dict[str, Any]] = []
        events_generated = 0

        try:
            from backend.log_sources.agentic_generator import AgenticLogGenerator
            gen = AgenticLogGenerator()

            # Determine which source IDs to generate from
            source_ids_to_use: list[str] = []
            for raw_id in expected_log_sources:
                resolved = _resolve_source_id(raw_id)
                if resolved and resolved not in source_ids_to_use:
                    source_ids_to_use.append(resolved)

            # Fallback to windows_sysmon if nothing resolved
            if not source_ids_to_use:
                source_ids_to_use = ["windows_sysmon"]

            # Generate events for each (source, technique) pair
            for technique_id in technique_ids or ["T1059"]:
                for source_id in source_ids_to_use[:2]:  # cap at 2 sources per technique
                    try:
                        result = await gen.generate(
                            source_id=source_id,
                            technique_id=technique_id,
                            count=10,
                        )
                        events = result.get("events", [])
                        all_events.extend(events)
                        events_generated += len(events)
                    except Exception as exc:
                        logger.warning(
                            "Log generation failed for source=%s technique=%s: %s",
                            source_id, technique_id, exc,
                        )

        except ImportError as exc:
            logger.warning("AgenticLogGenerator not available: %s", exc)

        if not all_events:
            logger.warning(
                "No events generated for use case %s — validation will use empty log set",
                use_case.id,
            )

        # Step 2: Load enabled detection rules from DB
        from backend.db.session import async_session
        from sqlalchemy import select

        db_rules: list[models.ImportedRule] = []
        try:
            async with async_session() as db:
                rows = (await db.scalars(
                    select(models.ImportedRule).where(
                        models.ImportedRule.enabled.is_(True)
                    )
                )).all()
                db_rules = list(rows)
        except Exception as exc:
            logger.warning("Failed to load detection rules from DB: %s", exc)

        if not db_rules:
            return {
                "status": "partial",
                "events_generated": events_generated,
                "rules_tested": 0,
                "rules_fired": 0,
                "expected_rules_fired": 0,
                "pass_rate": 0.0,
                "rule_results": [],
            }

        # Step 3: Parse rules and batch evaluate
        from backend.detection.rule_manager import RuleManager
        manager = RuleManager()

        parsed_rules = []
        rule_name_map: dict[str, str] = {}  # rule.name → db rule id for technique lookup

        for db_rule in db_rules:
            try:
                parsed = await manager.import_rules(
                    db_rule.source_query, db_rule.language
                )
                for p in parsed:
                    # Store the DB rule name so we can look up techniques later
                    p_name = p.name or db_rule.name
                    rule_name_map[p_name] = str(db_rule.id)
                parsed_rules.extend(parsed)
            except Exception as exc:
                logger.debug("Could not parse rule %s (%s): %s", db_rule.name, db_rule.language, exc)

        if not parsed_rules:
            return {
                "status": "partial",
                "events_generated": events_generated,
                "rules_tested": 0,
                "rules_fired": 0,
                "expected_rules_fired": 0,
                "pass_rate": 0.0,
                "rule_results": [],
            }

        # Build a lookup from db rule name → techniques for "expected" determination
        db_rule_tech_map: dict[str, list[str]] = {
            dr.name: list(dr.mitre_techniques or []) for dr in db_rules
        }

        # Evaluate rules against generated events
        batch_result = await manager.batch_evaluate(parsed_rules, all_events)

        # Step 4: Determine expected rules (techniques overlap with use_case.technique_ids)
        use_case_techniques = {t.upper() for t in (technique_ids or [])}

        rule_results: list[dict[str, Any]] = []
        rules_fired = 0
        expected_rules_fired = 0

        for eval_result in batch_result.results:
            r_name = eval_result.rule_name

            # Find DB techniques for this rule
            rule_techs: set[str] = set()
            for dr_name, techs in db_rule_tech_map.items():
                if dr_name == r_name or r_name.startswith(dr_name):
                    rule_techs = {t.upper() for t in techs}
                    break

            is_expected = bool(rule_techs & use_case_techniques)
            fired = eval_result.fired

            if fired:
                rules_fired += 1
            if fired and is_expected:
                expected_rules_fired += 1

            rule_results.append({
                "name": r_name,
                "fired": fired,
                "matched_count": eval_result.matched_count,
                "is_expected": is_expected,
            })

        rules_tested = batch_result.total_rules
        pass_rate = rules_fired / rules_tested if rules_tested > 0 else 0.0

        # Step 5: Determine status
        if expected_rules_fired > 0:
            status = "passed"
        elif rules_tested > 0:
            status = "failed"
        else:
            status = "partial"

        return {
            "status": status,
            "events_generated": events_generated,
            "rules_tested": rules_tested,
            "rules_fired": rules_fired,
            "expected_rules_fired": expected_rules_fired,
            "pass_rate": round(pass_rate, 4),
            "rule_results": rule_results,
        }
