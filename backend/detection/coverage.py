"""MITRE ATT&CK coverage analysis.

Maps imported detection rules to MITRE techniques and calculates
coverage metrics across the ATT&CK matrix. Identifies gaps and
computes rule efficacy scores.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from backend.detection.evaluator import EvalResult
from backend.detection.parsers.base_parser import ParsedRule

log = logging.getLogger(__name__)

# MITRE ATT&CK Enterprise tactics (in kill-chain order)
MITRE_TACTICS = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# Mapping of technique prefixes to their parent tactic (simplified; real
# implementation would use the full ATT&CK STIX data).  This covers the
# most commonly seen top-level technique -> tactic relationships.
_TECHNIQUE_TACTIC_MAP: dict[str, list[str]] = {
    "T1595": ["reconnaissance"],
    "T1592": ["reconnaissance"],
    "T1589": ["reconnaissance"],
    "T1590": ["reconnaissance"],
    "T1591": ["reconnaissance"],
    "T1583": ["resource-development"],
    "T1584": ["resource-development"],
    "T1587": ["resource-development"],
    "T1588": ["resource-development"],
    "T1566": ["initial-access"],
    "T1190": ["initial-access"],
    "T1133": ["initial-access", "persistence"],
    "T1078": ["initial-access", "persistence", "privilege-escalation", "defense-evasion"],
    "T1059": ["execution"],
    "T1053": ["execution", "persistence", "privilege-escalation"],
    "T1047": ["execution"],
    "T1204": ["execution"],
    "T1203": ["execution"],
    "T1547": ["persistence", "privilege-escalation"],
    "T1546": ["persistence", "privilege-escalation"],
    "T1543": ["persistence", "privilege-escalation"],
    "T1098": ["persistence", "privilege-escalation"],
    "T1548": ["privilege-escalation", "defense-evasion"],
    "T1134": ["privilege-escalation", "defense-evasion"],
    "T1055": ["privilege-escalation", "defense-evasion"],
    "T1036": ["defense-evasion"],
    "T1027": ["defense-evasion"],
    "T1070": ["defense-evasion"],
    "T1562": ["defense-evasion"],
    "T1140": ["defense-evasion"],
    "T1218": ["defense-evasion"],
    "T1003": ["credential-access"],
    "T1110": ["credential-access"],
    "T1555": ["credential-access"],
    "T1558": ["credential-access"],
    "T1552": ["credential-access"],
    "T1083": ["discovery"],
    "T1082": ["discovery"],
    "T1057": ["discovery"],
    "T1018": ["discovery"],
    "T1016": ["discovery"],
    "T1021": ["lateral-movement"],
    "T1570": ["lateral-movement"],
    "T1080": ["lateral-movement"],
    "T1560": ["collection"],
    "T1005": ["collection"],
    "T1074": ["collection"],
    "T1071": ["command-and-control"],
    "T1105": ["command-and-control"],
    "T1095": ["command-and-control"],
    "T1572": ["command-and-control"],
    "T1573": ["command-and-control"],
    "T1041": ["exfiltration"],
    "T1048": ["exfiltration"],
    "T1567": ["exfiltration"],
    "T1486": ["impact"],
    "T1490": ["impact"],
    "T1489": ["impact"],
    "T1485": ["impact"],
    "T1529": ["impact"],
}


@dataclass
class TechniqueCoverage:
    """Coverage info for a single MITRE technique.

    Attributes:
        technique_id: The technique ID (e.g., "T1059.001").
        technique_name: Human-readable name (if known).
        tactics: List of tactics this technique belongs to.
        rule_count: Number of rules covering this technique.
        rule_names: Names of rules covering this technique.
        avg_efficacy: Average efficacy score of covering rules (0-100).
    """
    technique_id: str
    technique_name: str = ""
    tactics: list[str] = field(default_factory=list)
    rule_count: int = 0
    rule_names: list[str] = field(default_factory=list)
    avg_efficacy: float = 0.0


@dataclass
class CoverageMatrix:
    """Full MITRE ATT&CK coverage matrix.

    Attributes:
        techniques: Dict of technique_id -> TechniqueCoverage.
        tactic_coverage: Dict of tactic -> {covered, total, pct}.
        total_techniques_covered: Number of unique techniques with rules.
        total_rules: Total number of rules analyzed.
        overall_coverage_pct: Percentage of known techniques covered.
    """
    techniques: dict[str, TechniqueCoverage] = field(default_factory=dict)
    tactic_coverage: dict[str, dict[str, Any]] = field(default_factory=dict)
    total_techniques_covered: int = 0
    total_rules: int = 0
    overall_coverage_pct: float = 0.0


@dataclass
class GapAnalysis:
    """Gap analysis comparing rules against actor TTPs.

    Attributes:
        actor_techniques: Techniques used by the threat actor(s).
        covered_techniques: Techniques that have detection rules.
        uncovered_techniques: Techniques with no detection rules.
        coverage_pct: Percentage of actor techniques covered.
        recommendations: Suggested rules or data sources to close gaps.
    """
    actor_techniques: list[str] = field(default_factory=list)
    covered_techniques: list[str] = field(default_factory=list)
    uncovered_techniques: list[str] = field(default_factory=list)
    coverage_pct: float = 0.0
    recommendations: list[str] = field(default_factory=list)


class CoverageAnalyzer:
    """Compute MITRE ATT&CK coverage from imported rules.

    Analyzes a set of ParsedRules, maps them to MITRE techniques and
    tactics, and computes coverage metrics and gap analysis.

    Example::

        analyzer = CoverageAnalyzer()
        matrix = analyzer.compute_coverage(parsed_rules)
        print(matrix.overall_coverage_pct)

        gaps = analyzer.identify_gaps(parsed_rules, ["T1059", "T1003", "T1486"])
        print(gaps.uncovered_techniques)
    """

    def compute_coverage(self, rules: list[ParsedRule]) -> CoverageMatrix:
        """Compute which MITRE techniques are covered by the rule set.

        Builds a full coverage matrix mapping rules to techniques and
        tactics.

        Args:
            rules: List of parsed detection rules.

        Returns:
            CoverageMatrix with technique and tactic coverage.
        """
        technique_map: dict[str, TechniqueCoverage] = {}

        for rule in rules:
            for tech_id in rule.mitre_techniques:
                tech_id_upper = tech_id.upper()
                if tech_id_upper not in technique_map:
                    tactics = self._get_tactics_for_technique(tech_id_upper)
                    technique_map[tech_id_upper] = TechniqueCoverage(
                        technique_id=tech_id_upper,
                        tactics=tactics,
                    )

                tc = technique_map[tech_id_upper]
                tc.rule_count += 1
                if rule.name and rule.name not in tc.rule_names:
                    tc.rule_names.append(rule.name)

        # Compute tactic-level coverage
        tactic_techniques: dict[str, set[str]] = defaultdict(set)
        tactic_covered: dict[str, set[str]] = defaultdict(set)

        # Add all known techniques to tactic buckets
        for tech_id, tactics in _TECHNIQUE_TACTIC_MAP.items():
            for tactic in tactics:
                tactic_techniques[tactic].add(tech_id)

        # Mark covered techniques
        for tech_id, tc in technique_map.items():
            # Get parent technique (strip sub-technique)
            parent = tech_id.split(".")[0]
            for tactic in tc.tactics:
                tactic_covered[tactic].add(parent)

        tactic_coverage: dict[str, dict[str, Any]] = {}
        for tactic in MITRE_TACTICS:
            total = len(tactic_techniques.get(tactic, set()))
            covered = len(tactic_covered.get(tactic, set()))
            pct = (covered / total * 100) if total > 0 else 0.0
            tactic_coverage[tactic] = {
                "covered": covered,
                "total": total,
                "pct": round(pct, 1),
            }

        total_known = len(_TECHNIQUE_TACTIC_MAP)
        total_covered = len({tc.technique_id.split(".")[0] for tc in technique_map.values()})
        overall_pct = (total_covered / total_known * 100) if total_known > 0 else 0.0

        return CoverageMatrix(
            techniques=technique_map,
            tactic_coverage=tactic_coverage,
            total_techniques_covered=len(technique_map),
            total_rules=len(rules),
            overall_coverage_pct=round(overall_pct, 1),
        )

    def identify_gaps(
        self, rules: list[ParsedRule], actor_techniques: list[str]
    ) -> GapAnalysis:
        """Identify which actor techniques are not covered by rules.

        Compares the set of techniques used by a threat actor against
        the techniques covered by the current rule set.

        Args:
            rules: List of parsed detection rules.
            actor_techniques: List of MITRE technique IDs used by the actor.

        Returns:
            GapAnalysis with covered/uncovered techniques and recommendations.
        """
        # Build set of covered techniques (including parent techniques)
        covered: set[str] = set()
        for rule in rules:
            for tech in rule.mitre_techniques:
                tech_upper = tech.upper()
                covered.add(tech_upper)
                # Also add parent technique
                parent = tech_upper.split(".")[0]
                covered.add(parent)

        actor_set = {t.upper() for t in actor_techniques}

        covered_by_actor = actor_set & covered
        uncovered = actor_set - covered

        # Generate recommendations for uncovered techniques
        recommendations: list[str] = []
        for tech in sorted(uncovered):
            tactics = self._get_tactics_for_technique(tech)
            tactic_str = ", ".join(tactics) if tactics else "unknown"
            recommendations.append(
                f"No detection rule for {tech} (tactic: {tactic_str}). "
                f"Consider adding a Sigma rule or equivalent."
            )

        pct = (len(covered_by_actor) / len(actor_set) * 100) if actor_set else 0.0

        return GapAnalysis(
            actor_techniques=sorted(actor_set),
            covered_techniques=sorted(covered_by_actor),
            uncovered_techniques=sorted(uncovered),
            coverage_pct=round(pct, 1),
            recommendations=recommendations,
        )

    def compute_efficacy_score(
        self, rule: ParsedRule, eval_results: list[EvalResult]
    ) -> float:
        """Compute a rule efficacy score (0-100) based on evaluation results.

        The score is based on:
        - True positive rate (did it fire on malicious logs?) - 60% weight
        - False positive rate (did it NOT fire on benign logs?) - 30% weight
        - Rule completeness (has MITRE mapping, proper severity, etc.) - 10% weight

        Args:
            rule: The parsed detection rule.
            eval_results: List of evaluation results for this rule.

        Returns:
            Score from 0 to 100.
        """
        if not eval_results:
            # Score based on rule completeness only
            return self._rule_completeness_score(rule) * 10

        # Calculate TP and FP rates from evaluation results
        total_evals = len(eval_results)
        fired_count = sum(1 for r in eval_results if r.fired)
        fire_rate = fired_count / total_evals if total_evals > 0 else 0

        # True positive component (60% weight) - assumes provided logs should trigger
        tp_score = fire_rate * 60

        # False positive component (30% weight) - inverse of false positives
        # If we don't have labeled data, assume a moderate FP rate
        fp_score = 30  # Default: assume no false positives without labeled data

        # Completeness component (10% weight)
        completeness = self._rule_completeness_score(rule) * 10

        return round(min(100, tp_score + fp_score + completeness), 1)

    def _rule_completeness_score(self, rule: ParsedRule) -> float:
        """Score rule completeness on a 0-1 scale.

        Args:
            rule: The parsed rule.

        Returns:
            Completeness score from 0 to 1.
        """
        score = 0.0
        if rule.name:
            score += 0.2
        if rule.description:
            score += 0.1
        if rule.mitre_techniques:
            score += 0.3
        if rule.severity and rule.severity != "medium":
            score += 0.1
        if rule.data_sources:
            score += 0.15
        if rule.filter and rule.filter.children:
            score += 0.15
        return score

    @staticmethod
    def _get_tactics_for_technique(technique_id: str) -> list[str]:
        """Look up tactics for a given MITRE technique ID.

        Args:
            technique_id: Technique ID (e.g., "T1059" or "T1059.001").

        Returns:
            List of tactic names.
        """
        # Try exact match first
        tactics = _TECHNIQUE_TACTIC_MAP.get(technique_id)
        if tactics:
            return list(tactics)

        # Try parent technique (strip sub-technique)
        parent = technique_id.split(".")[0]
        tactics = _TECHNIQUE_TACTIC_MAP.get(parent)
        if tactics:
            return list(tactics)

        return []
