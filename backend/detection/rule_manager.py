"""Rule manager -- CRUD operations and lifecycle for detection rules.

Handles importing rules from various sources, parsing them with the
appropriate parser, running evaluations, and computing coverage.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

from backend.detection.coverage import CoverageAnalyzer, CoverageMatrix, GapAnalysis
from backend.detection.evaluator import EvalResult, RuleEvaluator
from backend.detection.parsers.base_parser import ParsedRule
from backend.detection.parsers.esql_parser import ESQLParser
from backend.detection.parsers.kql_parser import KQLParser
from backend.detection.parsers.sigma_parser import SigmaParser
from backend.detection.parsers.spl_parser import SPLParser
from backend.detection.parsers.yara_l_parser import YARALParser

log = logging.getLogger(__name__)


@dataclass
class TestRunResult:
    """Result of a full test run evaluating multiple rules against logs.

    Attributes:
        total_rules: Number of rules evaluated.
        rules_fired: Number of rules that matched (fired).
        rules_silent: Number of rules that did not match.
        results: Individual EvalResult for each rule.
        coverage: MITRE ATT&CK coverage matrix.
        total_time_ms: Total evaluation time in milliseconds.
    """
    total_rules: int = 0
    rules_fired: int = 0
    rules_silent: int = 0
    results: list[EvalResult] = field(default_factory=list)
    coverage: CoverageMatrix | None = None
    total_time_ms: float = 0.0


class RuleManager:
    """Manages detection rule lifecycle: import, parse, store, test.

    Central orchestrator for the detection engine. Knows how to pick
    the right parser for each rule language and coordinate evaluation
    and coverage analysis.

    Example::

        manager = RuleManager()
        rules = await manager.import_rules(sigma_yaml, "sigma")
        results = await manager.test_rules(rules, log_entries)
        print(results[0].fired)

        batch = await manager.batch_evaluate(rules, log_entries)
        print(batch.coverage.overall_coverage_pct)
    """

    def __init__(
        self,
        field_mapping: dict[str, str] | None = None,
    ):
        """Initialize the rule manager.

        Args:
            field_mapping: Optional field name mapping for the evaluator.
        """
        self.parsers = {
            "sigma": SigmaParser(),
            "spl": SPLParser(),
            "kql": KQLParser(),
            "esql": ESQLParser(),
            "yara_l": YARALParser(),
        }
        self.evaluator = RuleEvaluator(field_mapping=field_mapping)
        self.coverage_analyzer = CoverageAnalyzer()

    async def import_rules(
        self, rules_text: str, language: str, **kwargs
    ) -> list[ParsedRule]:
        """Import and parse rules from text.

        For Sigma, the text may contain multiple YAML documents
        separated by '---'. For SPL/KQL/ES|QL, each line or
        double-newline-separated block is a separate rule.

        Args:
            rules_text: Raw rule text (may contain multiple rules).
            language: Rule language ("sigma", "spl", "kql", "esql", or "auto").
            **kwargs: Additional parser kwargs (name, description, severity).

        Returns:
            List of successfully parsed rules.

        Raises:
            ValueError: If the language is not supported.
        """
        if language == "auto":
            language = await self.detect_language(rules_text)

        parser = self.parsers.get(language)
        if parser is None:
            raise ValueError(
                f"Unsupported rule language: {language}. "
                f"Supported: {', '.join(self.parsers.keys())}"
            )

        rules: list[ParsedRule] = []
        errors: list[str] = []

        if language == "sigma":
            # Sigma: split on YAML document separators
            documents = re.split(r'\n---\s*\n', rules_text)
            for i, doc in enumerate(documents):
                doc = doc.strip()
                if not doc:
                    continue
                try:
                    rule = parser.parse(doc, **kwargs)
                    rules.append(rule)
                except Exception as exc:
                    errors.append(f"Sigma doc {i + 1}: {exc}")
                    log.warning("Failed to parse Sigma document %d: %s", i + 1, exc)
        else:
            # SPL/KQL/ESQL: split on double newlines or treat as single query
            blocks = re.split(r'\n\s*\n', rules_text)
            for i, block in enumerate(blocks):
                block = block.strip()
                if not block:
                    continue
                try:
                    rule = parser.parse(block, **kwargs)
                    rules.append(rule)
                except Exception as exc:
                    errors.append(f"Rule block {i + 1}: {exc}")
                    log.warning("Failed to parse rule block %d: %s", i + 1, exc)

        if errors and not rules:
            raise ValueError(f"All rules failed to parse: {'; '.join(errors)}")

        log.info(
            "Imported %d rules (%s), %d errors",
            len(rules), language, len(errors),
        )
        return rules

    async def detect_language(self, rule_text: str) -> str:
        """Auto-detect the rule language from the text content.

        Tries each parser's supports() method and returns the first match.
        Falls back to heuristic detection based on keywords.

        Args:
            rule_text: Raw rule text.

        Returns:
            Detected language string ("sigma", "spl", "kql", "esql").

        Raises:
            ValueError: If the language cannot be detected.
        """
        # Try each parser in priority order
        priority_order = ["sigma", "esql", "kql", "spl"]
        for lang in priority_order:
            parser = self.parsers[lang]
            try:
                if parser.supports(rule_text):
                    return lang
            except Exception:
                continue

        # Fallback heuristics
        text = rule_text.strip()
        if "detection:" in text and ("title:" in text or "logsource:" in text):
            return "sigma"
        if text.upper().startswith("FROM ") or "| WHERE " in text.upper():
            return "esql"
        if "| summarize " in text.lower() or "| extend " in text.lower():
            return "kql"
        if "index=" in text.lower() or "sourcetype=" in text.lower():
            return "spl"

        raise ValueError(
            "Could not auto-detect rule language. "
            "Please specify: sigma, spl, kql, or esql."
        )

    async def test_rules(
        self, rules: list[ParsedRule], logs: list[dict]
    ) -> list[EvalResult]:
        """Test multiple rules against a log dataset.

        Evaluates each rule independently against the full log set.

        Args:
            rules: List of parsed detection rules.
            logs: List of log entries to test against.

        Returns:
            List of EvalResult, one per rule.
        """
        results: list[EvalResult] = []
        for rule in rules:
            try:
                result = self.evaluator.evaluate(rule, logs)
                results.append(result)
            except Exception as exc:
                log.error("Error evaluating rule '%s': %s", rule.name, exc)
                results.append(EvalResult(
                    rule_name=rule.name,
                    fired=False,
                    matched_count=0,
                    total_logs=len(logs),
                    details=f"Evaluation error: {exc}",
                ))
        return results

    async def batch_evaluate(
        self, rules: list[ParsedRule], logs: list[dict]
    ) -> TestRunResult:
        """Run a full test with coverage analysis.

        Evaluates all rules, computes MITRE coverage, and returns
        a comprehensive TestRunResult.

        Args:
            rules: List of parsed detection rules.
            logs: List of log entries to test against.

        Returns:
            TestRunResult with individual results and coverage.
        """
        start = time.perf_counter()

        results = await self.test_rules(rules, logs)
        coverage = self.coverage_analyzer.compute_coverage(rules)

        elapsed = (time.perf_counter() - start) * 1000

        fired = sum(1 for r in results if r.fired)

        return TestRunResult(
            total_rules=len(rules),
            rules_fired=fired,
            rules_silent=len(rules) - fired,
            results=results,
            coverage=coverage,
            total_time_ms=round(elapsed, 3),
        )

    async def import_and_test(
        self,
        rules_text: str,
        language: str,
        logs: list[dict],
        **kwargs,
    ) -> TestRunResult:
        """Import rules and immediately test them -- convenience method.

        Args:
            rules_text: Raw rule text.
            language: Rule language or "auto".
            logs: Log entries to test against.
            **kwargs: Additional parser kwargs.

        Returns:
            TestRunResult with parse + evaluation results.
        """
        rules = await self.import_rules(rules_text, language, **kwargs)
        return await self.batch_evaluate(rules, logs)
