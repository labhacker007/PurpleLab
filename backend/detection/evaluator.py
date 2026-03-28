"""Detection rule evaluator -- tests rules against in-memory log data.

This is the CORE of the "SIEM-less detection testing engine." It takes
a ParsedRule (unified AST) and evaluates it against a list of log entries,
reporting which rules matched and which didn't.
"""
from __future__ import annotations

import fnmatch
import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from backend.detection.parsers.base_parser import (
    Aggregation,
    Condition,
    LogicGroup,
    LogicOp,
    Operator,
    ParsedRule,
)

log = logging.getLogger(__name__)


@dataclass
class EvalResult:
    """Result of evaluating a rule against logs.

    Attributes:
        rule_name: Name of the rule that was evaluated.
        fired: Whether the rule matched (True = detection triggered).
        matched_count: Number of individual logs that matched the filter.
        total_logs: Total number of logs evaluated.
        matched_log_indices: Indices of matching logs in the input list.
        aggregation_result: If aggregation: {group_key: aggregated_value}.
        evaluation_time_ms: Time taken to evaluate in milliseconds.
        details: Human-readable explanation of the result.
    """
    rule_name: str
    fired: bool
    matched_count: int
    total_logs: int
    matched_log_indices: list[int] = field(default_factory=list)
    aggregation_result: dict[str, Any] | None = None
    evaluation_time_ms: float = 0.0
    details: str = ""


class RuleEvaluator:
    """In-memory detection rule evaluation engine.

    Takes a ParsedRule (unified AST) and evaluates it against a list of
    log entries. This is the "SIEM-less detection testing engine" -- the
    core differentiator of the platform.

    Example::

        evaluator = RuleEvaluator()
        rule = sigma_parser.parse(sigma_yaml)
        logs = [{"CommandLine": "powershell -enc ...", "User": "admin"}]
        result = evaluator.evaluate(rule, logs)
        print(result.fired)  # True
        print(result.matched_count)  # 1
    """

    def __init__(self, field_mapping: dict[str, str] | None = None):
        """Initialize the evaluator with optional field mapping.

        Args:
            field_mapping: Optional field name mapping for translating
                between schemas (e.g., {"process.name": "Image",
                "process.command_line": "CommandLine"}).
        """
        self.field_mapping = field_mapping or {}
        # Build reverse mapping too
        self._reverse_mapping: dict[str, str] = {v: k for k, v in self.field_mapping.items()}

    def evaluate(self, rule: ParsedRule, logs: list[dict]) -> EvalResult:
        """Evaluate a rule against a list of log entries.

        First applies the filter to find matching logs, then applies
        aggregation (if any) to determine if the rule fires.

        Args:
            rule: The parsed detection rule (unified AST).
            logs: List of log entries (dicts) to evaluate against.

        Returns:
            EvalResult with match status, counts, and details.
        """
        start = time.perf_counter()

        if not logs:
            return EvalResult(
                rule_name=rule.name,
                fired=False,
                matched_count=0,
                total_logs=0,
                details="No logs to evaluate",
                evaluation_time_ms=0.0,
            )

        # Phase 1: Apply filter to find matching logs
        matched_indices: list[int] = []
        if rule.filter is not None:
            for i, entry in enumerate(logs):
                if self._evaluate_logic_group(rule.filter, entry):
                    matched_indices.append(i)
        else:
            # No filter = all logs match
            matched_indices = list(range(len(logs)))

        matched_logs = [logs[i] for i in matched_indices]
        matched_count = len(matched_logs)

        # Phase 2: Apply aggregation (if any)
        agg_result: dict[str, Any] | None = None
        fired: bool

        if rule.aggregation is not None:
            fired, agg_result = self._evaluate_aggregation(
                rule.aggregation, matched_logs
            )
        else:
            fired = matched_count > 0

        elapsed = (time.perf_counter() - start) * 1000

        # Build details message
        if fired:
            if rule.aggregation and agg_result:
                details = (
                    f"Rule '{rule.name}' FIRED: {matched_count}/{len(logs)} logs "
                    f"matched filter; aggregation threshold met. "
                    f"Groups: {agg_result}"
                )
            else:
                details = (
                    f"Rule '{rule.name}' FIRED: {matched_count}/{len(logs)} logs matched."
                )
        else:
            if rule.aggregation:
                details = (
                    f"Rule '{rule.name}' did not fire: {matched_count}/{len(logs)} logs "
                    f"matched filter, but aggregation threshold not met."
                )
            else:
                details = (
                    f"Rule '{rule.name}' did not fire: 0/{len(logs)} logs matched filter."
                )

        return EvalResult(
            rule_name=rule.name,
            fired=fired,
            matched_count=matched_count,
            total_logs=len(logs),
            matched_log_indices=matched_indices,
            aggregation_result=agg_result,
            evaluation_time_ms=round(elapsed, 3),
            details=details,
        )

    # ── Condition Evaluation ─────────────────────────────────────────────

    def _evaluate_condition(self, condition: Condition, entry: dict) -> bool:
        """Evaluate a single condition against a log entry.

        Handles all operator types including wildcards, regex, contains,
        startswith, endswith, numeric comparisons, in/not_in, and
        exists/not_exists.

        Args:
            condition: The condition to evaluate.
            entry: A single log entry dict.

        Returns:
            True if the condition matches.
        """
        op = condition.operator

        # EXISTS / NOT_EXISTS don't need a value from the log
        if op == Operator.EXISTS:
            return self._resolve_field(condition.field, entry) is not None
        if op == Operator.NOT_EXISTS:
            return self._resolve_field(condition.field, entry) is None

        actual = self._resolve_field(condition.field, entry)
        expected = condition.value

        # Handle None actual value
        if actual is None:
            if expected is None:
                return op == Operator.EQUALS
            return op == Operator.NOT_EQUALS

        # Handle None expected value
        if expected is None:
            return op == Operator.NOT_EQUALS

        # Convert both to strings for string operations
        actual_str = str(actual)
        expected_str = str(expected)

        if condition.case_insensitive:
            actual_lower = actual_str.lower()
            expected_lower = expected_str.lower()
        else:
            actual_lower = actual_str
            expected_lower = expected_str

        if op == Operator.EQUALS:
            # Try numeric comparison first
            if self._both_numeric(actual, expected):
                return float(actual) == float(expected)
            return actual_lower == expected_lower if condition.case_insensitive else actual_str == expected_str

        if op == Operator.NOT_EQUALS:
            if self._both_numeric(actual, expected):
                return float(actual) != float(expected)
            return actual_lower != expected_lower if condition.case_insensitive else actual_str != expected_str

        if op == Operator.CONTAINS:
            return expected_lower in actual_lower if condition.case_insensitive else expected_str in actual_str

        if op == Operator.STARTS_WITH:
            return actual_lower.startswith(expected_lower) if condition.case_insensitive else actual_str.startswith(expected_str)

        if op == Operator.ENDS_WITH:
            return actual_lower.endswith(expected_lower) if condition.case_insensitive else actual_str.endswith(expected_str)

        if op == Operator.WILDCARD:
            return self._wildcard_match(expected_str, actual_str, condition.case_insensitive)

        if op == Operator.REGEX:
            flags = re.IGNORECASE if condition.case_insensitive else 0
            try:
                return bool(re.search(expected_str, actual_str, flags))
            except re.error:
                log.warning("Invalid regex pattern: %s", expected_str)
                return False

        # Numeric comparisons
        if op in (Operator.GT, Operator.GTE, Operator.LT, Operator.LTE):
            try:
                actual_num = float(actual)
                expected_num = float(expected)
            except (ValueError, TypeError):
                return False

            if op == Operator.GT:
                return actual_num > expected_num
            if op == Operator.GTE:
                return actual_num >= expected_num
            if op == Operator.LT:
                return actual_num < expected_num
            if op == Operator.LTE:
                return actual_num <= expected_num

        # IN / NOT_IN
        if op == Operator.IN:
            if isinstance(expected, list):
                if condition.case_insensitive:
                    return actual_lower in [str(v).lower() for v in expected]
                return actual_str in [str(v) for v in expected]
            return False

        if op == Operator.NOT_IN:
            if isinstance(expected, list):
                if condition.case_insensitive:
                    return actual_lower not in [str(v).lower() for v in expected]
                return actual_str not in [str(v) for v in expected]
            return True

        log.warning("Unhandled operator: %s", op)
        return False

    def _evaluate_logic_group(self, group: LogicGroup, entry: dict) -> bool:
        """Evaluate a logic group (AND/OR/NOT) against a log entry.

        Uses short-circuit evaluation for performance.

        Args:
            group: The logic group to evaluate.
            entry: A single log entry dict.

        Returns:
            True if the logic group matches.
        """
        if not group.children:
            # Empty group -- AND of nothing is True, OR of nothing is False
            return group.operator == LogicOp.AND

        if group.operator == LogicOp.AND:
            return all(self._evaluate_child(child, entry) for child in group.children)
        elif group.operator == LogicOp.OR:
            return any(self._evaluate_child(child, entry) for child in group.children)
        elif group.operator == LogicOp.NOT:
            # NOT applies to the first child
            return not self._evaluate_child(group.children[0], entry)
        return False

    def _evaluate_child(
        self, child: Condition | LogicGroup, entry: dict
    ) -> bool:
        """Evaluate a child node (Condition or LogicGroup).

        Args:
            child: A Condition or LogicGroup to evaluate.
            entry: A single log entry dict.

        Returns:
            True if the child matches.
        """
        if isinstance(child, Condition):
            return self._evaluate_condition(child, entry)
        elif isinstance(child, LogicGroup):
            return self._evaluate_logic_group(child, entry)
        return False

    # ── Aggregation Evaluation ───────────────────────────────────────────

    def _evaluate_aggregation(
        self, aggregation: Aggregation, matching_logs: list[dict]
    ) -> tuple[bool, dict[str, Any]]:
        """Evaluate aggregation conditions against matching logs.

        Groups logs by group_by fields, applies the aggregation function,
        then checks if the threshold condition is met for any group.

        Args:
            aggregation: The aggregation specification.
            matching_logs: Logs that passed the filter phase.

        Returns:
            Tuple of (threshold_met, {group_key: aggregated_value}).
        """
        if not matching_logs:
            return False, {}

        # Group logs by group_by fields
        groups: dict[str, list[dict]] = defaultdict(list)

        if aggregation.group_by:
            for entry in matching_logs:
                key_parts = []
                for field_name in aggregation.group_by:
                    val = self._resolve_field(field_name, entry)
                    key_parts.append(str(val) if val is not None else "<null>")
                key = " | ".join(key_parts)
                groups[key].append(entry)
        else:
            groups["_all"] = matching_logs

        # Apply aggregation function to each group
        results: dict[str, Any] = {}
        func = aggregation.function
        agg_field = aggregation.field

        for group_key, group_logs in groups.items():
            if func == "count":
                results[group_key] = len(group_logs)
            elif func == "dc":
                # Distinct count
                if agg_field:
                    values = {self._resolve_field(agg_field, e) for e in group_logs}
                    values.discard(None)
                    results[group_key] = len(values)
                else:
                    results[group_key] = len(group_logs)
            elif func == "sum":
                if agg_field:
                    total = 0.0
                    for e in group_logs:
                        v = self._resolve_field(agg_field, e)
                        try:
                            total += float(v)
                        except (ValueError, TypeError):
                            pass
                    results[group_key] = total
                else:
                    results[group_key] = 0
            elif func == "avg":
                if agg_field:
                    values = []
                    for e in group_logs:
                        v = self._resolve_field(agg_field, e)
                        try:
                            values.append(float(v))
                        except (ValueError, TypeError):
                            pass
                    results[group_key] = sum(values) / len(values) if values else 0
                else:
                    results[group_key] = 0
            elif func == "min":
                if agg_field:
                    values = []
                    for e in group_logs:
                        v = self._resolve_field(agg_field, e)
                        try:
                            values.append(float(v))
                        except (ValueError, TypeError):
                            pass
                    results[group_key] = min(values) if values else 0
                else:
                    results[group_key] = 0
            elif func == "max":
                if agg_field:
                    values = []
                    for e in group_logs:
                        v = self._resolve_field(agg_field, e)
                        try:
                            values.append(float(v))
                        except (ValueError, TypeError):
                            pass
                    results[group_key] = max(values) if values else 0
                else:
                    results[group_key] = 0
            else:
                results[group_key] = len(group_logs)

        # Check threshold condition
        if aggregation.condition is not None:
            threshold_met = any(
                self._check_threshold(aggregation.condition, agg_value)
                for agg_value in results.values()
            )
        else:
            # No threshold = fire if any group has results
            threshold_met = any(v > 0 for v in results.values())

        return threshold_met, results

    def _check_threshold(self, condition: Condition, value: Any) -> bool:
        """Check if an aggregated value meets the threshold condition.

        Args:
            condition: The threshold condition (e.g., count > 5).
            value: The aggregated value.

        Returns:
            True if the threshold is met.
        """
        try:
            actual = float(value)
            expected = float(condition.value)
        except (ValueError, TypeError):
            return False

        op = condition.operator
        if op == Operator.GT:
            return actual > expected
        if op == Operator.GTE:
            return actual >= expected
        if op == Operator.LT:
            return actual < expected
        if op == Operator.LTE:
            return actual <= expected
        if op == Operator.EQUALS:
            return actual == expected
        if op == Operator.NOT_EQUALS:
            return actual != expected
        return False

    # ── Field Resolution ─────────────────────────────────────────────────

    def _resolve_field(self, field_name: str, entry: dict) -> Any:
        """Resolve a field value from a log entry.

        Handles:
        - Direct key lookup (case-insensitive)
        - Dot notation (process.name -> entry["process"]["name"])
        - Field mapping (Image -> process.name via configured mapping)

        Args:
            field_name: The field name to resolve.
            entry: A log entry dict.

        Returns:
            The field value, or None if not found.
        """
        if not entry or not field_name:
            return None

        # 1. Try direct lookup (exact case)
        if field_name in entry:
            return entry[field_name]

        # 2. Try case-insensitive lookup
        field_lower = field_name.lower()
        for key, value in entry.items():
            if key.lower() == field_lower:
                return value

        # 3. Try field mapping (before dot notation, so mapped fields take priority)
        mapped_name = self.field_mapping.get(field_name)
        if mapped_name:
            result = self._resolve_field_direct(mapped_name, entry)
            if result is not None:
                return result

        # 4. Try reverse mapping
        reverse_name = self._reverse_mapping.get(field_name)
        if reverse_name:
            result = self._resolve_field_direct(reverse_name, entry)
            if result is not None:
                return result

        # 5. Try dot notation (e.g., "process.name" -> entry["process"]["name"])
        if "." in field_name:
            parts = field_name.split(".")
            current: Any = entry
            for part in parts:
                if isinstance(current, dict):
                    # Try exact match first
                    if part in current:
                        current = current[part]
                        continue
                    # Case-insensitive
                    found = False
                    for k, v in current.items():
                        if k.lower() == part.lower():
                            current = v
                            found = True
                            break
                    if not found:
                        return None
                else:
                    return None
            return current

        return None

    def _resolve_field_direct(self, field_name: str, entry: dict) -> Any:
        """Resolve a field by direct or case-insensitive lookup only (no mapping).

        Args:
            field_name: The field name to resolve.
            entry: A log entry dict.

        Returns:
            The field value, or None if not found.
        """
        if field_name in entry:
            return entry[field_name]
        field_lower = field_name.lower()
        for key, value in entry.items():
            if key.lower() == field_lower:
                return value
        # Try dot notation
        if "." in field_name:
            parts = field_name.split(".")
            current: Any = entry
            for part in parts:
                if isinstance(current, dict):
                    if part in current:
                        current = current[part]
                        continue
                    found = False
                    for k, v in current.items():
                        if k.lower() == part.lower():
                            current = v
                            found = True
                            break
                    if not found:
                        return None
                else:
                    return None
            return current
        return None

    # ── Wildcard Matching ────────────────────────────────────────────────

    @staticmethod
    def _wildcard_match(
        pattern: str, value: str, case_insensitive: bool = False
    ) -> bool:
        """Match wildcard patterns (* and ?).

        Uses fnmatch for pattern matching. Handles backslash-separated
        paths correctly.

        Args:
            pattern: Wildcard pattern (e.g., "*\\\\cmd.exe").
            value: Value to match against.
            case_insensitive: Whether to do case-insensitive matching.

        Returns:
            True if the value matches the pattern.
        """
        if case_insensitive:
            pattern = pattern.lower()
            value = value.lower()

        # fnmatch handles * and ? wildcards
        return fnmatch.fnmatch(value, pattern)

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _both_numeric(a: Any, b: Any) -> bool:
        """Check if both values can be interpreted as numbers.

        Args:
            a: First value.
            b: Second value.

        Returns:
            True if both can be converted to float.
        """
        try:
            float(a)
            float(b)
            return True
        except (ValueError, TypeError):
            return False
