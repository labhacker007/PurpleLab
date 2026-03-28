"""Tests for the detection rule engine: parsers, evaluator, coverage.

Covers Sigma, SPL, KQL, ES|QL parsing, in-memory evaluation,
aggregation, field mapping, coverage analysis, and the rule manager.
"""
from __future__ import annotations

import asyncio

import pytest

from backend.detection.parsers.base_parser import (
    Aggregation,
    Condition,
    LogicGroup,
    LogicOp,
    Operator,
    ParsedRule,
)
from backend.detection.parsers.sigma_parser import SigmaParser
from backend.detection.parsers.spl_parser import SPLParser
from backend.detection.parsers.kql_parser import KQLParser
from backend.detection.parsers.esql_parser import ESQLParser
from backend.detection.evaluator import RuleEvaluator, EvalResult
from backend.detection.coverage import CoverageAnalyzer
from backend.detection.rule_manager import RuleManager


# ── Sigma Parser Tests ──────────────────────────────────────────────────

SIGMA_RULE = """
title: Suspicious PowerShell Execution
status: test
description: Detects suspicious PowerShell commands
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - powershell
            - cmd.exe
        ParentImage|endswith: "\\\\explorer.exe"
    filter:
        User: SYSTEM
    condition: selection and not filter
level: high
tags:
    - attack.execution
    - attack.t1059.001
"""


class TestSigmaParser:
    def setup_method(self):
        self.parser = SigmaParser()

    def test_supports_sigma(self):
        assert self.parser.supports(SIGMA_RULE)
        assert not self.parser.supports("index=main sourcetype=sysmon")

    def test_parse_basic_sigma(self):
        rule = self.parser.parse(SIGMA_RULE)
        assert rule.name == "Suspicious PowerShell Execution"
        assert rule.source_language == "sigma"
        assert rule.severity == "high"
        assert "T1059.001" in rule.mitre_techniques
        assert rule.filter is not None
        assert "CommandLine" in rule.referenced_fields
        assert "ParentImage" in rule.referenced_fields

    def test_parse_data_sources(self):
        rule = self.parser.parse(SIGMA_RULE)
        assert "category:process_creation" in rule.data_sources
        assert "product:windows" in rule.data_sources

    def test_parse_1_of_selection(self):
        sigma = """
title: Multi Selection
detection:
    selection1:
        CommandLine|contains: powershell
    selection2:
        CommandLine|contains: cmd.exe
    condition: 1 of selection*
level: medium
"""
        rule = self.parser.parse(sigma)
        assert rule.filter is not None
        assert rule.filter.operator == LogicOp.OR

    def test_parse_all_modifier(self):
        sigma = """
title: All Modifier Test
detection:
    selection:
        CommandLine|contains|all:
            - powershell
            - encoded
    condition: selection
level: medium
"""
        rule = self.parser.parse(sigma)
        assert rule.filter is not None

    def test_invalid_yaml(self):
        with pytest.raises(ValueError, match="Invalid Sigma YAML"):
            self.parser.parse("not: valid: yaml: [[[")

    def test_missing_detection(self):
        with pytest.raises(ValueError, match="detection"):
            self.parser.parse("title: No Detection\nlevel: high\n")


# ── SPL Parser Tests ────────────────────────────────────────────────────

class TestSPLParser:
    def setup_method(self):
        self.parser = SPLParser()

    def test_supports_spl(self):
        assert self.parser.supports('index=main sourcetype=sysmon EventCode=1')
        assert not self.parser.supports('title: My Rule\ndetection:\n  selection:\n    field: value\n  condition: selection')

    def test_parse_basic_spl(self):
        rule = self.parser.parse('index=main sourcetype=sysmon EventCode=1')
        assert rule.source_language == "spl"
        assert rule.filter is not None
        assert "index=main" in rule.data_sources
        assert "sourcetype=sysmon" in rule.data_sources

    def test_parse_where_like(self):
        rule = self.parser.parse(
            'index=main | where CommandLine LIKE "%powershell%"'
        )
        assert rule.filter is not None
        assert "CommandLine" in rule.referenced_fields

    def test_parse_stats_aggregation(self):
        rule = self.parser.parse(
            'index=main EventCode=1 | stats count by Computer, User'
        )
        assert rule.aggregation is not None
        assert rule.aggregation.function == "count"
        assert "Computer" in rule.aggregation.group_by
        assert "User" in rule.aggregation.group_by

    def test_parse_empty(self):
        with pytest.raises(ValueError):
            self.parser.parse("")


# ── KQL Parser Tests ────────────────────────────────────────────────────

class TestKQLParser:
    def setup_method(self):
        self.parser = KQLParser()

    def test_supports_kql(self):
        assert self.parser.supports(
            'SecurityEvent\n| where EventID == 4688\n| where CommandLine contains "powershell"'
        )

    def test_parse_basic_kql(self):
        rule = self.parser.parse(
            'SecurityEvent\n| where EventID == 4688\n| where CommandLine contains "powershell"'
        )
        assert rule.source_language == "kql"
        assert "SecurityEvent" in rule.data_sources
        assert rule.filter is not None

    def test_parse_summarize(self):
        rule = self.parser.parse(
            'SecurityEvent\n| where EventID == 4688\n| summarize count() by Computer'
        )
        assert rule.aggregation is not None
        assert rule.aggregation.function == "count"
        assert "Computer" in rule.aggregation.group_by

    def test_parse_string_operators(self):
        kql = 'Logs\n| where Name startswith "admin"\n| where Path endswith ".exe"'
        rule = self.parser.parse(kql)
        assert rule.filter is not None
        assert "Name" in rule.referenced_fields
        assert "Path" in rule.referenced_fields


# ── ESQL Parser Tests ───────────────────────────────────────────────────

class TestESQLParser:
    def setup_method(self):
        self.parser = ESQLParser()

    def test_supports_esql(self):
        assert self.parser.supports('FROM logs-* | WHERE event.category == "process"')

    def test_parse_basic_esql(self):
        rule = self.parser.parse(
            'FROM logs-*\n| WHERE event.category == "process"\n| WHERE process.name == "powershell.exe"'
        )
        assert rule.source_language == "esql"
        assert "logs-*" in rule.data_sources
        assert rule.filter is not None

    def test_parse_stats(self):
        rule = self.parser.parse(
            'FROM logs-*\n| STATS count = COUNT(*) BY host.name'
        )
        assert rule.aggregation is not None
        assert rule.aggregation.function == "count"
        assert "host.name" in rule.aggregation.group_by

    def test_parse_like(self):
        rule = self.parser.parse(
            'FROM logs-*\n| WHERE process.name LIKE "*powershell*"'
        )
        assert rule.filter is not None
        assert "process.name" in rule.referenced_fields


# ── Evaluator Tests ─────────────────────────────────────────────────────

class TestRuleEvaluator:
    def setup_method(self):
        self.evaluator = RuleEvaluator()

    def test_simple_equals(self):
        rule = ParsedRule(
            source_language="test",
            raw_text="test",
            name="test",
            filter=LogicGroup(LogicOp.AND, [
                Condition("EventCode", Operator.EQUALS, "1"),
            ]),
        )
        logs = [
            {"EventCode": "1", "User": "admin"},
            {"EventCode": "2", "User": "admin"},
        ]
        result = self.evaluator.evaluate(rule, logs)
        assert result.fired
        assert result.matched_count == 1
        assert 0 in result.matched_log_indices

    def test_contains(self):
        rule = ParsedRule(
            source_language="test",
            raw_text="test",
            name="test",
            filter=LogicGroup(LogicOp.AND, [
                Condition("CommandLine", Operator.CONTAINS, "powershell", case_insensitive=True),
            ]),
        )
        logs = [
            {"CommandLine": "PowerShell.exe -enc abc"},
            {"CommandLine": "notepad.exe"},
        ]
        result = self.evaluator.evaluate(rule, logs)
        assert result.fired
        assert result.matched_count == 1

    def test_wildcard(self):
        rule = ParsedRule(
            source_language="test",
            raw_text="test",
            name="test",
            filter=LogicGroup(LogicOp.AND, [
                Condition("Image", Operator.WILDCARD, "*\\cmd.exe", case_insensitive=True),
            ]),
        )
        logs = [
            {"Image": "C:\\Windows\\System32\\cmd.exe"},
            {"Image": "C:\\Windows\\notepad.exe"},
        ]
        result = self.evaluator.evaluate(rule, logs)
        assert result.fired
        assert result.matched_count == 1

    def test_and_logic(self):
        rule = ParsedRule(
            source_language="test",
            raw_text="test",
            name="test",
            filter=LogicGroup(LogicOp.AND, [
                Condition("EventCode", Operator.EQUALS, "1"),
                Condition("User", Operator.EQUALS, "admin"),
            ]),
        )
        logs = [
            {"EventCode": "1", "User": "admin"},
            {"EventCode": "1", "User": "system"},
            {"EventCode": "2", "User": "admin"},
        ]
        result = self.evaluator.evaluate(rule, logs)
        assert result.matched_count == 1

    def test_or_logic(self):
        rule = ParsedRule(
            source_language="test",
            raw_text="test",
            name="test",
            filter=LogicGroup(LogicOp.OR, [
                Condition("EventCode", Operator.EQUALS, "1"),
                Condition("EventCode", Operator.EQUALS, "2"),
            ]),
        )
        logs = [
            {"EventCode": "1"},
            {"EventCode": "2"},
            {"EventCode": "3"},
        ]
        result = self.evaluator.evaluate(rule, logs)
        assert result.matched_count == 2

    def test_not_logic(self):
        rule = ParsedRule(
            source_language="test",
            raw_text="test",
            name="test",
            filter=LogicGroup(LogicOp.AND, [
                Condition("EventCode", Operator.EQUALS, "1"),
                LogicGroup(LogicOp.NOT, [
                    Condition("User", Operator.EQUALS, "SYSTEM"),
                ]),
            ]),
        )
        logs = [
            {"EventCode": "1", "User": "admin"},
            {"EventCode": "1", "User": "SYSTEM"},
        ]
        result = self.evaluator.evaluate(rule, logs)
        assert result.matched_count == 1
        assert 0 in result.matched_log_indices

    def test_dot_notation(self):
        rule = ParsedRule(
            source_language="test",
            raw_text="test",
            name="test",
            filter=LogicGroup(LogicOp.AND, [
                Condition("process.name", Operator.EQUALS, "powershell.exe"),
            ]),
        )
        logs = [
            {"process": {"name": "powershell.exe"}},
            {"process": {"name": "notepad.exe"}},
        ]
        result = self.evaluator.evaluate(rule, logs)
        assert result.matched_count == 1

    def test_aggregation_count(self):
        rule = ParsedRule(
            source_language="test",
            raw_text="test",
            name="test",
            filter=LogicGroup(LogicOp.AND, [
                Condition("EventCode", Operator.EQUALS, "1"),
            ]),
            aggregation=Aggregation(
                function="count",
                group_by=["Computer"],
                condition=Condition("count", Operator.GT, 2),
            ),
        )
        logs = [
            {"EventCode": "1", "Computer": "WS01"},
            {"EventCode": "1", "Computer": "WS01"},
            {"EventCode": "1", "Computer": "WS01"},
            {"EventCode": "1", "Computer": "WS02"},
            {"EventCode": "2", "Computer": "WS01"},
        ]
        result = self.evaluator.evaluate(rule, logs)
        assert result.fired  # WS01 has count=3 > 2
        assert result.aggregation_result is not None

    def test_aggregation_not_met(self):
        rule = ParsedRule(
            source_language="test",
            raw_text="test",
            name="test",
            filter=LogicGroup(LogicOp.AND, [
                Condition("EventCode", Operator.EQUALS, "1"),
            ]),
            aggregation=Aggregation(
                function="count",
                group_by=["Computer"],
                condition=Condition("count", Operator.GT, 10),
            ),
        )
        logs = [
            {"EventCode": "1", "Computer": "WS01"},
            {"EventCode": "1", "Computer": "WS01"},
        ]
        result = self.evaluator.evaluate(rule, logs)
        assert not result.fired  # count=2, not > 10

    def test_field_mapping(self):
        evaluator = RuleEvaluator(field_mapping={"process.name": "Image"})
        rule = ParsedRule(
            source_language="test",
            raw_text="test",
            name="test",
            filter=LogicGroup(LogicOp.AND, [
                Condition("process.name", Operator.EQUALS, "cmd.exe"),
            ]),
        )
        logs = [{"Image": "cmd.exe"}]
        result = evaluator.evaluate(rule, logs)
        assert result.fired

    def test_empty_logs(self):
        rule = ParsedRule(
            source_language="test",
            raw_text="test",
            name="test",
            filter=LogicGroup(LogicOp.AND, [
                Condition("EventCode", Operator.EQUALS, "1"),
            ]),
        )
        result = self.evaluator.evaluate(rule, [])
        assert not result.fired
        assert result.matched_count == 0

    def test_no_filter(self):
        rule = ParsedRule(source_language="test", raw_text="test", name="test")
        result = self.evaluator.evaluate(rule, [{"a": 1}, {"b": 2}])
        assert result.fired
        assert result.matched_count == 2

    def test_numeric_comparison(self):
        rule = ParsedRule(
            source_language="test",
            raw_text="test",
            name="test",
            filter=LogicGroup(LogicOp.AND, [
                Condition("score", Operator.GT, 50),
            ]),
        )
        logs = [{"score": 75}, {"score": 30}]
        result = self.evaluator.evaluate(rule, logs)
        assert result.matched_count == 1

    def test_in_operator(self):
        rule = ParsedRule(
            source_language="test",
            raw_text="test",
            name="test",
            filter=LogicGroup(LogicOp.AND, [
                Condition("User", Operator.IN, ["admin", "root"], case_insensitive=True),
            ]),
        )
        logs = [{"User": "Admin"}, {"User": "guest"}, {"User": "ROOT"}]
        result = self.evaluator.evaluate(rule, logs)
        assert result.matched_count == 2

    def test_exists_operator(self):
        rule = ParsedRule(
            source_language="test",
            raw_text="test",
            name="test",
            filter=LogicGroup(LogicOp.AND, [
                Condition("optional_field", Operator.EXISTS, True),
            ]),
        )
        logs = [{"optional_field": "value"}, {"other_field": "x"}]
        result = self.evaluator.evaluate(rule, logs)
        assert result.matched_count == 1


# ── Sigma + Evaluator Integration Tests ─────────────────────────────────

class TestSigmaEvaluation:
    """Test Sigma rules parsed and evaluated end-to-end."""

    def setup_method(self):
        self.parser = SigmaParser()
        self.evaluator = RuleEvaluator()

    def test_selection_and_not_filter(self):
        rule = self.parser.parse(SIGMA_RULE)
        logs = [
            {"CommandLine": "powershell -enc base64", "ParentImage": "C:\\Windows\\explorer.exe", "User": "admin"},
            {"CommandLine": "notepad.exe", "ParentImage": "C:\\Windows\\explorer.exe", "User": "admin"},
            {"CommandLine": "cmd.exe /c whoami", "ParentImage": "C:\\Windows\\explorer.exe", "User": "SYSTEM"},
        ]
        result = self.evaluator.evaluate(rule, logs)
        assert result.fired
        # Log 0: matches (powershell + explorer + not SYSTEM)
        # Log 1: no match (notepad, not powershell/cmd)
        # Log 2: matches selection (cmd.exe + explorer) but filtered (SYSTEM)
        assert result.matched_count == 1
        assert 0 in result.matched_log_indices


# ── Coverage Analyzer Tests ─────────────────────────────────────────────

class TestCoverageAnalyzer:
    def setup_method(self):
        self.analyzer = CoverageAnalyzer()

    def test_compute_coverage(self):
        rules = [
            ParsedRule(source_language="test", raw_text="", name="R1",
                       mitre_techniques=["T1059.001"]),
            ParsedRule(source_language="test", raw_text="", name="R2",
                       mitre_techniques=["T1003"]),
        ]
        matrix = self.analyzer.compute_coverage(rules)
        assert matrix.total_techniques_covered == 2
        assert "T1059.001" in matrix.techniques
        assert "T1003" in matrix.techniques

    def test_identify_gaps(self):
        rules = [
            ParsedRule(source_language="test", raw_text="", name="R1",
                       mitre_techniques=["T1059.001"]),
        ]
        gaps = self.analyzer.identify_gaps(rules, ["T1059", "T1003", "T1486"])
        assert "T1059" in gaps.covered_techniques
        assert "T1003" in gaps.uncovered_techniques
        assert "T1486" in gaps.uncovered_techniques
        assert gaps.coverage_pct > 0

    def test_efficacy_score(self):
        rule = ParsedRule(
            source_language="test", raw_text="", name="R1",
            description="A rule", mitre_techniques=["T1059"],
            severity="high",
            filter=LogicGroup(LogicOp.AND, [Condition("x", Operator.EQUALS, "1")]),
        )
        results = [
            EvalResult(rule_name="R1", fired=True, matched_count=5, total_logs=10),
            EvalResult(rule_name="R1", fired=True, matched_count=3, total_logs=10),
        ]
        score = self.analyzer.compute_efficacy_score(rule, results)
        assert 0 < score <= 100


# ── Rule Manager Tests ──────────────────────────────────────────────────

class TestRuleManager:
    def setup_method(self):
        self.manager = RuleManager()

    def test_import_sigma(self):
        rules = asyncio.run(self.manager.import_rules(SIGMA_RULE, "sigma"))
        assert len(rules) == 1
        assert rules[0].name == "Suspicious PowerShell Execution"

    def test_import_spl(self):
        rules = asyncio.run(self.manager.import_rules(
            'index=main sourcetype=sysmon EventCode=1', "spl"
        ))
        assert len(rules) == 1

    def test_detect_language_sigma(self):
        lang = asyncio.run(self.manager.detect_language(SIGMA_RULE))
        assert lang == "sigma"

    def test_detect_language_spl(self):
        lang = asyncio.run(self.manager.detect_language(
            'index=main sourcetype=sysmon | stats count by Computer'
        ))
        assert lang == "spl"

    def test_batch_evaluate(self):
        rules = asyncio.run(self.manager.import_rules(SIGMA_RULE, "sigma"))
        logs = [
            {"CommandLine": "powershell.exe -enc abc", "ParentImage": "C:\\Windows\\explorer.exe", "User": "admin"},
        ]
        batch = asyncio.run(self.manager.batch_evaluate(rules, logs))
        assert batch.total_rules == 1
        assert batch.rules_fired == 1
        assert batch.coverage is not None

    def test_import_auto_detect(self):
        rules = asyncio.run(self.manager.import_rules(SIGMA_RULE, "auto"))
        assert len(rules) == 1
        assert rules[0].source_language == "sigma"
