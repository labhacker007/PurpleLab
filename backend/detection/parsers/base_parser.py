"""Unified AST and abstract parser interface for detection rule languages.

Defines the core data structures that represent detection logic in a
language-agnostic way. All parser implementations convert their native
format into this unified AST, which is then evaluated by the RuleEvaluator.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field as dataclass_field
from enum import Enum
from typing import Any, Union


# ── AST Node Types ──────────────────────────────────────────────────────────


class Operator(Enum):
    """Comparison operators for field-level conditions."""
    EQUALS = "eq"
    NOT_EQUALS = "neq"
    CONTAINS = "contains"
    STARTS_WITH = "startswith"
    ENDS_WITH = "endswith"
    REGEX = "regex"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    IN = "in"
    NOT_IN = "not_in"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    WILDCARD = "wildcard"  # For * patterns like "cmd*.exe"


class LogicOp(Enum):
    """Logical operators for combining conditions."""
    AND = "and"
    OR = "or"
    NOT = "not"


@dataclass
class Condition:
    """A single field comparison: field_name op value.

    Examples:
        Condition("CommandLine", Operator.CONTAINS, "powershell")
        Condition("EventCode", Operator.EQUALS, 1)
        Condition("Image", Operator.WILDCARD, "*\\\\cmd.exe")
    """
    field: str
    operator: Operator
    value: Any
    case_insensitive: bool = False


@dataclass
class LogicGroup:
    """Logical combination of conditions: (cond1 AND cond2) OR cond3.

    Examples:
        LogicGroup(LogicOp.AND, [
            Condition("EventCode", Operator.EQUALS, "1"),
            LogicGroup(LogicOp.OR, [
                Condition("Image", Operator.ENDSWITH, "cmd.exe"),
                Condition("Image", Operator.ENDSWITH, "powershell.exe"),
            ])
        ])
    """
    operator: LogicOp
    children: list[Union[Condition, 'LogicGroup']] = dataclass_field(default_factory=list)


@dataclass
class Aggregation:
    """Aggregation clause: function(field) BY group_fields WHERE threshold.

    Examples:
        # count by Computer where count > 5
        Aggregation("count", None, ["Computer"], Condition("count", Operator.GT, 5))

        # dc(User) by Computer where dc > 3
        Aggregation("dc", "User", ["Computer"], Condition("dc", Operator.GT, 3))
    """
    function: str  # "count", "sum", "avg", "min", "max", "dc" (distinct count)
    field: str | None = None  # Field to aggregate (None for count(*))
    group_by: list[str] = dataclass_field(default_factory=list)
    condition: Condition | None = None  # threshold condition (e.g., count > 5)


@dataclass
class ParsedRule:
    """Unified AST for any detection rule.

    This is the central data structure of the detection engine. Every parser
    converts its native format (Sigma YAML, SPL, KQL, ES|QL) into this
    common representation, which is then evaluated by the RuleEvaluator.

    Example:
        ParsedRule(
            source_language="sigma",
            raw_text="<yaml>",
            name="Suspicious PowerShell",
            severity="high",
            filter=LogicGroup(LogicOp.AND, [
                Condition("CommandLine", Operator.CONTAINS, "powershell"),
                Condition("ParentImage", Operator.ENDSWITH, "explorer.exe"),
            ]),
            mitre_techniques=["T1059.001"],
        )
    """
    source_language: str  # "spl", "kql", "sigma", "esql"
    raw_text: str
    name: str = ""
    description: str = ""
    severity: str = "medium"
    mitre_techniques: list[str] = dataclass_field(default_factory=list)

    # The detection logic
    filter: LogicGroup | None = None  # WHERE/search conditions
    aggregation: Aggregation | None = None  # stats/summarize/count

    # Field references (for coverage analysis)
    referenced_fields: set[str] = dataclass_field(default_factory=set)

    # Metadata
    data_sources: list[str] = dataclass_field(default_factory=list)
    tags: list[str] = dataclass_field(default_factory=list)


# ── Abstract Parser ─────────────────────────────────────────────────────────


class AbstractParser(ABC):
    """Base class for all rule parsers.

    Each parser converts a specific detection language into the unified
    ParsedRule AST. Parsers do NOT evaluate rules -- that is the job
    of the RuleEvaluator.
    """

    language: str = ""

    @abstractmethod
    def parse(self, rule_text: str, **kwargs) -> ParsedRule:
        """Parse a rule into the unified AST.

        Args:
            rule_text: The raw detection rule text.
            **kwargs: Parser-specific options.

        Returns:
            A ParsedRule containing the unified AST representation.

        Raises:
            ValueError: If the rule text cannot be parsed.
        """
        ...

    @abstractmethod
    def supports(self, rule_text: str) -> bool:
        """Check if this parser can handle the given rule text.

        Args:
            rule_text: The raw detection rule text.

        Returns:
            True if this parser can parse the rule.
        """
        ...

    def extract_fields(self, query: str) -> list[str]:
        """Extract field names referenced in the query.

        Default implementation returns empty list.
        Subclasses should override for language-specific extraction.
        """
        return []

    def extract_data_sources(self, query: str) -> list[str]:
        """Extract data source references from the query.

        Default implementation returns empty list.
        """
        return []
