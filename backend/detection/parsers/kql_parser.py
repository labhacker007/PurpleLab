"""Kusto Query Language (KQL) parser for Microsoft Sentinel rules.

Parses detection-relevant KQL into the unified AST. Handles where
clauses, summarize aggregations, extend/project field references,
and table source identification.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from backend.detection.parsers.base_parser import (
    AbstractParser,
    Aggregation,
    Condition,
    LogicGroup,
    LogicOp,
    Operator,
    ParsedRule,
)

log = logging.getLogger(__name__)


class KQLParser(AbstractParser):
    """Parser for KQL detection rules (Microsoft Sentinel).

    Handles Sentinel analytics rule patterns:
    - where clauses with comparison operators
    - contains, startswith, endswith, matches regex, in, !in
    - summarize (aggregation) with count, dcount, sum
    - project (field selection)
    - extend (computed fields)

    Example::

        SecurityEvent
        | where EventID == 4688
        | where CommandLine contains "powershell"
        | where ParentProcessName endswith "explorer.exe"
        | summarize count() by Computer, Account
        | where count_ > 5
    """

    language = "kql"

    def parse(self, rule_text: str, **kwargs) -> ParsedRule:
        """Parse a KQL query into the unified AST.

        Args:
            rule_text: Raw KQL query string.

        Returns:
            ParsedRule with filter, aggregation, and metadata.

        Raises:
            ValueError: If the query is empty or cannot be parsed.
        """
        rule_text = rule_text.strip()
        if not rule_text:
            raise ValueError("KQL query is empty")

        segments = self._split_pipes(rule_text)
        if not segments:
            raise ValueError("KQL query has no segments")

        data_sources: list[str] = []
        referenced_fields: set[str] = set()
        all_conditions: list[Condition | LogicGroup] = []
        aggregation: Aggregation | None = None

        for i, segment in enumerate(segments):
            segment = segment.strip()
            if not segment:
                continue

            seg_lower = segment.lower().lstrip()

            if i == 0 and not seg_lower.startswith("where ") and not seg_lower.startswith("let "):
                # First segment is typically the table name
                table_name = segment.strip()
                # Could be "TableName" or "TableName | where ..."
                if table_name and not table_name.startswith("//"):
                    data_sources.append(table_name)
                continue

            if seg_lower.startswith("where "):
                conds, fields = self._parse_where_clause(segment[6:])
                all_conditions.extend(conds)
                referenced_fields.update(fields)
            elif seg_lower.startswith("summarize "):
                agg = self._parse_summarize_clause(segment[10:])
                if agg:
                    aggregation = agg
                    if agg.field:
                        referenced_fields.add(agg.field)
                    referenced_fields.update(agg.group_by)
            elif seg_lower.startswith("extend "):
                fields = self._extract_extend_fields(segment[7:])
                referenced_fields.update(fields)
            elif seg_lower.startswith("project "):
                fields = self._extract_project_fields(segment[8:])
                referenced_fields.update(fields)
            elif seg_lower.startswith("let "):
                # Let statements define variables -- extract field refs
                fields = self._extract_let_fields(segment[4:])
                referenced_fields.update(fields)

        # Build filter AST
        filter_ast: LogicGroup | None = None
        if all_conditions:
            if len(all_conditions) == 1 and isinstance(all_conditions[0], LogicGroup):
                filter_ast = all_conditions[0]
            else:
                filter_ast = LogicGroup(LogicOp.AND, all_conditions)

        return ParsedRule(
            source_language="kql",
            raw_text=rule_text,
            name=kwargs.get("name", ""),
            description=kwargs.get("description", ""),
            severity=kwargs.get("severity", "medium"),
            filter=filter_ast,
            aggregation=aggregation,
            referenced_fields=referenced_fields,
            data_sources=data_sources,
        )

    def supports(self, rule_text: str) -> bool:
        """Check if text looks like KQL.

        Args:
            rule_text: Raw text to check.

        Returns:
            True if this looks like a KQL query.
        """
        text = rule_text.strip().lower()
        kql_indicators = [
            "| where ", "| summarize ", "| extend ", "| project ",
            " contains ", " startswith ", " endswith ", " has ",
            " !contains ", " !startswith ", " !endswith ", " !has ",
            "| join ", "| union ", " matches regex ",
        ]
        # Also check for known Sentinel table names
        sentinel_tables = [
            "securityevent", "signinlogs", "auditlogs", "commonlogevent",
            "syslog", "deviceprocessevents", "devicenetworkevents",
            "officeactivity", "azureactivity", "securityalert",
        ]
        first_line = text.split("|")[0].strip().split("\n")[0].strip()
        if first_line.lower() in sentinel_tables:
            return True
        return any(ind in text for ind in kql_indicators)

    # ── Pipe Splitting ───────────────────────────────────────────────────

    def _split_pipes(self, query: str) -> list[str]:
        """Split KQL query on pipe characters, respecting quotes and newlines.

        KQL uses | as pipe delimiter. We also handle multi-line queries
        where lines may start with |.

        Args:
            query: Raw KQL query.

        Returns:
            List of command segments.
        """
        # Normalize: join lines, then split on |
        # But be careful: | can appear inside strings
        segments: list[str] = []
        current: list[str] = []
        in_quote: str | None = None
        i = 0
        text = query.replace("\r\n", "\n")

        while i < len(text):
            ch = text[i]
            if ch in ('"', "'") and (i == 0 or text[i - 1] != "\\"):
                if in_quote == ch:
                    in_quote = None
                elif in_quote is None:
                    in_quote = ch
                current.append(ch)
            elif ch == "|" and in_quote is None:
                segments.append("".join(current).strip())
                current = []
            elif ch == "\n" and in_quote is None:
                current.append(" ")
            else:
                current.append(ch)
            i += 1

        if current:
            seg = "".join(current).strip()
            if seg:
                segments.append(seg)

        return segments

    # ── Where Clause Parsing ─────────────────────────────────────────────

    def _parse_where_clause(
        self, clause: str
    ) -> tuple[list[Condition | LogicGroup], set[str]]:
        """Parse a KQL where clause into conditions.

        Handles:
        - field == "value" / field != "value"
        - field contains "value" / field !contains "value"
        - field startswith "value" / field endswith "value"
        - field matches regex "pattern"
        - field in ("a", "b") / field !in ("a", "b")
        - field has "value" / field !has "value"
        - isnotempty(field) / isempty(field)
        - AND, OR, NOT combinations

        Args:
            clause: Where clause text (without 'where' prefix).

        Returns:
            Tuple of (conditions, referenced_fields).
        """
        clause = clause.strip()
        fields: set[str] = set()

        # Parse into a logic tree
        result = self._parse_kql_or(clause, fields)
        if result is None:
            return [], fields
        if isinstance(result, Condition):
            return [result], fields
        return [result], fields

    def _parse_kql_or(
        self, expr: str, fields: set[str]
    ) -> Condition | LogicGroup | None:
        """Parse OR-level KQL expressions.

        Args:
            expr: Expression string.
            fields: Accumulator for field names.

        Returns:
            Condition or LogicGroup.
        """
        parts = self._split_on_logic_op(expr, "or")
        if len(parts) == 1:
            return self._parse_kql_and(parts[0].strip(), fields)

        children = []
        for part in parts:
            child = self._parse_kql_and(part.strip(), fields)
            if child:
                children.append(child)
        if not children:
            return None
        if len(children) == 1:
            return children[0]
        return LogicGroup(LogicOp.OR, children)

    def _parse_kql_and(
        self, expr: str, fields: set[str]
    ) -> Condition | LogicGroup | None:
        """Parse AND-level KQL expressions.

        Args:
            expr: Expression string.
            fields: Accumulator for field names.

        Returns:
            Condition or LogicGroup.
        """
        parts = self._split_on_logic_op(expr, "and")
        if len(parts) == 1:
            return self._parse_kql_atom(parts[0].strip(), fields)

        children = []
        for part in parts:
            child = self._parse_kql_atom(part.strip(), fields)
            if child:
                children.append(child)
        if not children:
            return None
        if len(children) == 1:
            return children[0]
        return LogicGroup(LogicOp.AND, children)

    def _parse_kql_atom(
        self, expr: str, fields: set[str]
    ) -> Condition | LogicGroup | None:
        """Parse an atomic KQL expression (single comparison or NOT/parens).

        Args:
            expr: Expression string.
            fields: Accumulator for field names.

        Returns:
            Condition or LogicGroup, or None.
        """
        expr = expr.strip()
        if not expr:
            return None

        # Handle NOT prefix
        if expr.lower().startswith("not "):
            inner = self._parse_kql_atom(expr[4:].strip(), fields)
            if inner:
                return LogicGroup(LogicOp.NOT, [inner])
            return None

        # Handle parenthesized expression
        if expr.startswith("(") and expr.endswith(")"):
            return self._parse_kql_or(expr[1:-1].strip(), fields)

        # Handle isnotempty(field) / isempty(field)
        isnotempty_match = re.match(r'isnotempty\s*\(\s*([\w.]+)\s*\)', expr, re.IGNORECASE)
        if isnotempty_match:
            field_name = isnotempty_match.group(1)
            fields.add(field_name)
            return Condition(field_name, Operator.EXISTS, True)

        isempty_match = re.match(r'isempty\s*\(\s*([\w.]+)\s*\)', expr, re.IGNORECASE)
        if isempty_match:
            field_name = isempty_match.group(1)
            fields.add(field_name)
            return Condition(field_name, Operator.NOT_EXISTS, True)

        # Handle IN / !IN: field in ("a", "b") or field !in ("a", "b")
        in_match = re.match(
            r'([\w.]+)\s+(!?in)\s*\(([^)]+)\)',
            expr, re.IGNORECASE,
        )
        if in_match:
            field_name = in_match.group(1)
            op_str = in_match.group(2).lower()
            values_str = in_match.group(3)
            values = [self._strip_quotes(v.strip()) for v in values_str.split(",")]
            fields.add(field_name)
            operator = Operator.NOT_IN if op_str == "!in" else Operator.IN
            return Condition(field_name, operator, values, case_insensitive=True)

        # Handle "in~" (case insensitive in)
        in_ci_match = re.match(
            r'([\w.]+)\s+in~\s*\(([^)]+)\)',
            expr, re.IGNORECASE,
        )
        if in_ci_match:
            field_name = in_ci_match.group(1)
            values_str = in_ci_match.group(2)
            values = [self._strip_quotes(v.strip()) for v in values_str.split(",")]
            fields.add(field_name)
            return Condition(field_name, Operator.IN, values, case_insensitive=True)

        # String operators: contains, !contains, startswith, endswith, has, matches regex
        str_op_match = re.match(
            r'([\w.]+)\s+(!?(?:contains|startswith|endswith|has|matches\s+regex|contains_cs|has_cs))\s+(.+)',
            expr, re.IGNORECASE,
        )
        if str_op_match:
            field_name = str_op_match.group(1)
            op_str = str_op_match.group(2).lower().strip()
            value = self._strip_quotes(str_op_match.group(3).strip())
            fields.add(field_name)

            negated = op_str.startswith("!")
            if negated:
                op_str = op_str[1:]

            case_insensitive = not op_str.endswith("_cs")
            if op_str.endswith("_cs"):
                op_str = op_str[:-3]

            op_map = {
                "contains": Operator.CONTAINS,
                "startswith": Operator.STARTS_WITH,
                "endswith": Operator.ENDS_WITH,
                "has": Operator.CONTAINS,
                "matches regex": Operator.REGEX,
            }
            operator = op_map.get(op_str, Operator.CONTAINS)
            cond = Condition(field_name, operator, value, case_insensitive=case_insensitive)

            if negated:
                return LogicGroup(LogicOp.NOT, [cond])
            return cond

        # Comparison operators: ==, !=, >=, <=, >, <
        comp_match = re.match(
            r'([\w.]+)\s*(==|!=|>=|<=|>|<)\s*(.+)',
            expr,
        )
        if comp_match:
            field_name = comp_match.group(1)
            op_str = comp_match.group(2)
            value = self._strip_quotes(comp_match.group(3).strip())
            fields.add(field_name)

            op_map = {
                "==": Operator.EQUALS, "!=": Operator.NOT_EQUALS,
                ">": Operator.GT, ">=": Operator.GTE,
                "<": Operator.LT, "<=": Operator.LTE,
            }
            operator = op_map.get(op_str, Operator.EQUALS)
            value = self._try_numeric(value)
            return Condition(field_name, operator, value, case_insensitive=True)

        return None

    def _split_on_logic_op(self, expr: str, op: str) -> list[str]:
        """Split expression on a logical operator, respecting parens and quotes.

        Args:
            expr: Expression string.
            op: "and" or "or".

        Returns:
            List of expression parts.
        """
        parts: list[str] = []
        current: list[str] = []
        depth = 0
        in_quote: str | None = None
        tokens = expr.split()
        i = 0

        while i < len(tokens):
            token = tokens[i]

            # Track quotes
            for ch in token:
                if ch in ('"', "'") and in_quote is None:
                    in_quote = ch
                elif ch == in_quote:
                    in_quote = None

            # Track parentheses
            depth += token.count("(") - token.count(")")

            if (in_quote is None and depth == 0
                    and token.lower() == op):
                if current:
                    parts.append(" ".join(current))
                    current = []
            else:
                current.append(token)
            i += 1

        if current:
            parts.append(" ".join(current))

        return parts if parts else [expr]

    # ── Summarize Clause Parsing ─────────────────────────────────────────

    def _parse_summarize_clause(self, clause: str) -> Aggregation | None:
        """Parse a KQL summarize clause into an Aggregation.

        Handles:
        - summarize count() by field1, field2
        - summarize dcount(field) by field1
        - summarize sum(field) by field1

        Args:
            clause: Summarize clause text (without 'summarize' prefix).

        Returns:
            Aggregation or None.
        """
        clause = clause.strip()

        # Split on "by" (case insensitive)
        by_match = re.split(r'\bby\b', clause, flags=re.IGNORECASE, maxsplit=1)
        agg_part = by_match[0].strip()
        group_part = by_match[1].strip() if len(by_match) > 1 else ""

        # Parse aggregation function
        func_match = re.match(
            r'(?:\w+\s*=\s*)?(count|dcount|sum|avg|min|max|countif)\s*\(\s*([\w.*]*)\s*\)',
            agg_part, re.IGNORECASE,
        )
        if not func_match:
            return None

        func = func_match.group(1).lower()
        agg_field = func_match.group(2) or None
        if agg_field in ("*", ""):
            agg_field = None

        # Map KQL function names to our standard names
        func_map = {"dcount": "dc", "countif": "count"}
        func = func_map.get(func, func)

        # Parse group by fields
        group_by: list[str] = []
        if group_part:
            group_by = [f.strip() for f in group_part.split(",") if f.strip()]

        return Aggregation(function=func, field=agg_field, group_by=group_by)

    # ── Field Extraction ─────────────────────────────────────────────────

    def _extract_extend_fields(self, clause: str) -> set[str]:
        """Extract field references from an extend clause.

        Args:
            clause: Extend clause text.

        Returns:
            Set of field names.
        """
        fields: set[str] = set()
        # Pattern: NewField = expression
        for match in re.finditer(r'(\w+)\s*=', clause):
            fields.add(match.group(1))
        # Also extract field references in expressions
        for match in re.finditer(r'\b([\w][\w.]*)\b', clause):
            name = match.group(1)
            if name.lower() not in ("true", "false", "null", "and", "or", "not",
                                     "tostring", "toint", "todatetime", "strcat",
                                     "tolower", "toupper", "trim"):
                fields.add(name)
        return fields

    def _extract_project_fields(self, clause: str) -> set[str]:
        """Extract field names from a project clause.

        Args:
            clause: Project clause text.

        Returns:
            Set of field names.
        """
        return {f.strip() for f in clause.split(",") if f.strip()}

    def _extract_let_fields(self, clause: str) -> set[str]:
        """Extract field references from a let statement.

        Args:
            clause: Let clause text.

        Returns:
            Set of field names.
        """
        fields: set[str] = set()
        for match in re.finditer(r'\b([\w][\w.]*)\b', clause):
            name = match.group(1)
            if name.lower() not in ("true", "false", "null"):
                fields.add(name)
        return fields

    # ── Utilities ────────────────────────────────────────────────────────

    @staticmethod
    def _strip_quotes(value: str) -> str:
        """Remove surrounding quotes from a value.

        Args:
            value: Value that may be quoted.

        Returns:
            Unquoted value.
        """
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'", "@"):
            return value[1:-1] if value[0] != "@" else value[1:]
        # Handle @"..." strings (KQL verbatim strings)
        if value.startswith('@"') and value.endswith('"'):
            return value[2:-1]
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            return value[1:-1]
        return value

    @staticmethod
    def _try_numeric(value: Any) -> Any:
        """Try to convert a string value to a number.

        Args:
            value: Value to convert.

        Returns:
            Numeric value if possible, original otherwise.
        """
        if not isinstance(value, str):
            return value
        try:
            if "." in value:
                return float(value)
            return int(value)
        except (ValueError, TypeError):
            return value
