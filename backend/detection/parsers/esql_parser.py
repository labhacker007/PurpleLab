"""Elasticsearch Query Language (ES|QL) parser.

Parses detection-relevant ES|QL into the unified AST. Handles FROM
sources, WHERE clauses, STATS aggregations, and EVAL computed fields.
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


class ESQLParser(AbstractParser):
    """Parser for ES|QL detection rules (Elastic Security).

    Handles the detection-relevant subset of ES|QL:
    - FROM source
    - WHERE with ==, !=, LIKE, RLIKE, IN, IS NULL, IS NOT NULL
    - STATS aggregations with COUNT, SUM, AVG, MIN, MAX
    - EVAL computed fields
    - AND, OR, NOT logic

    Example::

        FROM logs-*
        | WHERE event.category == "process" AND process.name == "powershell.exe"
        | WHERE process.command_line LIKE "*encoded*"
        | STATS count = COUNT(*) BY host.name, user.name
        | WHERE count > 5
    """

    language = "esql"

    def parse(self, rule_text: str, **kwargs) -> ParsedRule:
        """Parse an ES|QL query into the unified AST.

        Args:
            rule_text: Raw ES|QL query string.

        Returns:
            ParsedRule with filter, aggregation, and metadata.

        Raises:
            ValueError: If the query is empty.
        """
        rule_text = rule_text.strip()
        if not rule_text:
            raise ValueError("ES|QL query is empty")

        segments = self._split_pipes(rule_text)
        if not segments:
            raise ValueError("ES|QL query has no segments")

        data_sources: list[str] = []
        referenced_fields: set[str] = set()
        all_conditions: list[Condition | LogicGroup] = []
        aggregation: Aggregation | None = None

        for segment in segments:
            segment = segment.strip()
            if not segment:
                continue

            seg_upper = segment.upper().lstrip()

            if seg_upper.startswith("FROM "):
                source = segment[5:].strip()
                # Remove METADATA clause if present
                meta_idx = source.upper().find("METADATA")
                if meta_idx > 0:
                    source = source[:meta_idx].strip()
                data_sources.append(source)
            elif seg_upper.startswith("WHERE "):
                conds, fields = self._parse_where_clause(segment[6:])
                all_conditions.extend(conds)
                referenced_fields.update(fields)
            elif seg_upper.startswith("STATS "):
                agg = self._parse_stats_clause(segment[6:])
                if agg:
                    aggregation = agg
                    if agg.field:
                        referenced_fields.add(agg.field)
                    referenced_fields.update(agg.group_by)
            elif seg_upper.startswith("EVAL "):
                fields = self._extract_eval_fields(segment[5:])
                referenced_fields.update(fields)
            elif seg_upper.startswith("KEEP ") or seg_upper.startswith("DROP "):
                # Field list commands
                field_list = segment.split(None, 1)[1] if " " in segment else ""
                for f in field_list.split(","):
                    f = f.strip()
                    if f:
                        referenced_fields.add(f)
            elif seg_upper.startswith("SORT "):
                # Extract field references from sort
                sort_clause = segment[5:].strip()
                for f in re.findall(r'\b([\w][\w.]*)\b', sort_clause):
                    if f.upper() not in ("ASC", "DESC", "NULLS", "FIRST", "LAST"):
                        referenced_fields.add(f)
            elif seg_upper.startswith("LIMIT "):
                pass  # Nothing to extract
            elif seg_upper.startswith("RENAME "):
                # Extract field refs from rename
                for match in re.finditer(r'\b([\w][\w.]*)\b', segment[7:]):
                    name = match.group(1)
                    if name.upper() != "AS":
                        referenced_fields.add(name)

        # Build filter AST
        filter_ast: LogicGroup | None = None
        if all_conditions:
            if len(all_conditions) == 1 and isinstance(all_conditions[0], LogicGroup):
                filter_ast = all_conditions[0]
            else:
                filter_ast = LogicGroup(LogicOp.AND, all_conditions)

        return ParsedRule(
            source_language="esql",
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
        """Check if text looks like ES|QL.

        ES|QL is identified primarily by starting with FROM and using
        pipe-delimited commands with uppercase keywords. We require
        the FROM keyword to distinguish from KQL/SPL.

        Args:
            rule_text: Raw text to check.

        Returns:
            True if this looks like an ES|QL query.
        """
        text = rule_text.strip()
        # Strong indicator: starts with FROM
        first_line = text.split("\n")[0].split("|")[0].strip()
        if first_line.upper().startswith("FROM "):
            return True
        # Also check for ES|QL-specific commands combined with FROM elsewhere
        text_upper = text.upper()
        if "FROM " in text_upper and any(
            cmd in text_upper for cmd in ("| WHERE ", "| STATS ", "| EVAL ", "| KEEP ", "| DROP ")
        ):
            return True
        return False

    # ── Pipe Splitting ───────────────────────────────────────────────────

    def _split_pipes(self, query: str) -> list[str]:
        """Split ES|QL query on pipe characters, respecting quotes.

        Args:
            query: Raw ES|QL query.

        Returns:
            List of command segments.
        """
        segments: list[str] = []
        current: list[str] = []
        in_quote: str | None = None
        text = query.replace("\r\n", "\n")

        for i, ch in enumerate(text):
            if ch in ('"', "'") and (i == 0 or text[i - 1] != "\\"):
                if in_quote == ch:
                    in_quote = None
                elif in_quote is None:
                    in_quote = ch
                current.append(ch)
            elif ch == "|" and in_quote is None:
                seg = "".join(current).strip()
                if seg:
                    segments.append(seg)
                current = []
            elif ch == "\n" and in_quote is None:
                current.append(" ")
            else:
                current.append(ch)

        final = "".join(current).strip()
        if final:
            segments.append(final)

        return segments

    # ── WHERE Clause Parsing ─────────────────────────────────────────────

    def _parse_where_clause(
        self, clause: str
    ) -> tuple[list[Condition | LogicGroup], set[str]]:
        """Parse an ES|QL WHERE clause into conditions.

        Handles:
        - field == "value" / field != "value"
        - field LIKE "pattern" / field RLIKE "regex"
        - field IN ("a", "b")
        - field IS NULL / field IS NOT NULL
        - AND, OR, NOT combinations

        Args:
            clause: WHERE clause text (without 'WHERE' prefix).

        Returns:
            Tuple of (conditions, referenced_fields).
        """
        clause = clause.strip()
        fields: set[str] = set()

        result = self._parse_esql_or(clause, fields)
        if result is None:
            return [], fields
        if isinstance(result, Condition):
            return [result], fields
        return [result], fields

    def _parse_esql_or(
        self, expr: str, fields: set[str]
    ) -> Condition | LogicGroup | None:
        """Parse OR-level ES|QL expressions."""
        parts = self._split_on_logic_op(expr, "OR")
        if len(parts) == 1:
            return self._parse_esql_and(parts[0].strip(), fields)

        children = []
        for part in parts:
            child = self._parse_esql_and(part.strip(), fields)
            if child:
                children.append(child)
        if not children:
            return None
        if len(children) == 1:
            return children[0]
        return LogicGroup(LogicOp.OR, children)

    def _parse_esql_and(
        self, expr: str, fields: set[str]
    ) -> Condition | LogicGroup | None:
        """Parse AND-level ES|QL expressions."""
        parts = self._split_on_logic_op(expr, "AND")
        if len(parts) == 1:
            return self._parse_esql_atom(parts[0].strip(), fields)

        children = []
        for part in parts:
            child = self._parse_esql_atom(part.strip(), fields)
            if child:
                children.append(child)
        if not children:
            return None
        if len(children) == 1:
            return children[0]
        return LogicGroup(LogicOp.AND, children)

    def _parse_esql_atom(
        self, expr: str, fields: set[str]
    ) -> Condition | LogicGroup | None:
        """Parse an atomic ES|QL expression."""
        expr = expr.strip()
        if not expr:
            return None

        # Handle NOT prefix
        if expr.upper().startswith("NOT "):
            inner = self._parse_esql_atom(expr[4:].strip(), fields)
            if inner:
                return LogicGroup(LogicOp.NOT, [inner])
            return None

        # Handle parenthesized expression
        if expr.startswith("(") and expr.endswith(")"):
            return self._parse_esql_or(expr[1:-1].strip(), fields)

        # IS NOT NULL
        is_not_null = re.match(r'([\w.]+)\s+IS\s+NOT\s+NULL', expr, re.IGNORECASE)
        if is_not_null:
            field_name = is_not_null.group(1)
            fields.add(field_name)
            return Condition(field_name, Operator.EXISTS, True)

        # IS NULL
        is_null = re.match(r'([\w.]+)\s+IS\s+NULL', expr, re.IGNORECASE)
        if is_null:
            field_name = is_null.group(1)
            fields.add(field_name)
            return Condition(field_name, Operator.NOT_EXISTS, True)

        # IN clause
        in_match = re.match(
            r'([\w.]+)\s+IN\s*\(([^)]+)\)',
            expr, re.IGNORECASE,
        )
        if in_match:
            field_name = in_match.group(1)
            values_str = in_match.group(2)
            values = [self._strip_quotes(v.strip()) for v in values_str.split(",")]
            fields.add(field_name)
            return Condition(field_name, Operator.IN, values, case_insensitive=True)

        # LIKE pattern
        like_match = re.match(
            r'([\w.]+)\s+LIKE\s+["\']([^"\']*)["\']',
            expr, re.IGNORECASE,
        )
        if like_match:
            field_name = like_match.group(1)
            pattern = like_match.group(2)
            fields.add(field_name)
            # ES|QL LIKE uses * as wildcard (like SQL LIKE with % replaced)
            wildcard_pattern = pattern
            return Condition(field_name, Operator.WILDCARD, wildcard_pattern, case_insensitive=True)

        # RLIKE regex
        rlike_match = re.match(
            r'([\w.]+)\s+RLIKE\s+["\']([^"\']*)["\']',
            expr, re.IGNORECASE,
        )
        if rlike_match:
            field_name = rlike_match.group(1)
            regex_pattern = rlike_match.group(2)
            fields.add(field_name)
            return Condition(field_name, Operator.REGEX, regex_pattern, case_insensitive=True)

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
        """Split expression on a logical operator (AND/OR), respecting parens and quotes.

        Args:
            expr: Expression string.
            op: "AND" or "OR".

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

            depth += token.count("(") - token.count(")")

            if (in_quote is None and depth == 0
                    and token.upper() == op):
                if current:
                    parts.append(" ".join(current))
                    current = []
            else:
                current.append(token)
            i += 1

        if current:
            parts.append(" ".join(current))

        return parts if parts else [expr]

    # ── STATS Clause Parsing ─────────────────────────────────────────────

    def _parse_stats_clause(self, clause: str) -> Aggregation | None:
        """Parse an ES|QL STATS clause into an Aggregation.

        Handles:
        - STATS count = COUNT(*) BY field1, field2
        - STATS COUNT(*) BY field1
        - STATS total = SUM(field) BY field1

        Args:
            clause: STATS clause text (without 'STATS' prefix).

        Returns:
            Aggregation or None.
        """
        clause = clause.strip()

        # Split on BY
        by_match = re.split(r'\bBY\b', clause, flags=re.IGNORECASE, maxsplit=1)
        agg_part = by_match[0].strip()
        group_part = by_match[1].strip() if len(by_match) > 1 else ""

        # Parse aggregation function: alias = FUNC(field) or FUNC(field)
        func_match = re.match(
            r'(?:\w+\s*=\s*)?(COUNT|SUM|AVG|MIN|MAX|COUNT_DISTINCT|MEDIAN|PERCENTILE)\s*\(\s*([\w.*]*)\s*\)',
            agg_part, re.IGNORECASE,
        )
        if not func_match:
            return None

        func = func_match.group(1).lower()
        agg_field = func_match.group(2) or None
        if agg_field in ("*", ""):
            agg_field = None

        # Map ES|QL function names
        func_map = {"count_distinct": "dc", "median": "avg", "percentile": "avg"}
        func = func_map.get(func, func)

        # Parse group by fields
        group_by: list[str] = []
        if group_part:
            group_by = [f.strip() for f in group_part.split(",") if f.strip()]

        return Aggregation(function=func, field=agg_field, group_by=group_by)

    # ── EVAL Field Extraction ────────────────────────────────────────────

    def _extract_eval_fields(self, clause: str) -> set[str]:
        """Extract field references from an EVAL expression.

        Args:
            clause: EVAL clause text.

        Returns:
            Set of field names.
        """
        fields: set[str] = set()
        for match in re.finditer(r'\b([\w][\w.]*)\b', clause):
            name = match.group(1)
            if name.upper() not in (
                "TRUE", "FALSE", "NULL", "AND", "OR", "NOT",
                "CASE", "LENGTH", "TRIM", "CONCAT", "SUBSTRING",
                "TO_STRING", "TO_INTEGER", "TO_DOUBLE", "TO_DATETIME",
                "DATE_EXTRACT", "DATE_FORMAT", "NOW", "ABS", "CEIL",
                "FLOOR", "ROUND", "MV_COUNT", "MV_FIRST", "MV_LAST",
                "COALESCE", "GREATEST", "LEAST", "IS", "AS",
            ):
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
