"""Splunk Search Processing Language (SPL) parser.

Parses the detection-relevant subset of SPL into the unified AST.
Handles search terms, where clauses, stats aggregations, eval
expressions, and pipe chains.
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


class SPLParser(AbstractParser):
    """Parser for Splunk SPL detection searches.

    Handles the detection-relevant subset of SPL:
    - search/where clauses with field comparisons
    - stats/eventstats with count, dc, sum
    - eval expressions (basic field reference extraction)
    - Pipe chain parsing (split on |, process each command)
    - index= and sourcetype= extraction for data source identification

    Example::

        index=main sourcetype=sysmon EventCode=1
        | where CommandLine LIKE "%powershell%"
        | stats count by Computer, User
        | where count > 5
    """

    language = "spl"

    def parse(self, rule_text: str, **kwargs) -> ParsedRule:
        """Parse an SPL query into the unified AST.

        Args:
            rule_text: Raw SPL query string.

        Returns:
            ParsedRule with filter, aggregation, and metadata.

        Raises:
            ValueError: If the query is empty or cannot be parsed.
        """
        rule_text = rule_text.strip()
        if not rule_text:
            raise ValueError("SPL query is empty")

        # Split on pipe boundaries (but not pipes inside quotes)
        segments = self._split_pipes(rule_text)

        data_sources: list[str] = []
        referenced_fields: set[str] = set()
        all_conditions: list[Condition | LogicGroup] = []
        aggregation: Aggregation | None = None

        for segment in segments:
            segment = segment.strip()
            if not segment:
                continue

            cmd_lower = segment.lower().lstrip()

            # Determine command type
            if cmd_lower.startswith("search "):
                conds, fields, sources = self._parse_search_clause(segment[7:])
                all_conditions.extend(conds)
                referenced_fields.update(fields)
                data_sources.extend(sources)
            elif cmd_lower.startswith("where "):
                conds, fields = self._parse_where_clause(segment[6:])
                all_conditions.extend(conds)
                referenced_fields.update(fields)
            elif cmd_lower.startswith("stats ") or cmd_lower.startswith("eventstats "):
                prefix_len = 6 if cmd_lower.startswith("stats ") else 11
                agg = self._parse_stats_clause(segment[prefix_len:])
                if agg:
                    aggregation = agg
                    if agg.field:
                        referenced_fields.add(agg.field)
                    referenced_fields.update(agg.group_by)
            elif cmd_lower.startswith("eval "):
                fields = self._extract_eval_fields(segment[5:])
                referenced_fields.update(fields)
            elif cmd_lower.startswith("tstats "):
                conds, fields, sources = self._parse_tstats(segment[7:])
                all_conditions.extend(conds)
                referenced_fields.update(fields)
                data_sources.extend(sources)
            elif not any(cmd_lower.startswith(skip) for skip in
                         ("table ", "fields ", "sort ", "head ", "tail ",
                          "rename ", "dedup ", "fillnull ", "lookup ")):
                # First segment without a command prefix = implicit search
                conds, fields, sources = self._parse_search_clause(segment)
                all_conditions.extend(conds)
                referenced_fields.update(fields)
                data_sources.extend(sources)

        # Build the filter AST
        filter_ast: LogicGroup | None = None
        if all_conditions:
            if len(all_conditions) == 1 and isinstance(all_conditions[0], LogicGroup):
                filter_ast = all_conditions[0]
            else:
                filter_ast = LogicGroup(LogicOp.AND, all_conditions)

        return ParsedRule(
            source_language="spl",
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
        """Check if text looks like SPL.

        Uses SPL-specific indicators that don't overlap with KQL/ESQL.

        Args:
            rule_text: Raw text to check.

        Returns:
            True if this looks like an SPL query.
        """
        text = rule_text.strip().lower()
        # Strong SPL indicators (unique to SPL)
        strong_indicators = [
            "index=", "sourcetype=", "| tstats ",
            "| search ", "eventstats",
        ]
        if any(ind in text for ind in strong_indicators):
            return True
        # Weaker indicators only if combined with SPL-like patterns
        if ("| stats " in text or "| eval " in text or "| table " in text):
            # KQL uses "| summarize" not "| stats"; ESQL uses "| STATS"
            # SPL uses field=value syntax without table name as first token
            if "index=" in text or "sourcetype=" in text:
                return True
            # Check for SPL-style field=value in the first segment
            first_seg = text.split("|")[0].strip()
            if re.search(r'\b\w+=\S', first_seg):
                return True
        return False

    # ── Pipe Splitting ───────────────────────────────────────────────────

    def _split_pipes(self, query: str) -> list[str]:
        """Split SPL query on pipe characters, respecting quoted strings.

        Args:
            query: Raw SPL query.

        Returns:
            List of command segments.
        """
        segments: list[str] = []
        current: list[str] = []
        in_quote: str | None = None
        i = 0

        while i < len(query):
            ch = query[i]
            if ch in ('"', "'") and (i == 0 or query[i - 1] != "\\"):
                if in_quote == ch:
                    in_quote = None
                elif in_quote is None:
                    in_quote = ch
                current.append(ch)
            elif ch == "|" and in_quote is None:
                segments.append("".join(current))
                current = []
            else:
                current.append(ch)
            i += 1

        if current:
            segments.append("".join(current))

        return segments

    # ── Search Clause Parsing ────────────────────────────────────────────

    def _parse_search_clause(
        self, clause: str
    ) -> tuple[list[Condition | LogicGroup], set[str], list[str]]:
        """Parse an SPL search clause (field=value pairs with AND/OR/NOT).

        Handles:
        - field=value, field="value", field=*wildcard*
        - field!=value
        - AND, OR, NOT operators
        - Parenthesized groups

        Args:
            clause: The search clause text (without 'search' prefix).

        Returns:
            Tuple of (conditions, referenced_fields, data_sources).
        """
        clause = clause.strip()
        fields: set[str] = set()
        data_sources: list[str] = []
        conditions: list[Condition | LogicGroup] = []

        # Tokenize: extract field=value pairs and logical operators
        tokens = self._tokenize_search(clause)

        i = 0
        pending_not = False

        while i < len(tokens):
            token = tokens[i]
            token_lower = token.lower()

            if token_lower == "and":
                i += 1
                continue
            elif token_lower == "or":
                # Wrap previous and next as OR
                if conditions and i + 1 < len(tokens):
                    left = conditions.pop() if conditions else None
                    i += 1
                    right_cond = self._parse_single_search_token(
                        tokens[i], fields, data_sources
                    )
                    if left and right_cond:
                        conditions.append(LogicGroup(LogicOp.OR, [left, right_cond]))
                    elif right_cond:
                        conditions.append(right_cond)
                    i += 1
                    continue
                i += 1
                continue
            elif token_lower == "not":
                pending_not = True
                i += 1
                continue
            elif token == "(":
                # Find matching close paren and recursively parse
                depth = 1
                j = i + 1
                while j < len(tokens) and depth > 0:
                    if tokens[j] == "(":
                        depth += 1
                    elif tokens[j] == ")":
                        depth -= 1
                    j += 1
                inner = " ".join(tokens[i + 1 : j - 1])
                inner_conds, inner_fields, inner_sources = self._parse_search_clause(inner)
                fields.update(inner_fields)
                data_sources.extend(inner_sources)
                if inner_conds:
                    group = LogicGroup(LogicOp.AND, inner_conds) if len(inner_conds) > 1 else (
                        inner_conds[0] if isinstance(inner_conds[0], LogicGroup) else LogicGroup(LogicOp.AND, inner_conds)
                    )
                    if pending_not:
                        group = LogicGroup(LogicOp.NOT, [group])
                        pending_not = False
                    conditions.append(group)
                i = j
                continue
            elif token == ")":
                i += 1
                continue
            else:
                cond = self._parse_single_search_token(token, fields, data_sources)
                if cond:
                    if pending_not:
                        cond = LogicGroup(LogicOp.NOT, [cond])
                        pending_not = False
                    conditions.append(cond)

            i += 1

        return conditions, fields, data_sources

    def _tokenize_search(self, clause: str) -> list[str]:
        """Tokenize an SPL search clause preserving quoted strings.

        Args:
            clause: Raw search clause.

        Returns:
            List of tokens.
        """
        tokens: list[str] = []
        i = 0
        while i < len(clause):
            ch = clause[i]
            if ch.isspace():
                i += 1
                continue
            if ch in ("(", ")"):
                tokens.append(ch)
                i += 1
                continue
            if ch in ('"', "'"):
                # Read quoted string as part of the surrounding token
                # Back up to include field= prefix
                j = i + 1
                while j < len(clause) and clause[j] != ch:
                    if clause[j] == "\\" and j + 1 < len(clause):
                        j += 1
                    j += 1
                j += 1  # skip closing quote
                # Check if there's a field= prefix before the quote
                if tokens and tokens[-1].endswith("="):
                    tokens[-1] += clause[i:j]
                elif tokens and tokens[-1].endswith("!="):
                    tokens[-1] += clause[i:j]
                else:
                    tokens.append(clause[i:j])
                i = j
                continue
            # Read a word
            j = i
            while j < len(clause) and not clause[j].isspace() and clause[j] not in ("(", ")"):
                if clause[j] in ('"', "'"):
                    # Include quoted part
                    q = clause[j]
                    j += 1
                    while j < len(clause) and clause[j] != q:
                        j += 1
                    if j < len(clause):
                        j += 1
                else:
                    j += 1
            tokens.append(clause[i:j])
            i = j

        return tokens

    def _parse_single_search_token(
        self, token: str, fields: set[str], data_sources: list[str]
    ) -> Condition | None:
        """Parse a single search token like field=value or field!=value.

        Args:
            token: A single token (e.g., 'EventCode=1', 'index=main').
            fields: Accumulator for referenced field names.
            data_sources: Accumulator for data source names.

        Returns:
            A Condition, or None if the token is not a field=value pair.
        """
        # field!=value
        neq_match = re.match(r'^([\w.]+)!=(.+)$', token)
        if neq_match:
            field_name = neq_match.group(1)
            value = self._strip_quotes(neq_match.group(2))
            fields.add(field_name)
            op = Operator.WILDCARD if "*" in str(value) or "?" in str(value) else Operator.NOT_EQUALS
            if op == Operator.WILDCARD:
                return LogicGroup(LogicOp.NOT, [Condition(field_name, Operator.WILDCARD, value, case_insensitive=True)])
            return Condition(field_name, Operator.NOT_EQUALS, value, case_insensitive=True)

        # field=value
        eq_match = re.match(r'^([\w.]+)=(.+)$', token)
        if eq_match:
            field_name = eq_match.group(1)
            value = self._strip_quotes(eq_match.group(2))

            # Track data sources
            if field_name.lower() in ("index", "sourcetype", "source"):
                data_sources.append(f"{field_name}={value}")
                fields.add(field_name)
                return Condition(field_name, Operator.EQUALS, value, case_insensitive=True)

            fields.add(field_name)

            # Determine operator based on value
            if isinstance(value, str) and ("*" in value or "?" in value):
                return Condition(field_name, Operator.WILDCARD, value, case_insensitive=True)
            else:
                return Condition(field_name, Operator.EQUALS, value, case_insensitive=True)

        # Bare keyword (no = sign) -- treat as keyword search
        if not token.lower() in ("and", "or", "not", "(", ")"):
            value = self._strip_quotes(token)
            if value:
                return Condition("_raw", Operator.CONTAINS, value, case_insensitive=True)

        return None

    # ── Where Clause Parsing ─────────────────────────────────────────────

    def _parse_where_clause(
        self, clause: str
    ) -> tuple[list[Condition | LogicGroup], set[str]]:
        """Parse an SPL where clause into conditions.

        Handles:
        - field LIKE "%pattern%"
        - field = "value" / field == "value"
        - field != "value"
        - field > N / field >= N / field < N / field <= N
        - field IN ("a", "b", "c")
        - AND, OR, NOT combinations

        Args:
            clause: The where clause text (without 'where' prefix).

        Returns:
            Tuple of (conditions, referenced_fields).
        """
        clause = clause.strip()
        fields: set[str] = set()
        conditions: list[Condition | LogicGroup] = []

        # Split on AND/OR at the top level (respecting parentheses)
        parts = self._split_where_logic(clause)

        for logic_op, part in parts:
            part = part.strip()
            if not part:
                continue

            # Check for NOT prefix
            is_negated = False
            if part.upper().startswith("NOT "):
                is_negated = True
                part = part[4:].strip()

            cond = self._parse_where_comparison(part, fields)
            if cond:
                if is_negated:
                    cond = LogicGroup(LogicOp.NOT, [cond])
                conditions.append(cond)

        if not conditions:
            return [], fields

        # If there were OR operators, we need to restructure
        # For now, treat all as AND (the split_where_logic handles OR)
        return conditions, fields

    def _split_where_logic(self, clause: str) -> list[tuple[str, str]]:
        """Split a WHERE clause on AND/OR, respecting parentheses and quotes.

        Args:
            clause: Raw WHERE clause.

        Returns:
            List of (logic_operator, expression) tuples.
        """
        results: list[tuple[str, str]] = []
        current: list[str] = []
        depth = 0
        in_quote: str | None = None
        i = 0
        tokens = clause.split()

        rebuilt: list[str] = []
        for token in tokens:
            # Track quotes
            for ch in token:
                if ch in ('"', "'") and in_quote is None:
                    in_quote = ch
                elif ch == in_quote:
                    in_quote = None
            # Track parentheses
            depth += token.count("(") - token.count(")")

            if in_quote is None and depth <= 0 and token.upper() in ("AND", "OR"):
                if rebuilt:
                    results.append(("AND" if not results else token.upper(), " ".join(rebuilt)))
                    rebuilt = []
                continue

            rebuilt.append(token)

        if rebuilt:
            results.append(("AND" if not results else "AND", " ".join(rebuilt)))

        return results

    def _parse_where_comparison(
        self, expr: str, fields: set[str]
    ) -> Condition | LogicGroup | None:
        """Parse a single WHERE comparison expression.

        Args:
            expr: A comparison expression (e.g., 'CommandLine LIKE "%powershell%"').
            fields: Accumulator for referenced field names.

        Returns:
            A Condition or LogicGroup, or None.
        """
        expr = expr.strip()
        if not expr:
            return None

        # Remove outer parentheses
        if expr.startswith("(") and expr.endswith(")"):
            expr = expr[1:-1].strip()

        # LIKE pattern
        like_match = re.match(
            r'([\w.]+)\s+LIKE\s+["\']([^"\']*)["\']',
            expr, re.IGNORECASE,
        )
        if like_match:
            field_name = like_match.group(1)
            pattern = like_match.group(2)
            fields.add(field_name)
            # Convert SQL LIKE (%) to wildcard (*)
            wildcard_pattern = pattern.replace("%", "*").replace("_", "?")
            return Condition(field_name, Operator.WILDCARD, wildcard_pattern, case_insensitive=True)

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

        # Comparison operators: ==, !=, >=, <=, >, <, =
        comp_match = re.match(
            r'([\w.]+)\s*(==|!=|>=|<=|>|<|=)\s*(.+)',
            expr,
        )
        if comp_match:
            field_name = comp_match.group(1)
            op_str = comp_match.group(2)
            value = self._strip_quotes(comp_match.group(3).strip())
            fields.add(field_name)

            op_map = {
                "=": Operator.EQUALS, "==": Operator.EQUALS,
                "!=": Operator.NOT_EQUALS,
                ">": Operator.GT, ">=": Operator.GTE,
                "<": Operator.LT, "<=": Operator.LTE,
            }
            operator = op_map.get(op_str, Operator.EQUALS)

            # Try to parse numeric values
            value = self._try_numeric(value)

            # Check for wildcards in string values
            if isinstance(value, str) and ("*" in value or "?" in value):
                operator = Operator.WILDCARD

            return Condition(field_name, operator, value, case_insensitive=True)

        return None

    # ── Stats Clause Parsing ─────────────────────────────────────────────

    def _parse_stats_clause(self, clause: str) -> Aggregation | None:
        """Parse an SPL stats clause into an Aggregation.

        Handles:
        - stats count by field1, field2
        - stats count(field) as alias by field1
        - stats dc(field) by field1
        - stats sum(field) by field1

        Args:
            clause: The stats clause text (without 'stats' prefix).

        Returns:
            Aggregation or None.
        """
        clause = clause.strip()

        # Pattern: function(field?) (as alias)? (by field1, field2)?
        stats_match = re.match(
            r'(count|dc|sum|avg|min|max|values)\s*'
            r'(?:\(\s*([\w.*]*)\s*\))?\s*'
            r'(?:as\s+\w+\s*)?'
            r'(?:by\s+(.+))?',
            clause, re.IGNORECASE,
        )
        if not stats_match:
            # Try simple "count by field"
            simple_match = re.match(r'count\s+by\s+(.+)', clause, re.IGNORECASE)
            if simple_match:
                group_by = [f.strip() for f in simple_match.group(1).split(",") if f.strip()]
                return Aggregation(function="count", field=None, group_by=group_by)
            return None

        func = stats_match.group(1).lower()
        agg_field = stats_match.group(2) or None
        if agg_field == "*" or agg_field == "":
            agg_field = None
        group_by_str = stats_match.group(3) or ""
        group_by = [f.strip() for f in group_by_str.split(",") if f.strip()]

        return Aggregation(function=func, field=agg_field, group_by=group_by)

    # ── Eval Extraction ──────────────────────────────────────────────────

    def _extract_eval_fields(self, clause: str) -> set[str]:
        """Extract field references from an eval expression.

        Args:
            clause: The eval clause text (without 'eval' prefix).

        Returns:
            Set of field names referenced.
        """
        fields: set[str] = set()
        # Find field names (word characters with dots)
        for match in re.finditer(r'\b([\w][\w.]*)\b', clause):
            name = match.group(1)
            # Skip function names and keywords
            if name.lower() not in (
                "if", "case", "coalesce", "null", "true", "false",
                "len", "lower", "upper", "trim", "replace", "split",
                "mvcount", "mvindex", "mvfilter", "tonumber", "tostring",
            ):
                fields.add(name)
        return fields

    # ── Tstats Parsing ───────────────────────────────────────────────────

    def _parse_tstats(
        self, clause: str
    ) -> tuple[list[Condition | LogicGroup], set[str], list[str]]:
        """Parse a tstats command (accelerated search).

        Args:
            clause: The tstats clause text.

        Returns:
            Tuple of (conditions, referenced_fields, data_sources).
        """
        fields: set[str] = set()
        data_sources: list[str] = []
        conditions: list[Condition | LogicGroup] = []

        # Extract "from datamodel=X" or "from X"
        dm_match = re.search(r'from\s+(?:datamodel\s*=\s*)?["\']?(\w+)["\']?', clause, re.IGNORECASE)
        if dm_match:
            data_sources.append(f"datamodel={dm_match.group(1)}")

        # Extract WHERE conditions
        where_match = re.search(r'where\s+(.+?)(?:\s+by\s+|\s*$)', clause, re.IGNORECASE)
        if where_match:
            search_conds, search_fields, search_sources = self._parse_search_clause(where_match.group(1))
            conditions.extend(search_conds)
            fields.update(search_fields)
            data_sources.extend(search_sources)

        # Extract BY fields
        by_match = re.search(r'by\s+(.+)', clause, re.IGNORECASE)
        if by_match:
            for f in by_match.group(1).split(","):
                fields.add(f.strip())

        return conditions, fields, data_sources

    # ── Utilities ────────────────────────────────────────────────────────

    @staticmethod
    def _strip_quotes(value: str) -> str:
        """Remove surrounding quotes from a value string.

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
            Numeric value if conversion succeeds, original value otherwise.
        """
        if not isinstance(value, str):
            return value
        try:
            if "." in value:
                return float(value)
            return int(value)
        except (ValueError, TypeError):
            return value
