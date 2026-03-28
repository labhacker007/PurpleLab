"""Sigma rule parser -- generic YAML-based detection format.

Parses Sigma YAML rules into the unified AST. Handles:
- Selection blocks with field modifiers (|contains, |endswith, etc.)
- Condition expressions (selection and not filter, 1 of selection*, all of them)
- Logsource mapping for data source identification
- Tag extraction for MITRE technique mapping
- Value lists (OR by default, AND with |all modifier)
"""
from __future__ import annotations

import base64
import logging
import re
from typing import Any

import yaml

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

# Map Sigma field modifiers to AST operators
_MODIFIER_MAP: dict[str, Operator] = {
    "contains": Operator.CONTAINS,
    "startswith": Operator.STARTS_WITH,
    "endswith": Operator.ENDS_WITH,
    "re": Operator.REGEX,
}

_SEVERITY_MAP: dict[str, str] = {
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


class SigmaParser(AbstractParser):
    """Parser for Sigma detection rules.

    Converts Sigma YAML into the unified ParsedRule AST. Sigma is the
    universal detection format, so this is the most important parser.

    Example Sigma rule::

        title: Suspicious PowerShell Execution
        status: test
        description: Detects suspicious PowerShell commands
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                CommandLine|contains:
                    - 'powershell'
                    - 'cmd.exe'
                ParentImage|endswith: '\\\\explorer.exe'
            filter:
                User: 'SYSTEM'
            condition: selection and not filter
        level: high
        tags:
            - attack.execution
            - attack.t1059.001
    """

    language = "sigma"

    def parse(self, rule_text: str, **kwargs) -> ParsedRule:
        """Parse a Sigma YAML rule into the unified AST.

        Args:
            rule_text: Raw Sigma YAML string.

        Returns:
            ParsedRule with filter and metadata extracted from the Sigma rule.

        Raises:
            ValueError: If the YAML is invalid or missing required sections.
        """
        try:
            data = yaml.safe_load(rule_text)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid Sigma YAML: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError("Sigma rule must be a YAML mapping")

        detection = data.get("detection")
        if not detection or not isinstance(detection, dict):
            raise ValueError("Sigma rule must contain a 'detection' section")

        condition_expr = detection.get("condition", "")
        if not condition_expr:
            raise ValueError("Sigma detection must contain a 'condition' field")

        # Build named detection blocks (everything in detection except 'condition' and 'timeframe')
        named_blocks: dict[str, LogicGroup] = {}
        referenced_fields: set[str] = set()

        for block_name, block_def in detection.items():
            if block_name in ("condition", "timeframe"):
                continue
            group, fields = self._parse_selection_block(block_def)
            named_blocks[block_name] = group
            referenced_fields.update(fields)

        # Parse the condition expression into a logic tree referencing named blocks
        filter_ast = self._parse_condition_expression(condition_expr, named_blocks)

        # Parse aggregation from condition (e.g., "selection | count(field) by src > 5")
        aggregation = self._parse_aggregation_condition(condition_expr, named_blocks)

        # Extract MITRE techniques from tags
        mitre_techniques: list[str] = []
        tags_list: list[str] = []
        for tag in data.get("tags", []):
            tag_str = str(tag).lower()
            tags_list.append(tag_str)
            # Extract technique IDs like attack.t1059.001
            tech_match = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)", tag_str)
            if tech_match:
                mitre_techniques.append(tech_match.group(1).upper())

        # Build data sources from logsource
        data_sources: list[str] = []
        logsource = data.get("logsource", {})
        if isinstance(logsource, dict):
            for key in ("category", "product", "service"):
                val = logsource.get(key)
                if val:
                    data_sources.append(f"{key}:{val}")

        severity_raw = str(data.get("level", "medium")).lower()
        severity = _SEVERITY_MAP.get(severity_raw, severity_raw)

        return ParsedRule(
            source_language="sigma",
            raw_text=rule_text,
            name=data.get("title", ""),
            description=data.get("description", ""),
            severity=severity,
            mitre_techniques=mitre_techniques,
            filter=filter_ast,
            aggregation=aggregation,
            referenced_fields=referenced_fields,
            data_sources=data_sources,
            tags=tags_list,
        )

    def supports(self, rule_text: str) -> bool:
        """Check if text looks like a Sigma rule (YAML with detection section).

        Args:
            rule_text: Raw text to check.

        Returns:
            True if this looks like Sigma YAML.
        """
        text = rule_text.strip()
        # Quick heuristic: YAML with detection: and title: or logsource:
        if not (text.startswith("title:") or text.startswith("---") or "detection:" in text):
            return False
        try:
            data = yaml.safe_load(text)
            return isinstance(data, dict) and "detection" in data
        except Exception:
            return False

    # ── Selection Block Parsing ──────────────────────────────────────────

    def _parse_selection_block(
        self, block_def: Any
    ) -> tuple[LogicGroup, set[str]]:
        """Parse a Sigma selection/filter block into a LogicGroup.

        A selection block is a dict of field conditions that are ANDed together.
        It can also be a list of dicts (ORed together).

        Args:
            block_def: The selection block definition from the YAML.

        Returns:
            Tuple of (LogicGroup, set of referenced field names).
        """
        fields: set[str] = set()

        if isinstance(block_def, dict):
            return self._parse_selection_dict(block_def, fields)
        elif isinstance(block_def, list):
            # List of dicts = OR
            children: list[LogicGroup | Condition] = []
            for item in block_def:
                if isinstance(item, dict):
                    group, item_fields = self._parse_selection_dict(item, fields)
                    children.append(group)
                    fields.update(item_fields)
                else:
                    # Single value -- treat as a keyword search
                    children.append(
                        Condition("_raw", Operator.CONTAINS, str(item), case_insensitive=True)
                    )
            if len(children) == 1:
                return children[0] if isinstance(children[0], LogicGroup) else LogicGroup(LogicOp.AND, children), fields
            return LogicGroup(LogicOp.OR, children), fields
        elif isinstance(block_def, str):
            # Plain string = keyword search
            return LogicGroup(LogicOp.AND, [
                Condition("_raw", Operator.CONTAINS, block_def, case_insensitive=True)
            ]), {"_raw"}
        else:
            return LogicGroup(LogicOp.AND, []), fields

    def _parse_selection_dict(
        self, block: dict, fields: set[str]
    ) -> tuple[LogicGroup, set[str]]:
        """Parse a single selection dict (field conditions ANDed together).

        Handles field modifiers like |contains, |endswith, |startswith,
        |re, |all, |base64, |base64offset.

        Args:
            block: Dict of field_name|modifier: value(s).
            fields: Accumulator for referenced field names.

        Returns:
            Tuple of (LogicGroup with AND operator, updated fields set).
        """
        conditions: list[Condition | LogicGroup] = []

        for key, value in block.items():
            # Parse field name and modifiers
            parts = key.split("|")
            field_name = parts[0]
            modifiers = [m.lower() for m in parts[1:]] if len(parts) > 1 else []

            fields.add(field_name)

            # Determine the operator from modifiers
            use_all = "all" in modifiers
            use_base64 = "base64" in modifiers or "base64offset" in modifiers

            operator = Operator.EQUALS
            for mod in modifiers:
                if mod in _MODIFIER_MAP:
                    operator = _MODIFIER_MAP[mod]
                    break

            # Normalize value to a list
            values = self._normalize_values(value, use_base64)

            if not values:
                continue

            # Build conditions from values
            if len(values) == 1:
                cond = Condition(field_name, operator, values[0], case_insensitive=True)
                conditions.append(cond)
            else:
                # Multiple values: OR by default, AND if |all modifier
                logic_op = LogicOp.AND if use_all else LogicOp.OR
                value_conditions = [
                    Condition(field_name, operator, v, case_insensitive=True)
                    for v in values
                ]
                conditions.append(LogicGroup(logic_op, value_conditions))

        if len(conditions) == 0:
            return LogicGroup(LogicOp.AND, []), fields
        if len(conditions) == 1 and isinstance(conditions[0], LogicGroup):
            return conditions[0], fields
        return LogicGroup(LogicOp.AND, conditions), fields

    def _normalize_values(self, value: Any, use_base64: bool = False) -> list[Any]:
        """Normalize a Sigma value into a flat list.

        Handles strings, integers, lists, and None values.
        Optionally adds base64-encoded variants.

        Args:
            value: The raw value from the YAML.
            use_base64: If True, add base64-encoded variants.

        Returns:
            List of normalized values.
        """
        if value is None:
            return [None]

        if isinstance(value, list):
            raw_values = value
        else:
            raw_values = [value]

        results: list[Any] = []
        for v in raw_values:
            if v is None:
                results.append(None)
                continue
            results.append(v)
            if use_base64 and isinstance(v, str):
                try:
                    encoded = base64.b64encode(v.encode("utf-8")).decode("ascii")
                    results.append(encoded)
                except Exception:
                    pass

        return results

    # ── Condition Expression Parsing ─────────────────────────────────────

    def _parse_condition_expression(
        self, expr: str, named_blocks: dict[str, LogicGroup]
    ) -> LogicGroup:
        """Parse a Sigma condition expression into a logic tree.

        Handles expressions like:
        - "selection"
        - "selection and not filter"
        - "selection1 or selection2"
        - "(selection1 and selection2) or selection3"
        - "1 of selection*"
        - "all of them"
        - "all of selection*"

        Args:
            expr: The condition expression string.
            named_blocks: Dict of named selection/filter blocks.

        Returns:
            LogicGroup representing the full condition logic.
        """
        expr = expr.strip()

        # Check for aggregation suffix (e.g., "selection | count(field) by src > 5")
        # Strip it for filter parsing; aggregation is handled separately
        if "|" in expr:
            expr = expr.split("|")[0].strip()

        # Handle "1 of selection*", "all of them", "all of selection*"
        of_match = re.match(
            r"(all|\d+)\s+of\s+(them|[\w]+\*?)", expr, re.IGNORECASE
        )
        if of_match:
            return self._parse_of_expression(of_match, named_blocks)

        # Tokenize and build expression tree
        return self._parse_bool_expression(expr, named_blocks)

    def _parse_of_expression(
        self, match: re.Match, named_blocks: dict[str, LogicGroup]
    ) -> LogicGroup:
        """Parse '1 of selection*' / 'all of them' expressions.

        Args:
            match: Regex match with groups (quantifier, target).
            named_blocks: Dict of named selection/filter blocks.

        Returns:
            LogicGroup (OR for '1 of', AND for 'all of').
        """
        quantifier = match.group(1).lower()
        target = match.group(2).lower()

        # Determine which blocks to include
        if target == "them":
            blocks = list(named_blocks.values())
        elif target.endswith("*"):
            prefix = target[:-1]
            blocks = [
                v for k, v in named_blocks.items()
                if k.lower().startswith(prefix)
            ]
        else:
            block = named_blocks.get(target)
            blocks = [block] if block else []

        if not blocks:
            return LogicGroup(LogicOp.AND, [])

        if quantifier == "all":
            return LogicGroup(LogicOp.AND, blocks)
        else:
            # "1 of" = OR
            return LogicGroup(LogicOp.OR, blocks)

    def _parse_bool_expression(
        self, expr: str, named_blocks: dict[str, LogicGroup]
    ) -> LogicGroup:
        """Parse a boolean expression with AND, OR, NOT, and parentheses.

        Uses a simple recursive descent approach.

        Args:
            expr: The boolean expression string (e.g., "selection and not filter").
            named_blocks: Dict of named detection blocks.

        Returns:
            LogicGroup representing the parsed expression.
        """
        tokens = self._tokenize_condition(expr)
        result, _ = self._parse_or_expr(tokens, 0, named_blocks)
        return result

    def _tokenize_condition(self, expr: str) -> list[str]:
        """Tokenize a Sigma condition expression.

        Args:
            expr: Raw condition string.

        Returns:
            List of tokens (identifiers, operators, parens).
        """
        tokens: list[str] = []
        i = 0
        while i < len(expr):
            ch = expr[i]
            if ch.isspace():
                i += 1
                continue
            if ch in ("(", ")"):
                tokens.append(ch)
                i += 1
                continue
            # Read a word
            j = i
            while j < len(expr) and not expr[j].isspace() and expr[j] not in ("(", ")"):
                j += 1
            tokens.append(expr[i:j])
            i = j
        return tokens

    def _parse_or_expr(
        self, tokens: list[str], pos: int, blocks: dict[str, LogicGroup]
    ) -> tuple[LogicGroup, int]:
        """Parse OR-level expressions (lowest precedence).

        Args:
            tokens: Token list.
            pos: Current position.
            blocks: Named detection blocks.

        Returns:
            Tuple of (LogicGroup, new position).
        """
        left, pos = self._parse_and_expr(tokens, pos, blocks)
        children = [left]

        while pos < len(tokens) and tokens[pos].lower() == "or":
            pos += 1  # skip 'or'
            right, pos = self._parse_and_expr(tokens, pos, blocks)
            children.append(right)

        if len(children) == 1:
            return children[0], pos
        return LogicGroup(LogicOp.OR, children), pos

    def _parse_and_expr(
        self, tokens: list[str], pos: int, blocks: dict[str, LogicGroup]
    ) -> tuple[LogicGroup, int]:
        """Parse AND-level expressions.

        Args:
            tokens: Token list.
            pos: Current position.
            blocks: Named detection blocks.

        Returns:
            Tuple of (LogicGroup, new position).
        """
        left, pos = self._parse_not_expr(tokens, pos, blocks)
        children = [left]

        while pos < len(tokens) and tokens[pos].lower() == "and":
            pos += 1  # skip 'and'
            right, pos = self._parse_not_expr(tokens, pos, blocks)
            children.append(right)

        if len(children) == 1:
            return children[0], pos
        return LogicGroup(LogicOp.AND, children), pos

    def _parse_not_expr(
        self, tokens: list[str], pos: int, blocks: dict[str, LogicGroup]
    ) -> tuple[LogicGroup, int]:
        """Parse NOT prefix expressions.

        Args:
            tokens: Token list.
            pos: Current position.
            blocks: Named detection blocks.

        Returns:
            Tuple of (LogicGroup, new position).
        """
        if pos < len(tokens) and tokens[pos].lower() == "not":
            pos += 1  # skip 'not'
            child, pos = self._parse_atom(tokens, pos, blocks)
            return LogicGroup(LogicOp.NOT, [child]), pos
        return self._parse_atom(tokens, pos, blocks)

    def _parse_atom(
        self, tokens: list[str], pos: int, blocks: dict[str, LogicGroup]
    ) -> tuple[LogicGroup, int]:
        """Parse an atomic expression: block name or parenthesized sub-expression.

        Also handles inline 'N of pattern' expressions.

        Args:
            tokens: Token list.
            pos: Current position.
            blocks: Named detection blocks.

        Returns:
            Tuple of (LogicGroup, new position).
        """
        if pos >= len(tokens):
            return LogicGroup(LogicOp.AND, []), pos

        token = tokens[pos]

        # Parenthesized expression
        if token == "(":
            pos += 1  # skip '('
            result, pos = self._parse_or_expr(tokens, pos, blocks)
            if pos < len(tokens) and tokens[pos] == ")":
                pos += 1  # skip ')'
            return result, pos

        # "N of pattern" or "all of pattern"
        if token.lower() in ("all",) or token.isdigit():
            if pos + 2 < len(tokens) and tokens[pos + 1].lower() == "of":
                quantifier = token.lower()
                target = tokens[pos + 2].lower()
                pos += 3

                if target == "them":
                    matched = list(blocks.values())
                elif target.endswith("*"):
                    prefix = target[:-1]
                    matched = [v for k, v in blocks.items() if k.lower().startswith(prefix)]
                else:
                    b = blocks.get(target)
                    matched = [b] if b else []

                if not matched:
                    return LogicGroup(LogicOp.AND, []), pos
                op = LogicOp.AND if quantifier == "all" else LogicOp.OR
                return LogicGroup(op, matched), pos

        # Named block reference
        block = blocks.get(token)
        if block is not None:
            return block, pos + 1

        # Unknown token -- return empty group
        log.warning("Unknown Sigma condition token: %s", token)
        return LogicGroup(LogicOp.AND, []), pos + 1

    # ── Aggregation Parsing ──────────────────────────────────────────────

    def _parse_aggregation_condition(
        self, expr: str, named_blocks: dict[str, LogicGroup]
    ) -> Aggregation | None:
        """Parse aggregation from Sigma condition (pipe syntax).

        Handles expressions like:
        - "selection | count(field) by src_ip > 5"
        - "selection | count() > 10"

        Args:
            expr: The full condition expression.
            named_blocks: Named detection blocks.

        Returns:
            Aggregation if found, None otherwise.
        """
        if "|" not in expr:
            return None

        agg_part = expr.split("|", 1)[1].strip()
        if not agg_part:
            return None

        # Pattern: count(field?) (by field1, field2)? (> N)?
        agg_match = re.match(
            r"(count|sum|avg|min|max|dc)\s*\(\s*(\w*)\s*\)"
            r"(?:\s+by\s+([\w,\s]+))?"
            r"(?:\s*(>|>=|<|<=|==|!=)\s*(\d+(?:\.\d+)?))?",
            agg_part,
            re.IGNORECASE,
        )
        if not agg_match:
            return None

        func = agg_match.group(1).lower()
        agg_field = agg_match.group(2) or None
        group_by_str = agg_match.group(3) or ""
        comp_op = agg_match.group(4)
        threshold = agg_match.group(5)

        group_by = [f.strip() for f in group_by_str.split(",") if f.strip()] if group_by_str else []

        threshold_cond = None
        if comp_op and threshold:
            op_map = {">": Operator.GT, ">=": Operator.GTE, "<": Operator.LT,
                      "<=": Operator.LTE, "==": Operator.EQUALS, "!=": Operator.NOT_EQUALS}
            threshold_cond = Condition(
                func, op_map.get(comp_op, Operator.GT), float(threshold)
            )

        return Aggregation(
            function=func,
            field=agg_field,
            group_by=group_by,
            condition=threshold_cond,
        )
