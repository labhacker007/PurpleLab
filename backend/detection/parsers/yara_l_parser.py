"""YARA-L 2.0 parser for Google Chronicle/SecOps rules.

Parses YARA-L 2.0 syntax into the unified ParsedRule AST. Handles:
- Rule name extraction from the header
- meta: section (author, description, severity, tags)
- events: section (field conditions parsed into Condition objects)
- condition: section (stored as raw string)
- Rule evaluation against flat event dicts
"""
from __future__ import annotations

import logging
import re
from typing import Any

from backend.detection.parsers.base_parser import (
    AbstractParser,
    Condition,
    LogicGroup,
    LogicOp,
    Operator,
    ParsedRule,
)

log = logging.getLogger(__name__)

# Map YARA-L severity strings to canonical severities
_SEVERITY_MAP: dict[str, str] = {
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "info": "info",
    "INFORMATIONAL": "info",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}


def _strip_block(text: str, keyword: str) -> str | None:
    """Extract the content between `keyword:` and the next top-level keyword or end.

    Finds the first occurrence of `keyword:` (at the start of a line or after
    whitespace) inside a YARA-L rule body and returns everything until the
    next section keyword (`meta:`, `events:`, `match:`, `condition:`,
    `outcome:`) or the closing `}`.

    Returns None if the keyword is not present.
    """
    # Find the section header: optional whitespace + keyword + colon
    pattern = re.compile(
        r"(?:^|\n)\s*" + re.escape(keyword) + r"\s*:\s*\n(.*?)(?=\n\s*(?:meta|events|match|condition|outcome)\s*:|(?=\s*\}))",
        re.DOTALL | re.IGNORECASE,
    )
    m = pattern.search(text)
    if m:
        return m.group(1)
    return None


def _parse_meta_block(block: str) -> dict[str, str]:
    """Parse a YARA-L meta: block into a dict of key=value pairs.

    Handles quoted string values and unquoted bare values.
    """
    meta: dict[str, str] = {}
    for line in block.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        # key = "value" or key = value
        m = re.match(r'(\w+)\s*=\s*"([^"]*)"', line)
        if m:
            meta[m.group(1)] = m.group(2)
            continue
        m = re.match(r"(\w+)\s*=\s*(.+)", line)
        if m:
            meta[m.group(1)] = m.group(2).strip()
    return meta


# Regex patterns for events: condition lines
# Matches patterns like:
#   $e.metadata.event_type = "PROCESS_LAUNCH"
#   $e.principal.process.command_line = /powershell.*-enc/
#   $e.principal.hostname != "WORKSTATION"
#   $e.target.process.pid > 0
#   $e.principal.user.userid notnull

_CONDITION_RE = re.compile(
    r"""
    (\$\w+\.\S+?)          # field path: $e.some.dotted.path
    \s*
    (=~|!=|>=|<=|>|<|=)   # operator
    \s*
    (/[^/]+/[imsx]*         # regex literal /pattern/flags
    |"[^"]*"                # quoted string
    |\d+(?:\.\d+)?          # numeric literal
    |\w+                    # bare word
    )
    """,
    re.VERBOSE,
)

_NOTNULL_RE = re.compile(r"(\$\w+\.\S+?)\s+notnull", re.IGNORECASE)


def _parse_events_block(block: str) -> list[dict[str, Any]]:
    """Parse the events: block into a list of condition dicts.

    Each condition dict has keys:
        field      - the full YARA-L field path (e.g. "$e.principal.process.command_line")
        operator   - one of "=", "!=", "=~", ">", ">=", "<", "<=", "notnull"
        value      - the comparison value (string, int, float, or regex pattern str)

    Lines beginning with // are treated as comments.
    """
    conditions: list[dict[str, Any]] = []

    for line in block.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue

        # notnull check first
        m = _NOTNULL_RE.match(line)
        if m:
            conditions.append({
                "field": m.group(1),
                "operator": "notnull",
                "value": None,
            })
            continue

        # regex-style operator =~ (used inline)
        # e.g. $e.principal.process.command_line =~ /foo.*/
        m = re.match(
            r"(\$\w+\.\S+?)\s*(=~)\s*(/[^/]+/[imsx]*)", line
        )
        if m:
            conditions.append({
                "field": m.group(1),
                "operator": "=~",
                "value": m.group(3),
            })
            continue

        # Standard operator line
        m = _CONDITION_RE.match(line)
        if m:
            field = m.group(1)
            op = m.group(2)
            raw_val: str = m.group(3)

            # Parse value: strip surrounding quotes for strings
            value: Any
            if raw_val.startswith('"') and raw_val.endswith('"'):
                value = raw_val[1:-1]
            elif re.match(r"^\d+$", raw_val):
                value = int(raw_val)
            elif re.match(r"^\d+\.\d+$", raw_val):
                value = float(raw_val)
            elif raw_val.startswith("/"):
                # Regex literal — store as string, operator becomes =~
                op = "=~"
                value = raw_val
            else:
                value = raw_val

            conditions.append({"field": field, "operator": op, "value": value})

    return conditions


def _conditions_to_ast(
    conditions: list[dict[str, Any]]
) -> LogicGroup:
    """Convert a flat list of condition dicts into a LogicGroup (AND of all).

    Args:
        conditions: List of dicts from _parse_events_block.

    Returns:
        LogicGroup(AND, [...Condition...])
    """
    ast_conds: list[Condition] = []
    op_map: dict[str, Operator] = {
        "=": Operator.EQUALS,
        "!=": Operator.NOT_EQUALS,
        "=~": Operator.REGEX,
        ">": Operator.GT,
        ">=": Operator.GTE,
        "<": Operator.LT,
        "<=": Operator.LTE,
        "notnull": Operator.EXISTS,
    }
    for cond in conditions:
        op = op_map.get(cond["operator"], Operator.EQUALS)
        ast_conds.append(
            Condition(field=cond["field"], operator=op, value=cond["value"])
        )
    return LogicGroup(LogicOp.AND, ast_conds)


def _resolve_field(field_path: str, event: dict[str, Any]) -> Any:
    """Resolve a YARA-L field path against a flat event dict.

    Tries three lookup strategies in order:
    1. Exact match on the full path (e.g. "$e.principal.process.command_line")
    2. Dot-separated traversal from the second segment onward
       (strips the "$e." variable prefix), descending into nested dicts
    3. Last path segment as a flat key

    Args:
        field_path: YARA-L field path like "$e.principal.process.command_line".
        event: Flat or nested dict representing a single event.

    Returns:
        Field value or a sentinel ``_MISSING`` if not found.
    """
    _MISSING = object()

    # Strategy 1: exact match
    if field_path in event:
        return event[field_path]

    # Strip leading "$varname." prefix
    # e.g. "$e.principal.process.command_line" -> ["principal", "process", "command_line"]
    parts = field_path.lstrip("$").split(".")
    if len(parts) > 1:
        parts = parts[1:]  # drop the variable name segment

    # Strategy 2: nested dict traversal
    node: Any = event
    for part in parts:
        if isinstance(node, dict):
            node = node.get(part, _MISSING)
            if node is _MISSING:
                break
        else:
            node = _MISSING
            break
    if node is not _MISSING:
        return node

    # Strategy 3: last segment as flat key
    flat_key = parts[-1] if parts else field_path
    return event.get(flat_key, _MISSING)


def _evaluate_condition(cond: dict[str, Any], event: dict[str, Any]) -> bool:
    """Evaluate a single condition dict against an event dict.

    Args:
        cond: Condition dict with keys field, operator, value.
        event: The event to test.

    Returns:
        True if the condition matches.
    """
    _MISSING = object.__new__(object)

    field_val = _resolve_field(cond["field"], event)
    op = cond["operator"]

    # notnull — field must exist and not be None
    if op == "notnull":
        return field_val is not None and not (
            isinstance(field_val, type(_MISSING))
        )

    # Field missing → condition fails
    if field_val is None:
        return op == "="  # only matches if we're explicitly testing for None

    val = cond["value"]
    field_str = str(field_val)

    if op == "=":
        return str(field_val) == str(val) if val is not None else field_val is None
    if op == "!=":
        return str(field_val) != str(val)
    if op == "=~":
        # val is a regex literal like /pattern/flags
        pattern_str = str(val)
        flags = 0
        if pattern_str.startswith("/"):
            # Extract pattern and flags from /pattern/flags
            end_slash = pattern_str.rfind("/")
            if end_slash > 0:
                flags_str = pattern_str[end_slash + 1:]
                pattern_str = pattern_str[1:end_slash]
                if "i" in flags_str:
                    flags |= re.IGNORECASE
                if "s" in flags_str:
                    flags |= re.DOTALL
                if "m" in flags_str:
                    flags |= re.MULTILINE
            else:
                pattern_str = pattern_str[1:]
        try:
            return bool(re.search(pattern_str, field_str, flags))
        except re.error:
            return False
    if op in (">", ">=", "<", "<="):
        try:
            fv = float(field_val)
            cv = float(val)
        except (TypeError, ValueError):
            return False
        if op == ">":
            return fv > cv
        if op == ">=":
            return fv >= cv
        if op == "<":
            return fv < cv
        if op == "<=":
            return fv <= cv

    return False


class YARALParser(AbstractParser):
    """Parser for YARA-L 2.0 detection rules (Google Chronicle/SecOps).

    Converts a YARA-L rule text into the unified ParsedRule AST.

    Example YARA-L rule::

        rule detect_encoded_powershell {
          meta:
            author = "PurpleLab"
            description = "Detects PowerShell with encoded commands"
            severity = "HIGH"
          events:
            $e.metadata.event_type = "PROCESS_LAUNCH"
            $e.principal.process.command_line =~ /powershell.*-enc/i
          condition:
            $e
        }
    """

    language = "yara_l"

    def parse(self, rule_text: str, **kwargs) -> ParsedRule:
        """Parse a YARA-L rule into the unified ParsedRule AST.

        Args:
            rule_text: Raw YARA-L rule text.

        Returns:
            ParsedRule with metadata, filter conditions, and raw text.

        Raises:
            ValueError: If the rule text cannot be parsed.
        """
        text = rule_text.strip()

        # Extract rule name: "rule <name> {"
        name_match = re.search(r"\brule\s+(\w+)\s*\{", text)
        if not name_match:
            raise ValueError("YARA-L rule must start with 'rule <name> {'")
        rule_name = name_match.group(1)

        # Extract rule body (between outermost braces)
        brace_open = text.index("{", name_match.start())
        body = text[brace_open + 1:]
        # Find matching closing brace
        depth = 1
        body_end = 0
        for i, ch in enumerate(body):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    body_end = i
                    break
        body = body[:body_end]

        # Parse meta: section
        meta: dict[str, str] = {}
        meta_block = _strip_block(body, "meta")
        if meta_block:
            meta = _parse_meta_block(meta_block)

        description = meta.get("description", "")
        severity_raw = (meta.get("severity", "medium")).lower()
        severity = _SEVERITY_MAP.get(severity_raw, "medium")

        # Tags from meta
        tags_raw = meta.get("tags", "")
        tags: list[str] = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []

        # Parse events: section
        events_block = _strip_block(body, "events")
        conditions: list[dict[str, Any]] = []
        referenced_fields: set[str] = set()
        if events_block:
            conditions = _parse_events_block(events_block)
            referenced_fields = {c["field"] for c in conditions}

        # Build unified AST filter
        filter_ast = _conditions_to_ast(conditions)

        # Parse condition: section — store as plain string
        condition_block = _strip_block(body, "condition")
        condition_str = condition_block.strip() if condition_block else ""

        # Build ParsedRule
        return ParsedRule(
            source_language="yara_l",
            raw_text=rule_text,
            name=rule_name,
            description=description,
            severity=severity,
            mitre_techniques=[],
            filter=filter_ast,
            aggregation=None,
            referenced_fields=referenced_fields,
            data_sources=[],
            tags=tags,
        )

    def supports(self, rule_text: str) -> bool:
        """Check if text looks like a YARA-L rule.

        Args:
            rule_text: Raw text to inspect.

        Returns:
            True if the text contains a YARA-L rule header.
        """
        text = rule_text.strip()
        return bool(re.search(r"\brule\s+\w+\s*\{", text))

    def evaluate(
        self, rule: ParsedRule, events: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Evaluate a parsed YARA-L rule against a list of event dicts.

        Parses the events: conditions from the raw rule text, then tests
        each event against all conditions (AND logic). Returns all events
        that match.

        Args:
            rule: A ParsedRule produced by this parser.
            events: List of flat event dicts to test.

        Returns:
            Subset of events that satisfy all rule conditions.
        """
        # Re-parse condition dicts from raw text for evaluation
        events_block = _strip_block(rule.raw_text, "events")
        if not events_block:
            return []
        conditions = _parse_events_block(events_block)
        if not conditions:
            return events  # no conditions = match all

        matched: list[dict[str, Any]] = []
        for event in events:
            if all(_evaluate_condition(cond, event) for cond in conditions):
                matched.append(event)
        return matched

    def evaluate_single(
        self, rule: ParsedRule, event: dict[str, Any]
    ) -> bool:
        """Evaluate a YARA-L rule against a single event.

        Convenience wrapper for the common single-event check used by
        the RuleEvaluator.

        Args:
            rule: Parsed YARA-L rule.
            event: Single event dict.

        Returns:
            True if the event matches all conditions in the rule.
        """
        return bool(self.evaluate(rule, [event]))

    def extract_fields(self, query: str) -> list[str]:
        """Extract all field paths referenced in the events: block.

        Args:
            query: Raw YARA-L rule text.

        Returns:
            List of unique field path strings (e.g. "$e.principal.hostname").
        """
        events_block = _strip_block(query, "events")
        if not events_block:
            return []
        conditions = _parse_events_block(events_block)
        return list({c["field"] for c in conditions})
