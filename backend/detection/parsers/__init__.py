"""Detection rule parsers for various query languages.

Exports all parser classes and the unified AST types.
"""
from backend.detection.parsers.base_parser import (
    AbstractParser,
    Aggregation,
    Condition,
    LogicGroup,
    LogicOp,
    Operator,
    ParsedRule,
)
from backend.detection.parsers.esql_parser import ESQLParser
from backend.detection.parsers.kql_parser import KQLParser
from backend.detection.parsers.sigma_parser import SigmaParser
from backend.detection.parsers.spl_parser import SPLParser

__all__ = [
    "AbstractParser",
    "Aggregation",
    "Condition",
    "ESQLParser",
    "KQLParser",
    "LogicGroup",
    "LogicOp",
    "Operator",
    "ParsedRule",
    "SigmaParser",
    "SPLParser",
]
