"""Detection engine -- rule management, parsing, evaluation, and coverage analysis.

Exports the main classes for the detection rule engine.
"""
from backend.detection.coverage import CoverageAnalyzer, CoverageMatrix, GapAnalysis
from backend.detection.evaluator import EvalResult, RuleEvaluator
from backend.detection.rule_manager import RuleManager, TestRunResult

__all__ = [
    "CoverageAnalyzer",
    "CoverageMatrix",
    "EvalResult",
    "GapAnalysis",
    "RuleEvaluator",
    "RuleManager",
    "TestRunResult",
]
