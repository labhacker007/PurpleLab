"""Detection Efficacy Score (DES).

DES measures how well a detection rule library covers a threat landscape.
It combines five dimensions into a single 0–100 score using a weighted
geometric mean so that a zero in any dimension drags the total toward zero.

Formula:
    raw = (breadth^w1) × (depth^w2) × (freshness^w3) × (pass_rate^w4) × (signal^w5)
    DES = round(raw × 100, 1)

Dimensions
----------
breadth:    Fraction of known techniques with ≥1 detection rule.
            = covered_techniques / total_techniques

depth:      Quality-adjusted rule density per technique.
            = mean(min(rule_count_per_technique, depth_cap) / depth_cap)

freshness:  Exponential decay on rule age.
            Each rule contributes exp(-λ × days_since_tested) where λ = ln(2)/90
            (half-life 90 days). Freshness = mean contribution across all rules.

pass_rate:  Bayesian Beta-Binomial estimate of true detection probability.
            Uses a skeptical prior (α=1, β=3) so 0 tests → 25% pass rate.
            pass_rate = (α + successes) / (α + β + total_tests)

signal:     Fraction of rule alerts that are true positives (precision proxy).
            signal = 1 − false_positive_rate

Weights (sum to 1):
    breadth=0.25, depth=0.20, freshness=0.20, pass_rate=0.25, signal=0.10
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class RuleTestResult:
    """Result of running a single detection rule against test data."""
    rule_id: str
    technique_id: str           # MITRE ATT&CK ID
    passed: bool
    test_run_at: datetime       # When the test was run
    false_positive_rate: float = 0.0  # 0.0–1.0 (0 = no FPs)


@dataclass
class RuleSummary:
    """Aggregated test history for one detection rule."""
    rule_id: str
    technique_id: str
    total_tests: int = 0
    successes: int = 0
    last_tested_at: datetime | None = None
    false_positive_rate: float = 0.0


@dataclass
class DESResult:
    """Full DES result with component breakdown."""
    score: float                # 0.0–100.0
    breadth: float              # 0.0–1.0
    depth: float                # 0.0–1.0
    freshness: float            # 0.0–1.0
    pass_rate: float            # 0.0–1.0
    signal: float               # 0.0–1.0
    covered_techniques: int
    total_techniques: int
    rule_count: int
    weights: dict[str, float]
    computed_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "components": {
                "breadth": round(self.breadth, 4),
                "depth": round(self.depth, 4),
                "freshness": round(self.freshness, 4),
                "pass_rate": round(self.pass_rate, 4),
                "signal_quality": round(self.signal, 4),
            },
            "context": {
                "covered_techniques": self.covered_techniques,
                "total_techniques": self.total_techniques,
                "rule_count": self.rule_count,
            },
            "weights": self.weights,
            "computed_at": self.computed_at,
        }


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------

class DetectionEfficacyScore:
    """Computes DES given rule summaries and a known technique universe.

    Args:
        weights: Override default dimension weights (must sum to ~1.0).
        bayesian_alpha: Prior successes (skeptical prior default: 1).
        bayesian_beta: Prior failures (skeptical prior default: 3).
        freshness_halflife_days: Half-life for test freshness decay.
        depth_cap: Max rules per technique that count toward depth.
    """

    DEFAULT_WEIGHTS = {
        "breadth": 0.25,
        "depth": 0.20,
        "freshness": 0.20,
        "pass_rate": 0.25,
        "signal": 0.10,
    }

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        bayesian_alpha: float = 1.0,
        bayesian_beta: float = 3.0,
        freshness_halflife_days: float = 90.0,
        depth_cap: int = 5,
    ) -> None:
        self.weights = weights or dict(self.DEFAULT_WEIGHTS)
        self.alpha = bayesian_alpha
        self.beta = bayesian_beta
        self._lambda = math.log(2) / freshness_halflife_days
        self.depth_cap = depth_cap

    def compute(
        self,
        rules: list[RuleSummary],
        known_techniques: list[str],
        now: datetime | None = None,
    ) -> DESResult:
        """Compute DES from rule summaries.

        Args:
            rules: Aggregated test history per rule.
            known_techniques: Full set of MITRE technique IDs in scope.
            now: Reference timestamp (defaults to UTC now).

        Returns:
            DESResult with score and component breakdown.
        """
        now = now or datetime.now(timezone.utc)
        total = max(len(known_techniques), 1)

        # --- Breadth ---
        covered = {r.technique_id for r in rules if r.technique_id in known_techniques}
        breadth = len(covered) / total

        # --- Depth ---
        depth = self._compute_depth(rules, known_techniques)

        # --- Freshness ---
        freshness = self._compute_freshness(rules, now)

        # --- Pass rate (Bayesian) ---
        pass_rate = self._compute_pass_rate(rules)

        # --- Signal quality ---
        signal = self._compute_signal(rules)

        # --- Weighted geometric mean ---
        components = {
            "breadth": breadth,
            "depth": depth,
            "freshness": freshness,
            "pass_rate": pass_rate,
            "signal": signal,
        }
        w = self.weights
        log_score = sum(
            w[k] * math.log(max(v, 1e-9))  # clamp to avoid log(0)
            for k, v in components.items()
        )
        raw = math.exp(log_score)
        score = round(raw * 100, 1)

        return DESResult(
            score=score,
            breadth=breadth,
            depth=depth,
            freshness=freshness,
            pass_rate=pass_rate,
            signal=signal,
            covered_techniques=len(covered),
            total_techniques=total,
            rule_count=len(rules),
            weights=w,
            computed_at=now.isoformat(),
        )

    def _compute_depth(
        self,
        rules: list[RuleSummary],
        known_techniques: list[str],
    ) -> float:
        """Mean capped rule density across all known techniques."""
        technique_counts: dict[str, int] = {}
        for r in rules:
            if r.technique_id in known_techniques:
                technique_counts[r.technique_id] = (
                    technique_counts.get(r.technique_id, 0) + 1
                )
        if not known_techniques:
            return 0.0
        depth_values = [
            min(technique_counts.get(t, 0), self.depth_cap) / self.depth_cap
            for t in known_techniques
        ]
        return sum(depth_values) / len(depth_values)

    def _compute_freshness(
        self, rules: list[RuleSummary], now: datetime
    ) -> float:
        """Exponential decay freshness across all rules."""
        if not rules:
            return 0.0
        scores = []
        for r in rules:
            if r.last_tested_at is None:
                scores.append(0.0)  # never tested
            else:
                last = r.last_tested_at
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                days = max((now - last).total_seconds() / 86400, 0)
                scores.append(math.exp(-self._lambda * days))
        return sum(scores) / len(scores)

    def _compute_pass_rate(self, rules: list[RuleSummary]) -> float:
        """Portfolio Bayesian pass rate with skeptical prior."""
        total_tests = sum(r.total_tests for r in rules)
        total_success = sum(r.successes for r in rules)
        # Beta-Binomial posterior mean
        return (self.alpha + total_success) / (self.alpha + self.beta + total_tests)

    def _compute_signal(self, rules: list[RuleSummary]) -> float:
        """Mean signal quality = 1 - false_positive_rate across rules."""
        if not rules:
            return 0.0
        return sum(1.0 - r.false_positive_rate for r in rules) / len(rules)
