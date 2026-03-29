"""Intel-to-Hunt-to-Detection Score (IHDS).

IHDS measures how well the full pipeline — from threat intelligence intake
through hunt coverage to detection rule firing — operates end-to-end.

The score is MULTIPLICATIVE: if any stage is zero, the overall score is zero.
This reflects reality: great detection rules are worthless if they cover
techniques your intel says the adversary never uses.

Formula:
    IHDS = Intel × Hunt × Detection × 100

    Intel     = coverage of adversary TTPs in the knowledge base
                (with recency decay — TTP intelligence older than 180 days decays)
    Hunt      = fraction of intel-covered techniques that have active hunts
                (with recency decay — hunts older than 60 days decay)
    Detection = DES pass_rate component for the hunted techniques
                (Bayesian Beta-Binomial, same prior as DES)

All three sub-scores are 0.0–1.0. IHDS is 0.0–100.0.

Integration with Joti:
    Joti provides the Hunt sub-score via GET /api/hunt-coverage/score (HCCS).
    If a Joti client is available, IHDS uses Joti's HCCS for the Hunt stage
    rather than computing it locally. This keeps the scores consistent.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class TTPIntelEntry:
    """A known TTP from threat intelligence."""
    technique_id: str
    threat_actor: str | None = None
    observed_at: datetime | None = None   # When the TTP was last observed


@dataclass
class HuntEntry:
    """A threat hunt entry covering a technique."""
    technique_id: str
    hunt_id: str
    last_executed_at: datetime | None = None
    result: str = "no_findings"           # no_findings|findings|escalated


@dataclass
class IHDSResult:
    """Full IHDS result with component breakdown."""
    score: float            # 0.0–100.0
    intel_score: float      # 0.0–1.0
    hunt_score: float       # 0.0–1.0
    detection_score: float  # 0.0–1.0
    intel_technique_count: int
    hunted_technique_count: int
    detected_technique_count: int
    joti_hunt_score_used: bool
    computed_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "components": {
                "intel": round(self.intel_score, 4),
                "hunt": round(self.hunt_score, 4),
                "detection": round(self.detection_score, 4),
            },
            "context": {
                "intel_techniques": self.intel_technique_count,
                "hunted_techniques": self.hunted_technique_count,
                "detected_techniques": self.detected_technique_count,
                "joti_hunt_score_used": self.joti_hunt_score_used,
            },
            "computed_at": self.computed_at,
            "interpretation": _interpret(self.score),
        }


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------

class IntelHuntDetectionScore:
    """Computes IHDS from intel, hunt, and detection data.

    Args:
        ttp_halflife_days: Decay half-life for TTP intel recency (default 180d).
        hunt_halflife_days: Decay half-life for hunt recency (default 60d).
        bayesian_alpha: Prior successes for detection pass-rate (default 1).
        bayesian_beta: Prior failures for detection pass-rate (default 3).
    """

    def __init__(
        self,
        ttp_halflife_days: float = 180.0,
        hunt_halflife_days: float = 60.0,
        bayesian_alpha: float = 1.0,
        bayesian_beta: float = 3.0,
    ) -> None:
        self._ttp_lambda = math.log(2) / ttp_halflife_days
        self._hunt_lambda = math.log(2) / hunt_halflife_days
        self.alpha = bayesian_alpha
        self.beta = bayesian_beta

    def compute(
        self,
        intel_entries: list[TTPIntelEntry],
        hunt_entries: list[HuntEntry],
        rule_summaries: list[Any],      # list[des.RuleSummary]
        known_techniques: list[str],
        joti_hunt_score: float | None = None,
        now: datetime | None = None,
    ) -> IHDSResult:
        """Compute IHDS.

        Args:
            intel_entries: Known TTPs from threat intelligence.
            hunt_entries: Executed hunts with recency info.
            rule_summaries: Detection rule test history (RuleSummary objects).
            known_techniques: Full universe of MITRE techniques in scope.
            joti_hunt_score: If provided, override hunt_score with Joti HCCS
                             value (0.0–1.0 or 0–100; auto-normalised).
            now: Reference timestamp.

        Returns:
            IHDSResult with score and breakdown.
        """
        now = now or datetime.now(timezone.utc)
        total = max(len(known_techniques), 1)

        # --- Intel score ---
        intel_score, intel_count = self._intel_score(
            intel_entries, known_techniques, now
        )

        # --- Hunt score ---
        joti_used = False
        if joti_hunt_score is not None:
            # Normalise Joti HCCS: may be 0–100 or 0–1
            hunt_score = joti_hunt_score / 100.0 if joti_hunt_score > 1 else joti_hunt_score
            hunt_score = max(0.0, min(1.0, hunt_score))
            joti_used = True
            hunt_count = round(hunt_score * len({e.technique_id for e in intel_entries}))
        else:
            hunt_score, hunt_count = self._hunt_score(
                hunt_entries, intel_entries, now
            )

        # --- Detection score (Bayesian pass rate over hunted techniques) ---
        hunted_techniques = {e.technique_id for e in hunt_entries}
        detection_score, detected_count = self._detection_score(
            rule_summaries, hunted_techniques
        )

        # --- Multiplicative combination ---
        raw = intel_score * hunt_score * detection_score
        score = round(raw * 100, 1)

        return IHDSResult(
            score=score,
            intel_score=intel_score,
            hunt_score=hunt_score,
            detection_score=detection_score,
            intel_technique_count=intel_count,
            hunted_technique_count=hunt_count,
            detected_technique_count=detected_count,
            joti_hunt_score_used=joti_used,
            computed_at=now.isoformat(),
        )

    def _intel_score(
        self,
        intel_entries: list[TTPIntelEntry],
        known_techniques: list[str],
        now: datetime,
    ) -> tuple[float, int]:
        """Fraction of known techniques with recent intel (decay-weighted)."""
        if not known_techniques:
            return 0.0, 0

        known_set = set(known_techniques)
        # Map technique → max decayed weight across all intel entries
        weights: dict[str, float] = {}
        for entry in intel_entries:
            if entry.technique_id not in known_set:
                continue
            w = self._decay(entry.observed_at, self._ttp_lambda, now)
            weights[entry.technique_id] = max(weights.get(entry.technique_id, 0.0), w)

        score = sum(weights.values()) / len(known_techniques)
        return min(score, 1.0), len(weights)

    def _hunt_score(
        self,
        hunt_entries: list[HuntEntry],
        intel_entries: list[TTPIntelEntry],
        now: datetime,
    ) -> tuple[float, int]:
        """Fraction of intel-covered techniques with recent hunts."""
        intel_techniques = {e.technique_id for e in intel_entries}
        if not intel_techniques:
            return 0.0, 0

        # Map technique → max decayed hunt weight
        weights: dict[str, float] = {}
        for entry in hunt_entries:
            if entry.technique_id not in intel_techniques:
                continue
            w = self._decay(entry.last_executed_at, self._hunt_lambda, now)
            weights[entry.technique_id] = max(weights.get(entry.technique_id, 0.0), w)

        score = sum(weights.values()) / len(intel_techniques)
        return min(score, 1.0), len(weights)

    def _detection_score(
        self,
        rule_summaries: list[Any],
        hunted_techniques: set[str],
    ) -> tuple[float, int]:
        """Bayesian pass rate restricted to hunted techniques."""
        relevant = [r for r in rule_summaries if r.technique_id in hunted_techniques]
        if not relevant:
            # No rules for hunted techniques → use prior only
            prior_only = self.alpha / (self.alpha + self.beta)
            return prior_only, 0

        total_tests = sum(r.total_tests for r in relevant)
        total_success = sum(r.successes for r in relevant)
        rate = (self.alpha + total_success) / (self.alpha + self.beta + total_tests)
        detected = len({r.technique_id for r in relevant if r.successes > 0})
        return rate, detected

    def _decay(
        self, observed_at: datetime | None, lam: float, now: datetime
    ) -> float:
        """Exponential decay: 1.0 if observed now, 0.5 at half-life."""
        if observed_at is None:
            return 0.25  # Stale/unknown intel still has some weight
        if observed_at.tzinfo is None:
            observed_at = observed_at.replace(tzinfo=timezone.utc)
        days = max((now - observed_at).total_seconds() / 86400, 0)
        return math.exp(-lam * days)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _interpret(score: float) -> str:
    if score >= 80:
        return "Excellent — intel, hunts, and detections are well-aligned."
    if score >= 60:
        return "Good — minor gaps in one or more pipeline stages."
    if score >= 40:
        return "Fair — significant gaps; one stage is degrading the pipeline."
    if score >= 20:
        return "Poor — multiple pipeline stages have major coverage gaps."
    return "Critical — pipeline is largely broken; prioritise coverage immediately."
