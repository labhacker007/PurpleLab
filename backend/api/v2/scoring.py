"""Scoring API — exposes DES and IHDS scores via REST.

GET  /scoring/des       — Compute current DES from all rules in DB
GET  /scoring/ihds      — Compute IHDS (with optional Joti data)
POST /scoring/snapshot  — Save current scores to DB for trend tracking
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException

from backend.db.session import async_session
from backend.db.models import ImportedRule

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scoring", tags=["scoring"])

# Known MITRE techniques universe (shared with pipeline engine)
_KNOWN_TECHNIQUES = [
    "T1595", "T1592", "T1589", "T1590", "T1591",
    "T1583", "T1584", "T1587", "T1588",
    "T1566", "T1190", "T1133", "T1078",
    "T1059", "T1053", "T1047", "T1204", "T1203",
    "T1547", "T1546", "T1543", "T1098",
    "T1548", "T1134", "T1055",
    "T1036", "T1027", "T1070", "T1562", "T1140", "T1218",
    "T1003", "T1110", "T1555", "T1558", "T1552",
    "T1083", "T1082", "T1057", "T1018", "T1016",
    "T1021", "T1570", "T1080",
    "T1560", "T1005", "T1074",
    "T1071", "T1105", "T1095", "T1572", "T1573",
    "T1041", "T1048", "T1567",
    "T1486", "T1490", "T1489", "T1485", "T1529",
    "T1566.001", "T1059.001", "T1003.001", "T1110.003",
    "T1543.003", "T1552.007", "T1611", "T1610",
]


# ---------------------------------------------------------------------------
# GET /scoring/des
# ---------------------------------------------------------------------------

@router.get("/des")
async def get_des_score() -> dict[str, Any]:
    """Compute current DES from all rules in DB."""
    from backend.scoring.des import DetectionEfficacyScore, RuleSummary
    from sqlalchemy import select

    now = datetime.now(timezone.utc)

    # Load all enabled rules
    async with async_session() as db:
        result = await db.execute(
            select(ImportedRule).where(ImportedRule.enabled == True)
        )
        rules = result.scalars().all()

    # Build RuleSummary objects
    summaries: list[RuleSummary] = []
    for rule in rules:
        techs: list[str] = rule.mitre_techniques or []
        for tech in techs:
            summaries.append(
                RuleSummary(
                    rule_id=str(rule.id),
                    technique_id=tech.upper(),
                    total_tests=0,
                    successes=0,
                    last_tested_at=rule.updated_at,
                    false_positive_rate=0.0,
                )
            )

    scorer = DetectionEfficacyScore()
    des = scorer.compute(summaries, _KNOWN_TECHNIQUES, now)

    # Determine interpretation
    interpretation = _interpret_des(des.score)

    return {
        "overall_score": des.score,
        "breadth": round(des.breadth, 4),
        "depth": round(des.depth, 4),
        "freshness": round(des.freshness, 4),
        "pass_rate": round(des.pass_rate, 4),
        "signal": round(des.signal, 4),
        "rules_analyzed": len(rules),
        "techniques_covered": des.covered_techniques,
        "total_techniques": des.total_techniques,
        "weights": des.weights,
        "computed_at": des.computed_at,
        "interpretation": interpretation,
    }


# ---------------------------------------------------------------------------
# GET /scoring/ihds
# ---------------------------------------------------------------------------

@router.get("/ihds")
async def get_ihds_score() -> dict[str, Any]:
    """Compute IHDS. Pulls Joti data if configured."""
    from backend.scoring.des import RuleSummary
    from backend.scoring.ihds import IntelHuntDetectionScore, TTPIntelEntry, HuntEntry
    from backend.db.models import ThreatActor
    from sqlalchemy import select

    now = datetime.now(timezone.utc)

    # ── Load rules ────────────────────────────────────────────────────
    async with async_session() as db:
        rules_result = await db.execute(
            select(ImportedRule).where(ImportedRule.enabled == True)
        )
        rules = rules_result.scalars().all()

        # Load threat actor techniques as intel entries
        actors_result = await db.execute(select(ThreatActor))
        actors = actors_result.scalars().all()

    # Build rule summaries
    rule_summaries: list[RuleSummary] = []
    for rule in rules:
        techs: list[str] = rule.mitre_techniques or []
        for tech in techs:
            rule_summaries.append(
                RuleSummary(
                    rule_id=str(rule.id),
                    technique_id=tech.upper(),
                    total_tests=0,
                    successes=0,
                    last_tested_at=rule.updated_at,
                    false_positive_rate=0.0,
                )
            )

    # Build intel entries from threat actors
    intel_entries: list[TTPIntelEntry] = []
    for actor in actors:
        techs: list[str] = actor.techniques or []
        for tech in techs:
            intel_entries.append(
                TTPIntelEntry(
                    technique_id=tech.upper(),
                    threat_actor=actor.name,
                    observed_at=actor.updated_at,
                )
            )

    # ── Pull Joti HCCS + TES if configured ───────────────────────────
    joti_hunt_score: float | None = None
    joti_hccs_data: dict[str, Any] = {}
    joti_tes_data: dict[str, Any] = {}
    joti_gaps: list[dict[str, Any]] = []
    joti_connected: bool = False
    try:
        from backend.joti import get_joti_client
        joti_client = get_joti_client()
        if joti_client:
            # Check connectivity first (fast health ping)
            joti_connected = await joti_client.is_connected()
            if joti_connected:
                # HCCS — Hunt Coverage Completeness Score
                hccs_raw = await joti_client.get_coverage_score()
                if hccs_raw:
                    raw_score = hccs_raw.get("score", 0.0)
                    # Joti returns 0-100; IHDS expects 0.0-100.0, same scale
                    joti_hunt_score = float(raw_score)
                    joti_hccs_data = {
                        "score": joti_hunt_score,
                        "covered_techniques": hccs_raw.get("covered_techniques", 0),
                        "total_techniques": hccs_raw.get("total_techniques", 0),
                        "computed_at": hccs_raw.get("computed_at", ""),
                    }
                # TES — Threat Exposure Score
                tes_raw = await joti_client.get_threat_profile()
                if tes_raw:
                    joti_tes_data = {
                        "score": float(tes_raw.get("score", 0.0)),
                        "components": tes_raw.get("components", {}),
                        "computed_at": tes_raw.get("computed_at", ""),
                    }
                # Active alerts as hunt gaps proxy
                active_alerts = await joti_client.get_active_alerts(limit=20)
                joti_gaps = [
                    {
                        "technique_id": a.get("technique_id") or a.get("mitre_technique"),
                        "severity": a.get("severity", "medium"),
                        "title": a.get("title", ""),
                    }
                    for a in active_alerts
                    if a.get("technique_id") or a.get("mitre_technique")
                ]
    except Exception as exc:
        logger.debug("Joti IHDS data pull failed (non-fatal): %s", exc)

    # ── Hunt entries: build from intel techniques with no Joti score ──
    # If Joti is not available, we have no hunt data → empty list
    hunt_entries: list[HuntEntry] = []

    # ── Compute IHDS ──────────────────────────────────────────────────
    scorer = IntelHuntDetectionScore()
    ihds = scorer.compute(
        intel_entries=intel_entries,
        hunt_entries=hunt_entries,
        rule_summaries=rule_summaries,
        known_techniques=_KNOWN_TECHNIQUES,
        joti_hunt_score=joti_hunt_score,
        now=now,
    )

    # Gap list: combine local + Joti gaps
    local_gap_techniques: list[str] = []
    covered_set = {rs.technique_id for rs in rule_summaries}
    for t in _KNOWN_TECHNIQUES:
        if t not in covered_set:
            local_gap_techniques.append(t)

    return {
        "ihds_score": ihds.score,
        "intel_score": round(ihds.intel_score, 4),
        "hunt_score": round(ihds.hunt_score, 4),
        "detection_score": round(ihds.detection_score, 4),
        "intel_techniques": ihds.intel_technique_count,
        "hunted_techniques": ihds.hunted_technique_count,
        "detected_techniques": ihds.detected_technique_count,
        "joti_connected": joti_connected,
        "joti_hunt_score_used": ihds.joti_hunt_score_used,
        "joti_hccs": joti_hccs_data if joti_hccs_data else None,
        "joti_tes": joti_tes_data if joti_tes_data else None,
        "ihds_interpretation": ihds.to_dict().get("interpretation", ""),
        "gaps": {
            "local_uncovered": local_gap_techniques[:50],  # cap for response size
            "joti_gaps": joti_gaps[:20],
            "total_local_uncovered": len(local_gap_techniques),
        },
        "computed_at": ihds.computed_at,
    }


# ---------------------------------------------------------------------------
# POST /scoring/snapshot
# ---------------------------------------------------------------------------

@router.post("/snapshot")
async def save_scoring_snapshot() -> dict[str, Any]:
    """Save current DES + IHDS as a snapshot to DB for trend tracking.

    Uses the AuditLog table to persist snapshot records since no dedicated
    scoring_snapshots table exists yet. The payload contains the full scores.
    """
    from backend.db.models import AuditLog
    import asyncio

    # Compute scores concurrently
    try:
        des_task = asyncio.create_task(_compute_des_snapshot())
        ihds_task = asyncio.create_task(_compute_ihds_snapshot())
        des_data, ihds_data = await asyncio.gather(des_task, ihds_task)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to compute scores for snapshot: {exc}",
        )

    snapshot_payload = {
        "des": des_data,
        "ihds": ihds_data,
        "snapshot_type": "manual",
    }

    # Persist to audit log as a snapshot record
    try:
        async with async_session() as db:
            log_entry = AuditLog(
                id=uuid.uuid4(),
                action="scoring_snapshot",
                resource_type="scoring",
                resource_id="snapshot",
                payload=snapshot_payload,
            )
            db.add(log_entry)
            await db.commit()
            await db.refresh(log_entry)
            snapshot_id = str(log_entry.id)
            created_at = log_entry.created_at.isoformat() if log_entry.created_at else None
    except Exception as exc:
        logger.warning("Failed to persist snapshot: %s", exc)
        snapshot_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()

    return {
        "snapshot_id": snapshot_id,
        "created_at": created_at,
        "des_score": des_data.get("overall_score"),
        "ihds_score": ihds_data.get("ihds_score"),
        "snapshot": snapshot_payload,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _interpret_des(score: float) -> str:
    if score >= 80:
        return "Excellent — detection rule library provides strong coverage."
    if score >= 60:
        return "Good — coverage is solid with some gaps to address."
    if score >= 40:
        return "Fair — notable gaps in breadth, depth, or freshness."
    if score >= 20:
        return "Poor — detection library needs significant improvement."
    return "Critical — very low detection coverage; prioritise rule development."


async def _compute_des_snapshot() -> dict[str, Any]:
    """Compute DES for snapshot (minimal version)."""
    try:
        from backend.scoring.des import DetectionEfficacyScore, RuleSummary
        from sqlalchemy import select

        now = datetime.now(timezone.utc)
        async with async_session() as db:
            result = await db.execute(
                select(ImportedRule).where(ImportedRule.enabled == True)
            )
            rules = result.scalars().all()

        summaries = [
            RuleSummary(
                rule_id=str(r.id),
                technique_id=tech.upper(),
                total_tests=0,
                successes=0,
                last_tested_at=r.updated_at,
            )
            for r in rules
            for tech in (r.mitre_techniques or [])
        ]

        scorer = DetectionEfficacyScore()
        des = scorer.compute(summaries, _KNOWN_TECHNIQUES, now)
        return {
            "overall_score": des.score,
            "breadth": round(des.breadth, 4),
            "depth": round(des.depth, 4),
            "freshness": round(des.freshness, 4),
            "pass_rate": round(des.pass_rate, 4),
            "signal": round(des.signal, 4),
            "rules_analyzed": len(rules),
            "techniques_covered": des.covered_techniques,
            "computed_at": des.computed_at,
        }
    except Exception as exc:
        logger.warning("DES snapshot failed: %s", exc)
        return {"error": str(exc)}


async def _compute_ihds_snapshot() -> dict[str, Any]:
    """Compute IHDS for snapshot (minimal version)."""
    try:
        from backend.scoring.des import RuleSummary
        from backend.scoring.ihds import IntelHuntDetectionScore, TTPIntelEntry
        from backend.db.models import ThreatActor
        from sqlalchemy import select

        now = datetime.now(timezone.utc)
        async with async_session() as db:
            rules_result = await db.execute(
                select(ImportedRule).where(ImportedRule.enabled == True)
            )
            rules = rules_result.scalars().all()
            actors_result = await db.execute(select(ThreatActor))
            actors = actors_result.scalars().all()

        rule_summaries = [
            RuleSummary(
                rule_id=str(r.id),
                technique_id=tech.upper(),
                total_tests=0,
                successes=0,
                last_tested_at=r.updated_at,
            )
            for r in rules
            for tech in (r.mitre_techniques or [])
        ]

        intel_entries = [
            TTPIntelEntry(
                technique_id=tech.upper(),
                threat_actor=actor.name,
                observed_at=actor.updated_at,
            )
            for actor in actors
            for tech in (actor.techniques or [])
        ]

        scorer = IntelHuntDetectionScore()
        ihds = scorer.compute(
            intel_entries=intel_entries,
            hunt_entries=[],
            rule_summaries=rule_summaries,
            known_techniques=_KNOWN_TECHNIQUES,
            now=now,
        )
        return {
            "ihds_score": ihds.score,
            "intel_score": round(ihds.intel_score, 4),
            "hunt_score": round(ihds.hunt_score, 4),
            "detection_score": round(ihds.detection_score, 4),
            "computed_at": ihds.computed_at,
        }
    except Exception as exc:
        logger.warning("IHDS snapshot failed: %s", exc)
        return {"error": str(exc)}
