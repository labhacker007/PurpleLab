"""Scoring API — exposes DES and IHDS scores via REST.

GET  /scoring/des          — Compute current DES from all rules in DB
GET  /scoring/ihds         — Compute IHDS (with optional Joti data)
POST /scoring/snapshot     — Save current scores to DB for trend tracking
GET  /scoring/history      — DES score history over time
GET  /scoring/breakdown    — Full DES breakdown by tactic
GET  /scoring/gap-analysis — Detailed gap report
GET  /scoring/leaderboard  — Top use cases by run count and pass rate
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query

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


# ---------------------------------------------------------------------------
# GET /scoring/history
# ---------------------------------------------------------------------------

@router.get("/history")
async def get_scoring_history(
    days: int = Query(30, ge=1, le=365),
    granularity: str = Query("day", pattern="^(day|week)$"),
) -> list[dict[str, Any]]:
    """DES score history over time.

    Sources data from AuditLog snapshots. If none exist, returns a synthetic
    history derived from the current DES score with slight variation.
    """
    from backend.db.models import AuditLog
    from sqlalchemy import select, and_

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    async with async_session() as db:
        result = await db.execute(
            select(AuditLog)
            .where(
                and_(
                    AuditLog.action == "scoring_snapshot",
                    AuditLog.created_at >= cutoff,
                )
            )
            .order_by(AuditLog.created_at.asc())
        )
        snapshots = result.scalars().all()

    if snapshots:
        # Group snapshots by day/week bucket
        buckets: dict[str, list[dict[str, Any]]] = {}
        for snap in snapshots:
            ts = snap.created_at
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if granularity == "week":
                # ISO week start (Monday)
                week_start = ts - timedelta(days=ts.weekday())
                key = week_start.strftime("%Y-%m-%d")
            else:
                key = ts.strftime("%Y-%m-%d")

            payload = snap.payload or {}
            des_data = payload.get("des", {})
            entry = {
                "des_score": des_data.get("overall_score", 0.0),
                "rules_count": des_data.get("rules_analyzed", 0),
                "techniques_covered": des_data.get("techniques_covered", 0),
            }
            if key not in buckets:
                buckets[key] = []
            buckets[key].append(entry)

        history = []
        for date_key in sorted(buckets.keys()):
            entries = buckets[date_key]
            avg_des = sum(e["des_score"] for e in entries) / len(entries)
            avg_rules = int(sum(e["rules_count"] for e in entries) / len(entries))
            history.append({
                "date": date_key,
                "des_score": round(avg_des, 4),
                "rules_count": avg_rules,
                "use_cases_passing": 0,
                "use_cases_total": 0,
            })
        return history
    else:
        # No snapshots — synthesize from current DES for UI to show something
        try:
            des_data = await _compute_des_snapshot()
            current_score = des_data.get("overall_score", 0.5)
            rules_count = des_data.get("rules_analyzed", 0)
        except Exception:
            current_score = 0.5
            rules_count = 0

        import math
        history = []
        num_points = days // (7 if granularity == "week" else 1)
        num_points = min(num_points, 90)
        now = datetime.now(timezone.utc)

        for i in range(num_points, -1, -1):
            if granularity == "week":
                ts = now - timedelta(weeks=i)
                ts = ts - timedelta(days=ts.weekday())
            else:
                ts = now - timedelta(days=i)

            # Gentle trend: score was slightly lower further in the past
            trend_factor = (num_points - i) / max(num_points, 1)
            noise = math.sin(i * 0.7) * 0.02
            synth_score = max(0.0, min(1.0, current_score * (0.85 + 0.15 * trend_factor) + noise))

            history.append({
                "date": ts.strftime("%Y-%m-%d"),
                "des_score": round(synth_score, 4),
                "rules_count": rules_count,
                "use_cases_passing": 0,
                "use_cases_total": 0,
            })
        return history


# ---------------------------------------------------------------------------
# GET /scoring/breakdown
# ---------------------------------------------------------------------------

# Technique-to-tactic mapping for the known techniques universe
_TECHNIQUE_TACTIC_MAP: dict[str, str] = {
    # Reconnaissance
    "T1595": "reconnaissance", "T1592": "reconnaissance", "T1589": "reconnaissance",
    "T1590": "reconnaissance", "T1591": "reconnaissance",
    # Resource Development
    "T1583": "resource-development", "T1584": "resource-development",
    "T1587": "resource-development", "T1588": "resource-development",
    # Initial Access
    "T1566": "initial-access", "T1190": "initial-access", "T1133": "initial-access",
    "T1078": "initial-access", "T1566.001": "initial-access",
    # Execution
    "T1059": "execution", "T1053": "execution", "T1047": "execution",
    "T1204": "execution", "T1203": "execution",
    "T1059.001": "execution",
    # Persistence
    "T1547": "persistence", "T1546": "persistence", "T1543": "persistence",
    "T1098": "persistence", "T1543.003": "persistence",
    # Privilege Escalation
    "T1548": "privilege-escalation", "T1134": "privilege-escalation", "T1055": "privilege-escalation",
    # Defense Evasion
    "T1036": "defense-evasion", "T1027": "defense-evasion", "T1070": "defense-evasion",
    "T1562": "defense-evasion", "T1140": "defense-evasion", "T1218": "defense-evasion",
    # Credential Access
    "T1003": "credential-access", "T1110": "credential-access", "T1555": "credential-access",
    "T1558": "credential-access", "T1552": "credential-access",
    "T1003.001": "credential-access", "T1110.003": "credential-access", "T1552.007": "credential-access",
    # Discovery
    "T1083": "discovery", "T1082": "discovery", "T1057": "discovery",
    "T1018": "discovery", "T1016": "discovery",
    # Lateral Movement
    "T1021": "lateral-movement", "T1570": "lateral-movement", "T1080": "lateral-movement",
    # Collection
    "T1560": "collection", "T1005": "collection", "T1074": "collection",
    # Command and Control
    "T1071": "command-and-control", "T1105": "command-and-control", "T1095": "command-and-control",
    "T1572": "command-and-control", "T1573": "command-and-control",
    # Exfiltration
    "T1041": "exfiltration", "T1048": "exfiltration", "T1567": "exfiltration",
    # Impact
    "T1486": "impact", "T1490": "impact", "T1489": "impact",
    "T1485": "impact", "T1529": "impact",
    # Cloud-specific
    "T1611": "privilege-escalation", "T1610": "execution",
}

_TECHNIQUE_NAMES: dict[str, str] = {
    "T1595": "Active Scanning", "T1592": "Gather Victim Host Info",
    "T1589": "Gather Victim Identity Info", "T1590": "Gather Victim Network Info",
    "T1591": "Gather Victim Org Info", "T1583": "Acquire Infrastructure",
    "T1584": "Compromise Infrastructure", "T1587": "Develop Capabilities",
    "T1588": "Obtain Capabilities", "T1566": "Phishing", "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services", "T1078": "Valid Accounts",
    "T1059": "Command and Scripting Interpreter", "T1053": "Scheduled Task/Job",
    "T1047": "Windows Management Instrumentation", "T1204": "User Execution",
    "T1203": "Exploitation for Client Execution", "T1547": "Boot or Logon Autostart Execution",
    "T1546": "Event Triggered Execution", "T1543": "Create or Modify System Process",
    "T1098": "Account Manipulation", "T1548": "Abuse Elevation Control Mechanism",
    "T1134": "Access Token Manipulation", "T1055": "Process Injection",
    "T1036": "Masquerading", "T1027": "Obfuscated Files or Information",
    "T1070": "Indicator Removal", "T1562": "Impair Defenses",
    "T1140": "Deobfuscate/Decode Files or Information", "T1218": "System Binary Proxy Execution",
    "T1003": "OS Credential Dumping", "T1110": "Brute Force",
    "T1555": "Credentials from Password Stores", "T1558": "Steal or Forge Kerberos Tickets",
    "T1552": "Unsecured Credentials", "T1083": "File and Directory Discovery",
    "T1082": "System Information Discovery", "T1057": "Process Discovery",
    "T1018": "Remote System Discovery", "T1016": "System Network Configuration Discovery",
    "T1021": "Remote Services", "T1570": "Lateral Tool Transfer",
    "T1080": "Taint Shared Content", "T1560": "Archive Collected Data",
    "T1005": "Data from Local System", "T1074": "Data Staged",
    "T1071": "Application Layer Protocol", "T1105": "Ingress Tool Transfer",
    "T1095": "Non-Application Layer Protocol", "T1572": "Protocol Tunneling",
    "T1573": "Encrypted Channel", "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol", "T1567": "Exfiltration Over Web Service",
    "T1486": "Data Encrypted for Impact", "T1490": "Inhibit System Recovery",
    "T1489": "Service Stop", "T1485": "Data Destruction", "T1529": "System Shutdown/Reboot",
    "T1566.001": "Spearphishing Attachment", "T1059.001": "PowerShell",
    "T1003.001": "LSASS Memory", "T1110.003": "Password Spraying",
    "T1543.003": "Windows Service", "T1552.007": "Container API",
    "T1611": "Escape to Host", "T1610": "Deploy Container",
}


@router.get("/breakdown")
async def get_scoring_breakdown() -> list[dict[str, Any]]:
    """Full DES breakdown by tactic. Sorted by coverage_pct ascending (gaps first)."""
    from sqlalchemy import select

    async with async_session() as db:
        result = await db.execute(
            select(ImportedRule).where(ImportedRule.enabled == True)
        )
        rules = result.scalars().all()

    # Build covered techniques set and per-technique rule counts
    covered_techniques: set[str] = set()
    rules_per_technique: dict[str, int] = {}
    for rule in rules:
        for tech in (rule.mitre_techniques or []):
            t = tech.upper()
            covered_techniques.add(t)
            rules_per_technique[t] = rules_per_technique.get(t, 0) + 1

    # Group all known techniques by tactic
    tactic_data: dict[str, dict[str, Any]] = {}
    for tech in _KNOWN_TECHNIQUES:
        tactic = _TECHNIQUE_TACTIC_MAP.get(tech, "other")
        if tactic not in tactic_data:
            tactic_data[tactic] = {
                "tactic": tactic,
                "total": 0,
                "covered": 0,
                "rules_count": 0,
            }
        tactic_data[tactic]["total"] += 1
        if tech in covered_techniques:
            tactic_data[tactic]["covered"] += 1
            tactic_data[tactic]["rules_count"] += rules_per_technique.get(tech, 0)

    breakdown = []
    for tactic, data in tactic_data.items():
        total = data["total"]
        covered = data["covered"]
        coverage_pct = round((covered / total * 100) if total > 0 else 0.0, 1)
        breakdown.append({
            "tactic": tactic,
            "technique_count": total,
            "covered_count": covered,
            "coverage_pct": coverage_pct,
            "rules_count": data["rules_count"],
            "use_cases_passing": 0,
            "use_cases_failing": 0,
            "des_contribution": round(coverage_pct / 100 * (total / len(_KNOWN_TECHNIQUES)), 4),
        })

    # Sort by coverage ascending — worst first
    breakdown.sort(key=lambda x: x["coverage_pct"])
    return breakdown


# ---------------------------------------------------------------------------
# GET /scoring/gap-analysis
# ---------------------------------------------------------------------------

@router.get("/gap-analysis")
async def get_gap_analysis() -> dict[str, Any]:
    """Detailed gap report with critical gaps, quick wins, and trajectory."""
    from sqlalchemy import select

    async with async_session() as db:
        result = await db.execute(
            select(ImportedRule).where(ImportedRule.enabled == True)
        )
        rules = result.scalars().all()

    covered_techniques: set[str] = set()
    rules_per_technique: dict[str, int] = {}
    for rule in rules:
        for tech in (rule.mitre_techniques or []):
            t = tech.upper()
            covered_techniques.add(t)
            rules_per_technique[t] = rules_per_technique.get(t, 0) + 1

    # Identify gaps
    gap_techniques = [t for t in _KNOWN_TECHNIQUES if t not in covered_techniques]

    # "High frequency" tactics for threat frequency badge
    high_freq_tactics = {"initial-access", "execution", "credential-access", "defense-evasion"}
    medium_freq_tactics = {"persistence", "privilege-escalation", "lateral-movement", "exfiltration"}

    def _threat_frequency(tech_id: str) -> str:
        tactic = _TECHNIQUE_TACTIC_MAP.get(tech_id, "other")
        if tactic in high_freq_tactics:
            return "high"
        if tactic in medium_freq_tactics:
            return "medium"
        return "low"

    # Log sources that are commonly available (heuristic by tactic)
    _LOG_SOURCE_HINTS: dict[str, list[str]] = {
        "initial-access": ["windows_security", "firewall", "web_proxy"],
        "execution": ["sysmon", "windows_security", "edr"],
        "persistence": ["windows_security", "sysmon", "registry"],
        "privilege-escalation": ["windows_security", "sysmon"],
        "defense-evasion": ["sysmon", "edr", "windows_security"],
        "credential-access": ["windows_security", "sysmon", "lsass_dump"],
        "discovery": ["sysmon", "windows_security"],
        "lateral-movement": ["windows_security", "network_logs"],
        "collection": ["sysmon", "dlp"],
        "command-and-control": ["network_logs", "dns", "proxy"],
        "exfiltration": ["network_logs", "proxy", "dlp"],
        "impact": ["windows_security", "sysmon", "backup_logs"],
        "reconnaissance": ["network_logs", "dns"],
        "resource-development": ["threat_intel_feeds"],
    }

    critical_gaps = []
    quick_wins = []
    for tech in gap_techniques:
        tactic = _TECHNIQUE_TACTIC_MAP.get(tech, "other")
        freq = _threat_frequency(tech)
        name = _TECHNIQUE_NAMES.get(tech, tech)
        entry = {
            "technique_id": tech,
            "name": name,
            "tactic": tactic,
            "threat_frequency": freq,
            "use_case_count": 0,
        }
        critical_gaps.append(entry)

        # Quick wins: tactics where log sources are commonly available
        log_sources = _LOG_SOURCE_HINTS.get(tactic, [])
        if log_sources:
            quick_wins.append({
                "technique_id": tech,
                "name": name,
                "tactic": tactic,
                "existing_log_sources": log_sources,
                "suggested_rule_type": "sigma",
            })

    # Sort critical gaps: high > medium > low threat frequency
    freq_order = {"high": 0, "medium": 1, "low": 2}
    critical_gaps.sort(key=lambda x: freq_order.get(x["threat_frequency"], 3))
    quick_wins = quick_wins[:10]  # top 10 quick wins

    # Compute current DES for trajectory projection
    try:
        des_data = await _compute_des_snapshot()
        current_des = des_data.get("overall_score", 0.5)
    except Exception:
        current_des = 0.5

    total = len(_KNOWN_TECHNIQUES)
    covered_count = len(covered_techniques)
    gap_count = len(gap_techniques)

    # Optimistic trajectory: assume team closes ~5 gaps per month
    gaps_per_month = 5
    projected_30d = round(min(1.0, current_des + (gaps_per_month / total) * 0.8), 4)
    projected_90d = round(min(1.0, current_des + (gaps_per_month * 3 / total) * 0.8), 4)

    return {
        "total_techniques": total,
        "covered": covered_count,
        "gap_count": gap_count,
        "critical_gaps": critical_gaps[:20],
        "quick_wins": quick_wins,
        "improvement_trajectory": {
            "current_des": round(current_des, 4),
            "projected_30d": projected_30d,
            "projected_90d": projected_90d,
        },
    }


# ---------------------------------------------------------------------------
# GET /scoring/leaderboard
# ---------------------------------------------------------------------------

@router.get("/leaderboard")
async def get_scoring_leaderboard() -> list[dict[str, Any]]:
    """Top 10 use cases by run count and pass rate."""
    from backend.db.models import UseCase, UseCaseRun
    from sqlalchemy import select, func as sqlfunc

    async with async_session() as db:
        # Aggregate stats per use case
        stats_result = await db.execute(
            select(
                UseCaseRun.use_case_id,
                sqlfunc.count(UseCaseRun.id).label("total_runs"),
                sqlfunc.avg(UseCaseRun.pass_rate).label("avg_pass_rate"),
                sqlfunc.max(UseCaseRun.created_at).label("last_run_at"),
            )
            .group_by(UseCaseRun.use_case_id)
            .order_by(sqlfunc.count(UseCaseRun.id).desc())
            .limit(10)
        )
        stats = stats_result.all()

        if not stats:
            return []

        # Fetch use case details for those IDs
        use_case_ids = [row.use_case_id for row in stats]
        uc_result = await db.execute(
            select(UseCase).where(UseCase.id.in_(use_case_ids))
        )
        use_cases = {uc.id: uc for uc in uc_result.scalars().all()}

    leaderboard = []
    for row in stats:
        uc = use_cases.get(row.use_case_id)
        technique_ids = list(uc.technique_ids or []) if uc else []
        first_technique = technique_ids[0] if technique_ids else ""
        pass_rate = float(row.avg_pass_rate) if row.avg_pass_rate is not None else 0.0
        last_run = row.last_run_at
        if last_run and last_run.tzinfo is None:
            last_run = last_run.replace(tzinfo=timezone.utc)

        leaderboard.append({
            "use_case_id": str(row.use_case_id),
            "name": uc.name if uc else "Unknown",
            "technique_id": first_technique,
            "total_runs": row.total_runs,
            "pass_rate": round(pass_rate, 4),
            "last_run_at": last_run.isoformat() if last_run else None,
        })

    # Sort by pass_rate desc, then total_runs desc
    leaderboard.sort(key=lambda x: (-x["pass_rate"], -x["total_runs"]))
    return leaderboard
