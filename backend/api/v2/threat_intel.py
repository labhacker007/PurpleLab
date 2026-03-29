"""Threat intelligence endpoints for v2 API.

Provides access to threat actors, MITRE ATT&CK techniques,
coverage analysis, and research capabilities.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.dependencies import get_actor_service, get_db, get_mitre_service, get_threat_researcher

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ResearchRequest(BaseModel):
    name: str


class ResearchTopicRequest(BaseModel):
    query: str


class CreateActorRequest(BaseModel):
    name: str
    aliases: list[str] = []
    description: str = ""


# ---------------------------------------------------------------------------
# Actor endpoints
# ---------------------------------------------------------------------------

@router.get("/actors")
async def list_actors(
    search: str = Query("", description="Search query for filtering actors"),
    actor_svc=Depends(get_actor_service),
):
    """List known threat actors with optional search."""
    try:
        actors = await actor_svc.list_actors(search=search)
        return {"actors": actors, "total": len(actors)}
    except Exception as exc:
        logger.error("list_actors failed: %s", exc)
        return {"actors": [], "total": 0, "error": str(exc)}


@router.get("/actors/{actor_id}")
async def get_actor(
    actor_id: str,
    actor_svc=Depends(get_actor_service),
):
    """Get detailed threat actor profile."""
    actor = await actor_svc.get_actor(actor_id)
    if actor:
        return actor
    return {"id": actor_id, "status": "not_found"}


@router.post("/actors")
async def create_actor(
    req: CreateActorRequest,
    actor_svc=Depends(get_actor_service),
):
    """Create a new threat actor profile."""
    actor = await actor_svc.create_or_update_actor(req.model_dump())
    return actor


@router.post("/actors/research")
async def research_actor(
    req: ResearchRequest,
    actor_svc=Depends(get_actor_service),
):
    """Research a threat actor using MITRE ATT&CK and web sources."""
    try:
        result = await actor_svc.research_actor(req.name)
        return result
    except Exception as exc:
        logger.error("research_actor failed: %s", exc)
        return {"name": req.name, "status": "error", "error": str(exc)}


@router.get("/actors/{actor_id}/ttps")
async def get_actor_ttps(
    actor_id: str,
    actor_svc=Depends(get_actor_service),
):
    """Get TTPs for a specific threat actor."""
    ttps = await actor_svc.get_actor_ttps(actor_id)
    return {"actor_id": actor_id, "ttps": ttps, "total": len(ttps)}


# ---------------------------------------------------------------------------
# Technique endpoints
# ---------------------------------------------------------------------------

@router.get("/techniques")
async def list_techniques(
    tactic: str = Query("", description="Filter by tactic (e.g., 'execution')"),
    platform: str = Query("", description="Filter by platform (e.g., 'Windows')"),
    search: str = Query("", description="Search query"),
    mitre_svc=Depends(get_mitre_service),
):
    """List MITRE ATT&CK techniques with filtering."""
    try:
        if search:
            techniques = await mitre_svc.search_techniques(search)
        else:
            techniques = await mitre_svc.list_techniques(tactic=tactic, platform=platform)
        return {"techniques": techniques, "total": len(techniques)}
    except Exception as exc:
        logger.error("list_techniques failed: %s", exc)
        return {"techniques": [], "total": 0, "error": str(exc)}


@router.get("/techniques/{technique_id}")
async def get_technique(
    technique_id: str,
    mitre_svc=Depends(get_mitre_service),
):
    """Get detailed MITRE technique info."""
    technique = await mitre_svc.get_technique(technique_id)
    if technique:
        return technique
    return {"technique_id": technique_id, "status": "not_found"}


# ---------------------------------------------------------------------------
# Groups endpoint
# ---------------------------------------------------------------------------

@router.get("/groups")
async def list_groups(
    mitre_svc=Depends(get_mitre_service),
):
    """List all MITRE ATT&CK threat groups."""
    try:
        groups = await mitre_svc.get_all_groups()
        return {"groups": groups, "total": len(groups)}
    except Exception as exc:
        logger.error("list_groups failed: %s", exc)
        return {"groups": [], "total": 0, "error": str(exc)}


# ---------------------------------------------------------------------------
# Coverage endpoint
# ---------------------------------------------------------------------------

@router.get("/coverage")
async def get_coverage(
    technique_ids: str = Query("", description="Comma-separated technique IDs that are covered"),
    mitre_svc=Depends(get_mitre_service),
):
    """Get MITRE ATT&CK coverage matrix.

    Shows which techniques are covered by detection rules or other
    provided technique IDs.
    """
    try:
        ids = [t.strip() for t in technique_ids.split(",") if t.strip()] if technique_ids else None
        result = await mitre_svc.get_coverage_matrix(ids)
        return result
    except Exception as exc:
        logger.error("get_coverage failed: %s", exc)
        return {"coverage": {}, "total_techniques": 0, "covered": 0, "coverage_pct": 0.0, "error": str(exc)}


# ---------------------------------------------------------------------------
# Research endpoints
# ---------------------------------------------------------------------------

@router.post("/research/topic")
async def research_topic(
    req: ResearchTopicRequest,
    researcher=Depends(get_threat_researcher),
):
    """Research an arbitrary threat intelligence topic."""
    try:
        result = await researcher.research_topic(req.query)
        return result
    except Exception as exc:
        logger.error("research_topic failed: %s", exc)
        return {"query": req.query, "status": "error", "error": str(exc)}


@router.post("/research/technique/{technique_id}")
async def research_technique(
    technique_id: str,
    researcher=Depends(get_threat_researcher),
):
    """Deep research on a specific MITRE technique."""
    try:
        result = await researcher.research_technique(technique_id)
        return result
    except Exception as exc:
        logger.error("research_technique failed: %s", exc)
        return {"technique_id": technique_id, "status": "error", "error": str(exc)}


# ---------------------------------------------------------------------------
# MITRE navigator endpoints (db-backed)
# ---------------------------------------------------------------------------

# 14 canonical ATT&CK tactics in order
_TACTIC_REGISTRY = [
    {"id": "TA0043", "name": "Reconnaissance", "slug": "reconnaissance",
     "description": "The adversary is trying to gather information they can use to plan future operations."},
    {"id": "TA0042", "name": "Resource Development", "slug": "resource-development",
     "description": "The adversary is trying to establish resources they can use to support operations."},
    {"id": "TA0001", "name": "Initial Access", "slug": "initial-access",
     "description": "The adversary is trying to get into your network."},
    {"id": "TA0002", "name": "Execution", "slug": "execution",
     "description": "The adversary is trying to run malicious code."},
    {"id": "TA0003", "name": "Persistence", "slug": "persistence",
     "description": "The adversary is trying to maintain their foothold."},
    {"id": "TA0004", "name": "Privilege Escalation", "slug": "privilege-escalation",
     "description": "The adversary is trying to gain higher-level permissions."},
    {"id": "TA0005", "name": "Defense Evasion", "slug": "defense-evasion",
     "description": "The adversary is trying to avoid being detected."},
    {"id": "TA0006", "name": "Credential Access", "slug": "credential-access",
     "description": "The adversary is trying to steal account names and passwords."},
    {"id": "TA0007", "name": "Discovery", "slug": "discovery",
     "description": "The adversary is trying to figure out your environment."},
    {"id": "TA0008", "name": "Lateral Movement", "slug": "lateral-movement",
     "description": "The adversary is trying to move through your environment."},
    {"id": "TA0009", "name": "Collection", "slug": "collection",
     "description": "The adversary is trying to gather data of interest to their goal."},
    {"id": "TA0011", "name": "Command and Control", "slug": "command-and-control",
     "description": "The adversary is trying to communicate with compromised systems to control them."},
    {"id": "TA0010", "name": "Exfiltration", "slug": "exfiltration",
     "description": "The adversary is trying to steal data."},
    {"id": "TA0040", "name": "Impact", "slug": "impact",
     "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data."},
]

# Slug variants the MITRETechnique.tactic column might use
def _tactic_slug_variants(slug: str) -> list[str]:
    """Return slug + underscore variant for matching."""
    return [slug, slug.replace("-", "_")]


@router.get("/mitre/tactics")
async def list_mitre_tactics(
    db: AsyncSession = Depends(get_db),
):
    """List all 14 MITRE tactics with technique counts and coverage stats."""
    from backend.db.models import ImportedRule, MITRETechnique

    try:
        # Count techniques per tactic
        tactic_counts_result = await db.execute(
            select(MITRETechnique.tactic, func.count(MITRETechnique.id).label("cnt"))
            .group_by(MITRETechnique.tactic)
        )
        tactic_counts: dict[str, int] = {row.tactic: row.cnt for row in tactic_counts_result}

        # All technique IDs that have at least one matching detection rule
        all_techniques = await db.execute(select(MITRETechnique.technique_id, MITRETechnique.tactic))
        rows = all_techniques.fetchall()

        # Build a set of covered technique IDs from ImportedRule.mitre_techniques JSONB column
        rules_result = await db.execute(
            select(ImportedRule.mitre_techniques).where(ImportedRule.enabled == True)  # noqa: E712
        )
        covered_ids: set[str] = set()
        for (rule_techniques,) in rules_result:
            if isinstance(rule_techniques, list):
                for tid in rule_techniques:
                    if isinstance(tid, str):
                        covered_ids.add(tid.upper())

        # Count covered per tactic
        covered_per_tactic: dict[str, int] = {}
        for row in rows:
            if row.technique_id.upper() in covered_ids:
                covered_per_tactic[row.tactic] = covered_per_tactic.get(row.tactic, 0) + 1

        result = []
        for t in _TACTIC_REGISTRY:
            slug = t["slug"]
            # Match tactic counts using both slug variants
            count = 0
            covered = 0
            for variant in _tactic_slug_variants(slug):
                count += tactic_counts.get(variant, 0)
                covered += covered_per_tactic.get(variant, 0)
            # Also try the full name lowercased
            name_lower = t["name"].lower().replace(" ", "-")
            if name_lower != slug:
                count += tactic_counts.get(name_lower, 0)
                covered += covered_per_tactic.get(name_lower, 0)

            result.append({
                "id": t["id"],
                "name": t["name"],
                "slug": slug,
                "description": t["description"],
                "technique_count": count,
                "covered_count": covered,
                "coverage_pct": round((covered / count * 100) if count else 0, 1),
            })
        return {"tactics": result}
    except Exception as exc:
        logger.error("list_mitre_tactics failed: %s", exc)
        # Fallback: return registry with zeroed counts
        return {
            "tactics": [
                {**t, "technique_count": 0, "covered_count": 0, "coverage_pct": 0.0}
                for t in _TACTIC_REGISTRY
            ]
        }


@router.get("/mitre/techniques")
async def list_mitre_techniques(
    tactic_id: Optional[str] = Query(None, description="Filter by tactic slug or TA ID"),
    search: Optional[str] = Query(None, description="ilike filter on name/technique_id"),
    has_coverage: Optional[bool] = Query(None, description="Filter to techniques with detection rules"),
    limit: int = Query(200, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    """List MITRE techniques with optional filters and coverage annotations."""
    from backend.db.models import ImportedRule, MITRETechnique

    try:
        q = select(MITRETechnique)

        # Tactic filter — accept TA-ID or slug
        if tactic_id:
            tactic_slug = tactic_id
            for t in _TACTIC_REGISTRY:
                if t["id"] == tactic_id:
                    tactic_slug = t["slug"]
                    break
            variants = _tactic_slug_variants(tactic_slug)
            q = q.where(MITRETechnique.tactic.in_(variants))

        # Search filter
        if search:
            pattern = f"%{search}%"
            from sqlalchemy import or_
            q = q.where(
                or_(
                    MITRETechnique.name.ilike(pattern),
                    MITRETechnique.technique_id.ilike(pattern),
                )
            )

        q = q.order_by(MITRETechnique.technique_id).limit(limit)
        result = await db.execute(q)
        techniques = result.scalars().all()

        # Build coverage map
        rules_result = await db.execute(
            select(ImportedRule.mitre_techniques, ImportedRule.id).where(
                ImportedRule.enabled == True  # noqa: E712
            )
        )
        rule_count_by_technique: dict[str, int] = {}
        for (rule_techniques, _rule_id) in rules_result:
            if isinstance(rule_techniques, list):
                for tid in rule_techniques:
                    if isinstance(tid, str):
                        k = tid.upper()
                        rule_count_by_technique[k] = rule_count_by_technique.get(k, 0) + 1

        # Build use-case count map
        from backend.db.models import UseCase
        uc_result = await db.execute(
            select(UseCase.technique_ids).where(UseCase.is_active == True)  # noqa: E712
        )
        uc_count_by_technique: dict[str, int] = {}
        for (uc_techniques,) in uc_result:
            if isinstance(uc_techniques, list):
                for tid in uc_techniques:
                    if isinstance(tid, str):
                        k = tid.upper()
                        uc_count_by_technique[k] = uc_count_by_technique.get(k, 0) + 1

        items = []
        for tech in techniques:
            key = tech.technique_id.upper()
            detection_count = rule_count_by_technique.get(key, 0)
            use_case_count = uc_count_by_technique.get(key, 0)
            has_cov = detection_count > 0
            if has_coverage is not None and has_cov != has_coverage:
                continue
            items.append({
                "technique_id": tech.technique_id,
                "name": tech.name,
                "tactic": tech.tactic,
                "description": tech.description[:300] if tech.description else "",
                "platforms": tech.platforms or [],
                "detection_count": detection_count,
                "use_case_count": use_case_count,
                "has_coverage": has_cov,
                "is_subtechnique": "." in tech.technique_id,
            })

        return {"techniques": items, "total": len(items)}
    except Exception as exc:
        logger.error("list_mitre_techniques failed: %s", exc)
        return {"techniques": [], "total": 0, "error": str(exc)}


@router.get("/mitre/techniques/{technique_id}")
async def get_mitre_technique_detail(
    technique_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Full technique detail with linked rules and use cases."""
    from backend.db.models import ImportedRule, MITRETechnique, UseCase

    try:
        result = await db.execute(
            select(MITRETechnique).where(
                func.upper(MITRETechnique.technique_id) == technique_id.upper()
            )
        )
        tech = result.scalar_one_or_none()
        if not tech:
            return {"technique_id": technique_id, "status": "not_found"}

        # Related rules — mitre_techniques is a JSONB list of technique ID strings
        from sqlalchemy import cast
        from sqlalchemy.dialects.postgresql import JSONB
        rules_result = await db.execute(
            select(ImportedRule.id, ImportedRule.name, ImportedRule.severity, ImportedRule.language)
            .where(
                ImportedRule.mitre_techniques.cast(JSONB).contains(
                    [technique_id.upper()]
                )
            )
            .limit(50)
        )
        related_rules = [
            {"id": str(r.id), "name": r.name, "severity": r.severity, "language": r.language}
            for r in rules_result.fetchall()
        ]

        # Also try lowercase technique ID match (JSONB array contains check)
        if not related_rules:
            rules_result2 = await db.execute(
                select(ImportedRule.id, ImportedRule.name, ImportedRule.severity, ImportedRule.language)
                .where(
                    ImportedRule.mitre_techniques.cast(JSONB).contains(
                        [technique_id.lower()]
                    )
                )
                .limit(50)
            )
            related_rules = [
                {"id": str(r.id), "name": r.name, "severity": r.severity, "language": r.language}
                for r in rules_result2.fetchall()
            ]

        # Related use cases
        uc_result = await db.execute(
            select(UseCase.id, UseCase.name, UseCase.severity, UseCase.tactic)
            .where(
                UseCase.technique_ids.cast(JSONB).contains([technique_id.upper()])
            )
            .limit(50)
        )
        related_use_cases = [
            {"id": str(u.id), "name": u.name, "severity": u.severity, "tactic": u.tactic}
            for u in uc_result.fetchall()
        ]

        return {
            "technique_id": tech.technique_id,
            "name": tech.name,
            "tactic": tech.tactic,
            "description": tech.description,
            "platforms": tech.platforms or [],
            "data_sources": tech.data_sources or [],
            "detection_notes": tech.detection_guidance,
            "sub_techniques": [],  # populated from MITRE source if needed
            "related_rules": related_rules,
            "related_use_cases": related_use_cases,
            "detection_count": len(related_rules),
            "use_case_count": len(related_use_cases),
            "has_coverage": len(related_rules) > 0,
        }
    except Exception as exc:
        logger.error("get_mitre_technique_detail failed: %s", exc)
        return {"technique_id": technique_id, "status": "error", "error": str(exc)}


@router.get("/mitre/coverage-matrix")
async def get_mitre_coverage_matrix(
    db: AsyncSession = Depends(get_db),
):
    """Heatmap data: coverage level per technique per tactic.

    Returns coverage_level: 0 = none, 1 = partial (<2 rules), 2 = full (2+ rules).
    """
    from backend.db.models import ImportedRule, MITRETechnique

    try:
        # All techniques
        tech_result = await db.execute(
            select(MITRETechnique.technique_id, MITRETechnique.name, MITRETechnique.tactic)
            .order_by(MITRETechnique.tactic, MITRETechnique.technique_id)
        )
        all_techniques = tech_result.fetchall()

        # Coverage counts
        rules_result = await db.execute(
            select(ImportedRule.mitre_techniques).where(ImportedRule.enabled == True)  # noqa: E712
        )
        rule_count_by_technique: dict[str, int] = {}
        for (rule_techniques,) in rules_result:
            if isinstance(rule_techniques, list):
                for tid in rule_techniques:
                    if isinstance(tid, str):
                        k = tid.upper()
                        rule_count_by_technique[k] = rule_count_by_technique.get(k, 0) + 1

        # Group by tactic using registry order
        tactic_slugs_all: set[str] = set()
        for t in all_techniques:
            tactic_slugs_all.add(t.tactic)

        # Build tactic → techniques mapping in canonical order
        tactic_data: dict[str, list[dict]] = {}
        for row in all_techniques:
            tactic = row.tactic
            if tactic not in tactic_data:
                tactic_data[tactic] = []
            count = rule_count_by_technique.get(row.technique_id.upper(), 0)
            tactic_data[tactic].append({
                "technique_id": row.technique_id,
                "name": row.name,
                "detection_count": count,
                "coverage_level": 0 if count == 0 else (1 if count < 2 else 2),
            })

        # Build ordered matrix following registry
        matrix = []
        for t in _TACTIC_REGISTRY:
            techniques_for_tactic = []
            for variant in _tactic_slug_variants(t["slug"]):
                techniques_for_tactic.extend(tactic_data.get(variant, []))
            if not techniques_for_tactic:
                techniques_for_tactic = tactic_data.get(t["name"].lower().replace(" ", "-"), [])
            total = len(techniques_for_tactic)
            covered = sum(1 for x in techniques_for_tactic if x["coverage_level"] > 0)
            matrix.append({
                "tactic_id": t["id"],
                "tactic_name": t["name"],
                "tactic_slug": t["slug"],
                "techniques": techniques_for_tactic,
                "total": total,
                "covered": covered,
                "coverage_pct": round((covered / total * 100) if total else 0, 1),
            })

        total_techniques = sum(m["total"] for m in matrix)
        total_covered = sum(m["covered"] for m in matrix)
        return {
            "matrix": matrix,
            "total_techniques": total_techniques,
            "total_covered": total_covered,
            "overall_coverage_pct": round(
                (total_covered / total_techniques * 100) if total_techniques else 0, 1
            ),
        }
    except Exception as exc:
        logger.error("get_mitre_coverage_matrix failed: %s", exc)
        return {"matrix": [], "total_techniques": 0, "total_covered": 0, "overall_coverage_pct": 0.0, "error": str(exc)}
