"""Sigma rule library REST API.

Manages open-source Sigma rule repositories, the local rule library, and
deployment of rules to simulation sessions. Supports GitHub sync with
sha256 deduplication.
"""
from __future__ import annotations

import hashlib
import os
import uuid
from typing import Any

import httpx
import yaml
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from backend.auth.dependencies import require_role
from backend.db.models import SessionSigmaRule, SigmaLibraryRule, SigmaRuleSource, SimulationSession
from backend.db.session import async_session

router = APIRouter(prefix="/sigma-library", tags=["sigma-library"])


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class RuleCreateRequest(BaseModel):
    title: str = Field(..., max_length=500)
    rule_yaml: str
    level: str = Field("medium", description="critical|high|medium|low|informational")
    status: str = Field("stable", description="stable|experimental|deprecated")
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)


class DeployRulesRequest(BaseModel):
    rule_ids: list[uuid.UUID]


def _source_to_dict(s: SigmaRuleSource) -> dict[str, Any]:
    return {
        "id": s.id,
        "name": s.name,
        "github_url": s.github_url,
        "github_api_path": s.github_api_path,
        "description": s.description,
        "enabled": s.enabled,
        "last_synced_at": s.last_synced_at.isoformat() if s.last_synced_at else None,
        "rule_count": s.rule_count,
        "created_at": s.created_at.isoformat(),
    }


def _rule_to_dict(r: SigmaLibraryRule, include_yaml: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": str(r.id),
        "source_id": r.source_id,
        "title": r.title,
        "description": r.description,
        "status": r.status,
        "level": r.level,
        "category": r.category,
        "product": r.product,
        "service": r.service,
        "technique_ids": r.technique_ids,
        "tags": r.tags,
        "file_path": r.file_path,
        "added_by": r.added_by,
        "created_at": r.created_at.isoformat(),
        "updated_at": r.updated_at.isoformat(),
    }
    if include_yaml:
        out["rule_yaml"] = r.rule_yaml
    return out


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

@router.get("/sources")
async def list_sources() -> dict[str, Any]:
    """List all registered Sigma rule sources with their rule counts."""
    async with async_session() as session:
        result = await session.execute(
            select(SigmaRuleSource).order_by(SigmaRuleSource.name)
        )
        sources = result.scalars().all()

    return {"sources": [_source_to_dict(s) for s in sources], "total": len(sources)}


@router.put("/sources/{source_id}/toggle", dependencies=[Depends(require_role("admin", "engineer"))])
async def toggle_source(source_id: int) -> dict[str, Any]:
    """Enable or disable a Sigma rule source."""
    async with async_session() as session:
        source = await session.scalar(
            select(SigmaRuleSource).where(SigmaRuleSource.id == source_id)
        )
        if not source:
            raise HTTPException(status_code=404, detail=f"Source {source_id} not found")

        source.enabled = not source.enabled
        await session.commit()
        await session.refresh(source)

    return {"id": source_id, "enabled": source.enabled}


@router.post("/sources/{source_id}/sync", dependencies=[Depends(require_role("admin", "engineer"))])
async def sync_source(source_id: int) -> dict[str, Any]:
    """Trigger a GitHub sync for the given source.

    Fetches the rule file list from the GitHub API, downloads each .yml file,
    parses title/description/level/status/tags, and inserts new rules using
    sha256 to skip unchanged files.

    Requires GITHUB_TOKEN env var for higher rate limits (optional).
    """
    async with async_session() as session:
        source = await session.scalar(
            select(SigmaRuleSource).where(SigmaRuleSource.id == source_id)
        )
        if not source:
            raise HTTPException(status_code=404, detail=f"Source {source_id} not found")
        if not source.enabled:
            raise HTTPException(status_code=400, detail="Source is disabled — enable it before syncing")

        github_api_path = source.github_api_path
        github_token = os.environ.get("GITHUB_TOKEN")
        headers: dict[str, str] = {"Accept": "application/vnd.github.v3+json"}
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"

    synced = 0
    skipped = 0
    errors = 0

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            # Build proper GitHub API URL from stored repo/path format (e.g. "SigmaHQ/sigma/rules")
            # → https://api.github.com/repos/SigmaHQ/sigma/contents/rules
            parts = github_api_path.strip("/").split("/", 2)
            if len(parts) >= 2:
                owner, repo = parts[0], parts[1]
                sub_path = parts[2] if len(parts) > 2 else ""
                # Use recursive tree for large repos, contents API for small ones
                if sub_path:
                    tree_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{sub_path}"
                else:
                    tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
            else:
                tree_url = f"https://api.github.com/repos/{github_api_path}"
            resp = await client.get(tree_url, headers=headers)
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"GitHub API returned {resp.status_code}: {resp.text[:200]}",
                )
            tree_data = resp.json()

            # Support both /contents/ (list) and /git/trees/ (recursive tree) API paths
            if isinstance(tree_data, list):
                file_items = [
                    item for item in tree_data
                    if isinstance(item, dict)
                    and item.get("type") == "file"
                    and item.get("name", "").endswith(".yml")
                ]
            elif "tree" in tree_data:
                file_items = [
                    item for item in tree_data["tree"]
                    if item.get("type") == "blob"
                    and item.get("path", "").endswith(".yml")
                ]
                # Pre-build raw download URLs for tree items (no direct download_url)
                for item in file_items:
                    if not item.get("download_url"):
                        item["download_url"] = (
                            f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{item['path']}"
                        )
            else:
                file_items = []

            # Cap to 500 rules per sync to avoid rate limits
            file_items = file_items[:500]

            # Fetch and parse each rule file
            async with async_session() as session:
                for item in file_items:
                    raw_url = item.get("download_url") or ""
                    file_path = item.get("path") or item.get("name", "")

                    if not raw_url:
                        errors += 1
                        continue

                    try:
                        rule_resp = await client.get(raw_url, headers=headers)
                        if rule_resp.status_code != 200:
                            errors += 1
                            continue

                        rule_content = rule_resp.text
                        content_hash = hashlib.sha256(rule_content.encode()).hexdigest()

                        # Dedup check
                        existing = await session.scalar(
                            select(SigmaLibraryRule).where(SigmaLibraryRule.sha256 == content_hash)
                        )
                        if existing:
                            skipped += 1
                            continue

                        # Parse YAML front-matter
                        try:
                            parsed = yaml.safe_load(rule_content) or {}
                        except yaml.YAMLError:
                            errors += 1
                            continue

                        if not isinstance(parsed, dict):
                            errors += 1
                            continue

                        title = parsed.get("title") or file_path.split("/")[-1].replace(".yml", "")
                        description = str(parsed.get("description") or "")
                        level = str(parsed.get("level") or "medium").lower()
                        status = str(parsed.get("status") or "experimental").lower()
                        raw_tags = parsed.get("tags") or []
                        tags: list[str] = [str(t) for t in raw_tags] if isinstance(raw_tags, list) else []

                        # Extract MITRE technique IDs from tags (attack.tNNNN pattern)
                        technique_ids = [
                            t.split("attack.")[1].upper()
                            for t in tags
                            if t.lower().startswith("attack.t")
                        ]

                        logsource = parsed.get("logsource") or {}
                        category = logsource.get("category")
                        product = logsource.get("product")
                        service = logsource.get("service")

                        rule = SigmaLibraryRule(
                            source_id=source_id,
                            title=str(title)[:500],
                            description=description,
                            rule_yaml=rule_content,
                            status=status,
                            level=level,
                            category=str(category) if category else None,
                            product=str(product) if product else None,
                            service=str(service) if service else None,
                            technique_ids=technique_ids,
                            tags=tags,
                            file_path=file_path,
                            sha256=content_hash,
                        )
                        session.add(rule)
                        synced += 1

                    except Exception:
                        errors += 1
                        continue

                # Update source stats
                src = await session.scalar(
                    select(SigmaRuleSource).where(SigmaRuleSource.id == source_id)
                )
                if src:
                    from datetime import datetime
                    src.last_synced_at = datetime.utcnow()
                    count_result = await session.scalar(
                        select(func.count()).select_from(SigmaLibraryRule).where(SigmaLibraryRule.source_id == source_id)
                    )
                    src.rule_count = (count_result or 0) + synced

                await session.commit()

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"GitHub sync failed: {str(exc)[:300]}")

    return {"synced": synced, "skipped": skipped, "errors": errors}


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

@router.get("/rules")
async def list_rules(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    search: str | None = Query(None),
    level: str | None = Query(None),
    source_id: int | None = Query(None),
    technique: str | None = Query(None, description="Filter by MITRE technique ID (e.g. T1059)"),
) -> dict[str, Any]:
    """List sigma library rules with pagination and filters."""
    async with async_session() as session:
        q = select(SigmaLibraryRule)
        count_q = select(func.count()).select_from(SigmaLibraryRule)

        if search:
            pattern = f"%{search}%"
            q = q.where(SigmaLibraryRule.title.ilike(pattern))
            count_q = count_q.where(SigmaLibraryRule.title.ilike(pattern))
        if level:
            q = q.where(SigmaLibraryRule.level == level)
            count_q = count_q.where(SigmaLibraryRule.level == level)
        if source_id is not None:
            q = q.where(SigmaLibraryRule.source_id == source_id)
            count_q = count_q.where(SigmaLibraryRule.source_id == source_id)
        if technique:
            # JSONB contains check via cast
            from sqlalchemy import cast, Text
            tech_upper = technique.upper()
            q = q.where(cast(SigmaLibraryRule.technique_ids, Text).ilike(f"%{tech_upper}%"))
            count_q = count_q.where(cast(SigmaLibraryRule.technique_ids, Text).ilike(f"%{tech_upper}%"))

        total = await session.scalar(count_q) or 0
        offset = (page - 1) * page_size
        result = await session.execute(
            q.order_by(SigmaLibraryRule.created_at.desc()).offset(offset).limit(page_size)
        )
        rules = result.scalars().all()

    return {
        "rules": [_rule_to_dict(r) for r in rules],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.post("/rules", dependencies=[Depends(require_role("admin", "engineer"))])
async def create_rule(
    body: RuleCreateRequest,
    current_user: Any = Depends(require_role("admin", "engineer")),
) -> dict[str, Any]:
    """Manually add a Sigma rule to the library (admin/engineer only)."""
    content_hash = hashlib.sha256(body.rule_yaml.encode()).hexdigest()

    async with async_session() as session:
        existing = await session.scalar(
            select(SigmaLibraryRule).where(SigmaLibraryRule.sha256 == content_hash)
        )
        if existing:
            raise HTTPException(status_code=409, detail="An identical rule (same content hash) already exists")

        rule = SigmaLibraryRule(
            source_id=None,
            title=body.title,
            description=body.description,
            rule_yaml=body.rule_yaml,
            level=body.level,
            status=body.status,
            technique_ids=body.technique_ids,
            tags=body.tags,
            sha256=content_hash,
            added_by=current_user.email,
        )
        session.add(rule)
        await session.commit()
        await session.refresh(rule)

    return _rule_to_dict(rule, include_yaml=True)


@router.get("/rules/{rule_id}")
async def get_rule(rule_id: uuid.UUID) -> dict[str, Any]:
    """Get a single Sigma rule with full YAML content."""
    async with async_session() as session:
        rule = await session.scalar(
            select(SigmaLibraryRule).where(SigmaLibraryRule.id == rule_id)
        )
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    return _rule_to_dict(rule, include_yaml=True)


@router.delete("/rules/{rule_id}", dependencies=[Depends(require_role("admin", "engineer"))])
async def delete_rule(rule_id: uuid.UUID) -> dict[str, Any]:
    """Delete a Sigma library rule (admin/engineer only)."""
    async with async_session() as session:
        rule = await session.scalar(
            select(SigmaLibraryRule).where(SigmaLibraryRule.id == rule_id)
        )
        if not rule:
            raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

        await session.delete(rule)
        await session.commit()

    return {"status": "deleted", "id": str(rule_id)}


# ---------------------------------------------------------------------------
# Session rule deployment
# ---------------------------------------------------------------------------

@router.post("/sessions/{session_id}/deploy", dependencies=[Depends(require_role("admin", "engineer"))])
async def deploy_rules_to_session(
    session_id: uuid.UUID,
    body: DeployRulesRequest,
    current_user: Any = Depends(require_role("admin", "engineer")),
) -> dict[str, Any]:
    """Deploy Sigma rules to a simulation session (skips already-deployed rules)."""
    async with async_session() as db:
        sim_session = await db.scalar(
            select(SimulationSession).where(SimulationSession.id == session_id)
        )
        if not sim_session:
            raise HTTPException(status_code=404, detail=f"Simulation session {session_id} not found")

        deployed = 0
        skipped = 0
        not_found = 0

        for rule_id in body.rule_ids:
            rule = await db.scalar(
                select(SigmaLibraryRule).where(SigmaLibraryRule.id == rule_id)
            )
            if not rule:
                not_found += 1
                continue

            already = await db.scalar(
                select(SessionSigmaRule).where(
                    SessionSigmaRule.session_id == session_id,
                    SessionSigmaRule.sigma_rule_id == rule_id,
                )
            )
            if already:
                skipped += 1
                continue

            entry = SessionSigmaRule(
                session_id=session_id,
                sigma_rule_id=rule_id,
                deployed_by=current_user.email,
            )
            db.add(entry)
            deployed += 1

        await db.commit()

    return {
        "session_id": str(session_id),
        "deployed": deployed,
        "skipped": skipped,
        "not_found": not_found,
    }


@router.get("/sessions/{session_id}/rules")
async def list_session_rules(session_id: uuid.UUID) -> dict[str, Any]:
    """List all Sigma rules deployed to a simulation session."""
    async with async_session() as db:
        sim_session = await db.scalar(
            select(SimulationSession).where(SimulationSession.id == session_id)
        )
        if not sim_session:
            raise HTTPException(status_code=404, detail=f"Simulation session {session_id} not found")

        result = await db.execute(
            select(SessionSigmaRule)
            .where(SessionSigmaRule.session_id == session_id)
            .order_by(SessionSigmaRule.deployed_at.desc())
        )
        entries = result.scalars().all()

        # Resolve rule details
        rules_out = []
        for entry in entries:
            rule = await db.scalar(
                select(SigmaLibraryRule).where(SigmaLibraryRule.id == entry.sigma_rule_id)
            )
            row = {
                "session_rule_id": str(entry.id),
                "deployed_at": entry.deployed_at.isoformat(),
                "deployed_by": entry.deployed_by,
                "rule": _rule_to_dict(rule) if rule else {"id": str(entry.sigma_rule_id), "title": "[deleted]"},
            }
            rules_out.append(row)

    return {"session_id": str(session_id), "rules": rules_out, "total": len(rules_out)}


@router.delete(
    "/sessions/{session_id}/rules/{rule_id}",
    dependencies=[Depends(require_role("admin", "engineer"))],
)
async def remove_rule_from_session(session_id: uuid.UUID, rule_id: uuid.UUID) -> dict[str, Any]:
    """Remove a Sigma rule from a simulation session."""
    async with async_session() as db:
        entry = await db.scalar(
            select(SessionSigmaRule).where(
                SessionSigmaRule.session_id == session_id,
                SessionSigmaRule.sigma_rule_id == rule_id,
            )
        )
        if not entry:
            raise HTTPException(
                status_code=404,
                detail=f"Rule {rule_id} is not deployed to session {session_id}",
            )

        await db.delete(entry)
        await db.commit()

    return {"status": "removed", "session_id": str(session_id), "rule_id": str(rule_id)}
