"""Cloud Security Posture Management (CSPM) REST API — v2.

Full CSPM findings lifecycle: browse findings across cloud accounts, triage
status transitions, posture scoring per framework and per account, and the
check catalog for policy-as-code reference.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc, and_, or_, case
from sqlalchemy.orm import selectinload

from backend.db.session import async_session
from backend.db.models import (
    CSPMFinding,
    CSPMCheck,
    ProductCloudAccount,
    ProductRegistryProduct,
)

router = APIRouter(prefix="/cspm", tags=["cspm"])


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class FindingStatusPatch(BaseModel):
    status: Optional[str] = Field(
        None,
        description="open | in_remediation | resolved | suppressed",
    )
    suppressed_reason: Optional[str] = Field(None, max_length=300)


# ---------------------------------------------------------------------------
# Serializers
# ---------------------------------------------------------------------------

def _finding_to_dict(
    f: CSPMFinding,
    check: Optional[CSPMCheck] = None,
    account: Optional[ProductCloudAccount] = None,
    product: Optional[ProductRegistryProduct] = None,
) -> dict[str, Any]:
    ch = check or f.check
    ac = account or f.cloud_account
    pr = product if product is not None else f.product
    return {
        "id": str(f.id),
        "check_id": f.check_id,
        "cloud_account_id": str(f.cloud_account_id),
        "product_id": str(f.product_id) if f.product_id else None,
        "resource_id": f.resource_id,
        "resource_type": f.resource_type,
        "resource_name": f.resource_name,
        "region": f.region,
        "status": f.status,
        "severity": f.severity,
        "title": f.title or (ch.title if ch else None),
        "description": f.description,
        "evidence": f.evidence,
        "remediation_effort": f.remediation_effort,
        "first_seen_at": f.first_seen_at.isoformat(),
        "last_seen_at": f.last_seen_at.isoformat(),
        "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
        "suppressed_reason": f.suppressed_reason,
        "created_at": f.created_at.isoformat(),
        "updated_at": f.updated_at.isoformat(),
        # Check context
        "check": {
            "check_id": ch.check_id,
            "title": ch.title,
            "section": ch.section,
            "framework": ch.framework,
            "cloud_provider": ch.cloud_provider,
            "severity": ch.severity,
            "automated": ch.automated,
            "remediation_steps": ch.remediation_steps,
        } if ch else None,
        # Account context
        "cloud_account": {
            "id": str(ac.id),
            "account_name": ac.account_name,
            "cloud_provider": ac.cloud_provider,
            "account_type": ac.account_type,
            "environment": ac.environment,
        } if ac else None,
        # Product context (nullable)
        "product": {
            "id": str(pr.id),
            "name": pr.name,
            "slug": pr.slug,
            "tier": pr.tier,
            "data_classification": pr.data_classification,
        } if pr else None,
    }


def _check_to_dict(c: CSPMCheck) -> dict[str, Any]:
    return {
        "id": c.id,
        "check_id": c.check_id,
        "framework": c.framework,
        "cloud_provider": c.cloud_provider,
        "section": c.section,
        "title": c.title,
        "description": c.description,
        "remediation_steps": c.remediation_steps,
        "severity": c.severity,
        "automated": c.automated,
        "created_at": c.created_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# GET /cspm/findings
# ---------------------------------------------------------------------------

@router.get("/findings")
async def list_cspm_findings(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    cloud_provider: Optional[str] = Query(None, description="aws|azure|gcp"),
    account_id: Optional[str] = Query(None, description="Cloud account UUID"),
    status: Optional[str] = Query(None, description="open|resolved|suppressed|in_remediation"),
    severity: Optional[str] = Query(None),
    section: Optional[str] = Query(None, description="IAM|Network|Storage|Encryption|Logging|Compute|Container|Database"),
    framework: Optional[str] = Query(None, description="CIS_AWS_v3|SOC2|NIST_CSF|PCI_DSS_v4"),
):
    """List CSPM findings across all cloud accounts with check + account context."""
    async with async_session() as session:
        base_q = (
            select(CSPMFinding)
            .options(
                selectinload(CSPMFinding.check),
                selectinload(CSPMFinding.cloud_account),
                selectinload(CSPMFinding.product),
            )
            .join(CSPMCheck, CSPMFinding.check_id == CSPMCheck.id)
            .join(ProductCloudAccount, CSPMFinding.cloud_account_id == ProductCloudAccount.id)
            .order_by(desc(CSPMFinding.last_seen_at))
        )

        if status:
            base_q = base_q.where(CSPMFinding.status == status)
        if severity:
            base_q = base_q.where(CSPMFinding.severity == severity)
        if cloud_provider:
            base_q = base_q.where(ProductCloudAccount.cloud_provider == cloud_provider)
        if account_id:
            try:
                aid = uuid.UUID(account_id)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid account_id UUID format.")
            base_q = base_q.where(CSPMFinding.cloud_account_id == aid)
        if section:
            base_q = base_q.where(CSPMCheck.section == section)
        if framework:
            base_q = base_q.where(CSPMCheck.framework == framework)

        total = (
            await session.execute(select(func.count()).select_from(base_q.subquery()))
        ).scalar() or 0

        result = await session.execute(base_q.offset(skip).limit(limit))
        findings = result.scalars().all()

        rows = [_finding_to_dict(f) for f in findings]

    return {"findings": rows, "total": total, "skip": skip, "limit": limit}


# ---------------------------------------------------------------------------
# GET /cspm/findings/{finding_id}
# ---------------------------------------------------------------------------

@router.get("/findings/{finding_id}")
async def get_cspm_finding(finding_id: str):
    """Full CSPM finding detail including check, evidence, and linked product."""
    try:
        fid = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid finding ID format.")

    async with async_session() as session:
        result = await session.execute(
            select(CSPMFinding)
            .options(
                selectinload(CSPMFinding.check),
                selectinload(CSPMFinding.cloud_account),
                selectinload(CSPMFinding.product),
            )
            .where(CSPMFinding.id == fid)
        )
        finding = result.scalar_one_or_none()
        if not finding:
            raise HTTPException(status_code=404, detail=f"CSPM finding '{finding_id}' not found.")

    return _finding_to_dict(finding)


# ---------------------------------------------------------------------------
# PATCH /cspm/findings/{finding_id}
# ---------------------------------------------------------------------------

@router.patch("/findings/{finding_id}")
async def patch_cspm_finding(finding_id: str, req: FindingStatusPatch):
    """Update finding status and/or suppression reason.

    Valid transitions:
      open → in_remediation → resolved
      open | in_remediation → suppressed
      suppressed → open (unsuppress)
    """
    try:
        fid = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid finding ID format.")

    valid_statuses = {"open", "in_remediation", "resolved", "suppressed"}
    if req.status and req.status not in valid_statuses:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status '{req.status}'. Must be one of: {', '.join(sorted(valid_statuses))}",
        )

    if req.status == "suppressed" and not req.suppressed_reason:
        raise HTTPException(
            status_code=422,
            detail="suppressed_reason is required when setting status to 'suppressed'.",
        )

    async with async_session() as session:
        result = await session.execute(
            select(CSPMFinding)
            .options(
                selectinload(CSPMFinding.check),
                selectinload(CSPMFinding.cloud_account),
                selectinload(CSPMFinding.product),
            )
            .where(CSPMFinding.id == fid)
        )
        finding = result.scalar_one_or_none()
        if not finding:
            raise HTTPException(status_code=404, detail=f"CSPM finding '{finding_id}' not found.")

        now = datetime.utcnow()

        if req.status is not None:
            if req.status == "resolved" and finding.status != "resolved":
                finding.resolved_at = now
            elif req.status != "resolved":
                finding.resolved_at = None

            if req.status != "suppressed":
                finding.suppressed_reason = None

            finding.status = req.status

        if req.suppressed_reason is not None:
            finding.suppressed_reason = req.suppressed_reason

        finding.updated_at = now
        await session.commit()
        await session.refresh(finding)

    return _finding_to_dict(finding)


# ---------------------------------------------------------------------------
# GET /cspm/summary
# ---------------------------------------------------------------------------

@router.get("/summary")
async def get_cspm_summary():
    """Org-wide CSPM posture snapshot across all cloud accounts and frameworks."""
    async with async_session() as session:
        open_statuses = ["open", "in_remediation"]

        # Total open
        total_open = (
            await session.execute(
                select(func.count(CSPMFinding.id)).where(
                    CSPMFinding.status.in_(open_statuses)
                )
            )
        ).scalar() or 0

        # By severity
        sev_rows = (
            await session.execute(
                select(
                    CSPMFinding.severity,
                    func.count(CSPMFinding.id).label("cnt"),
                )
                .where(CSPMFinding.status.in_(open_statuses))
                .group_by(CSPMFinding.severity)
            )
        ).all()
        by_severity = {row[0]: row[1] for row in sev_rows}

        # By section (from joined check)
        section_rows = (
            await session.execute(
                select(
                    func.coalesce(CSPMCheck.section, "Other").label("section"),
                    func.count(CSPMFinding.id).label("cnt"),
                )
                .join(CSPMCheck, CSPMFinding.check_id == CSPMCheck.id)
                .where(CSPMFinding.status.in_(open_statuses))
                .group_by(CSPMCheck.section)
            )
        ).all()
        by_section = {row[0]: row[1] for row in section_rows}

        # By cloud provider (from joined account)
        provider_rows = (
            await session.execute(
                select(
                    ProductCloudAccount.cloud_provider,
                    func.count(CSPMFinding.id).label("cnt"),
                )
                .join(ProductCloudAccount, CSPMFinding.cloud_account_id == ProductCloudAccount.id)
                .where(CSPMFinding.status.in_(open_statuses))
                .group_by(ProductCloudAccount.cloud_provider)
            )
        ).all()
        by_provider = {row[0]: row[1] for row in provider_rows}

        # By framework
        framework_rows = (
            await session.execute(
                select(
                    CSPMCheck.framework,
                    func.count(CSPMFinding.id).label("cnt"),
                )
                .join(CSPMCheck, CSPMFinding.check_id == CSPMCheck.id)
                .where(CSPMFinding.status.in_(open_statuses))
                .group_by(CSPMCheck.framework)
            )
        ).all()
        by_framework = {row[0]: row[1] for row in framework_rows}

        # Accounts with critical open findings
        critical_accounts_rows = (
            await session.execute(
                select(
                    ProductCloudAccount.id,
                    ProductCloudAccount.account_name,
                    ProductCloudAccount.cloud_provider,
                    ProductCloudAccount.account_type,
                    func.count(CSPMFinding.id).label("critical_count"),
                )
                .join(ProductCloudAccount, CSPMFinding.cloud_account_id == ProductCloudAccount.id)
                .where(
                    and_(
                        CSPMFinding.status.in_(open_statuses),
                        CSPMFinding.severity == "critical",
                    )
                )
                .group_by(
                    ProductCloudAccount.id,
                    ProductCloudAccount.account_name,
                    ProductCloudAccount.cloud_provider,
                    ProductCloudAccount.account_type,
                )
                .order_by(desc("critical_count"))
            )
        ).all()
        accounts_with_critical = [
            {
                "id": str(row[0]),
                "account_name": row[1],
                "cloud_provider": row[2],
                "account_type": row[3],
                "critical_finding_count": row[4],
            }
            for row in critical_accounts_rows
        ]

        # Compliance score by framework:
        # score = (total - open) / total * 100  per framework
        framework_total_rows = (
            await session.execute(
                select(
                    CSPMCheck.framework,
                    func.count(CSPMFinding.id).label("total"),
                    func.sum(
                        case(
                            (CSPMFinding.status.in_(["resolved", "suppressed"]), 1),
                            else_=0,
                        )
                    ).label("passed"),
                )
                .join(CSPMCheck, CSPMFinding.check_id == CSPMCheck.id)
                .group_by(CSPMCheck.framework)
            )
        ).all()

        # Use a simpler approach: count resolved/suppressed vs total per framework
        fw_totals_rows = (
            await session.execute(
                select(
                    CSPMCheck.framework,
                    func.count(CSPMFinding.id).label("total"),
                )
                .join(CSPMCheck, CSPMFinding.check_id == CSPMCheck.id)
                .group_by(CSPMCheck.framework)
            )
        ).all()
        fw_totals = {row[0]: row[1] for row in fw_totals_rows}

        fw_resolved_rows = (
            await session.execute(
                select(
                    CSPMCheck.framework,
                    func.count(CSPMFinding.id).label("resolved"),
                )
                .join(CSPMCheck, CSPMFinding.check_id == CSPMCheck.id)
                .where(CSPMFinding.status.in_(["resolved", "suppressed"]))
                .group_by(CSPMCheck.framework)
            )
        ).all()
        fw_resolved = {row[0]: row[1] for row in fw_resolved_rows}

        compliance_score_by_framework = {}
        for fw, total in fw_totals.items():
            if total > 0:
                resolved = fw_resolved.get(fw, 0)
                compliance_score_by_framework[fw] = round(resolved / total * 100, 1)
            else:
                compliance_score_by_framework[fw] = 100.0

        # Top 5 failing checks (most open findings)
        top_checks_rows = (
            await session.execute(
                select(
                    CSPMCheck.id,
                    CSPMCheck.check_id,
                    CSPMCheck.title,
                    CSPMCheck.section,
                    CSPMCheck.framework,
                    CSPMCheck.severity,
                    func.count(CSPMFinding.id).label("open_count"),
                )
                .join(CSPMFinding, CSPMFinding.check_id == CSPMCheck.id)
                .where(CSPMFinding.status.in_(open_statuses))
                .group_by(
                    CSPMCheck.id,
                    CSPMCheck.check_id,
                    CSPMCheck.title,
                    CSPMCheck.section,
                    CSPMCheck.framework,
                    CSPMCheck.severity,
                )
                .order_by(desc("open_count"))
                .limit(5)
            )
        ).all()
        top_5_failing_checks = [
            {
                "id": row[0],
                "check_id": row[1],
                "title": row[2],
                "section": row[3],
                "framework": row[4],
                "severity": row[5],
                "open_finding_count": row[6],
            }
            for row in top_checks_rows
        ]

    return {
        "total_open": total_open,
        "by_severity": by_severity,
        "by_section": by_section,
        "by_provider": by_provider,
        "by_framework": by_framework,
        "accounts_with_critical": accounts_with_critical,
        "compliance_score_by_framework": compliance_score_by_framework,
        "top_5_failing_checks": top_5_failing_checks,
        "generated_at": datetime.utcnow().isoformat(),
    }


# ---------------------------------------------------------------------------
# GET /cspm/account/{account_id}
# ---------------------------------------------------------------------------

@router.get("/account/{account_id}")
async def get_account_posture(
    account_id: str,
    status: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """All CSPM findings for a specific cloud account with posture scoring."""
    try:
        aid = uuid.UUID(account_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid account_id UUID format.")

    async with async_session() as session:
        account_result = await session.execute(
            select(ProductCloudAccount).where(ProductCloudAccount.id == aid)
        )
        account = account_result.scalar_one_or_none()
        if not account:
            raise HTTPException(status_code=404, detail=f"Cloud account '{account_id}' not found.")

        account_summary = {
            "id": str(account.id),
            "account_name": account.account_name,
            "cloud_provider": account.cloud_provider,
            "account_type": account.account_type,
            "environment": account.environment,
            "region_primary": account.region_primary,
            "status": account.status,
        }

        # Base findings query for this account
        base_q = (
            select(CSPMFinding)
            .options(
                selectinload(CSPMFinding.check),
                selectinload(CSPMFinding.product),
            )
            .where(CSPMFinding.cloud_account_id == aid)
            .order_by(desc(CSPMFinding.last_seen_at))
        )
        if status:
            base_q = base_q.where(CSPMFinding.status == status)

        total = (
            await session.execute(select(func.count()).select_from(base_q.subquery()))
        ).scalar() or 0

        result = await session.execute(base_q.offset(skip).limit(limit))
        findings = result.scalars().all()

        rows = [_finding_to_dict(f, account=account) for f in findings]

        # Posture score: % of all findings for this account that are resolved or suppressed
        all_total_result = await session.execute(
            select(func.count(CSPMFinding.id)).where(CSPMFinding.cloud_account_id == aid)
        )
        all_total = all_total_result.scalar() or 0

        resolved_result = await session.execute(
            select(func.count(CSPMFinding.id)).where(
                and_(
                    CSPMFinding.cloud_account_id == aid,
                    CSPMFinding.status.in_(["resolved", "suppressed"]),
                )
            )
        )
        resolved_count = resolved_result.scalar() or 0

        posture_score = round(resolved_count / all_total * 100, 1) if all_total > 0 else 100.0

        # By section breakdown (open only)
        section_rows = (
            await session.execute(
                select(
                    func.coalesce(CSPMCheck.section, "Other").label("section"),
                    func.count(CSPMFinding.id).label("cnt"),
                )
                .join(CSPMCheck, CSPMFinding.check_id == CSPMCheck.id)
                .where(
                    and_(
                        CSPMFinding.cloud_account_id == aid,
                        CSPMFinding.status.in_(["open", "in_remediation"]),
                    )
                )
                .group_by(CSPMCheck.section)
            )
        ).all()
        by_section = {row[0]: row[1] for row in section_rows}

        # By severity breakdown (open only)
        sev_rows = (
            await session.execute(
                select(
                    CSPMFinding.severity,
                    func.count(CSPMFinding.id).label("cnt"),
                )
                .where(
                    and_(
                        CSPMFinding.cloud_account_id == aid,
                        CSPMFinding.status.in_(["open", "in_remediation"]),
                    )
                )
                .group_by(CSPMFinding.severity)
            )
        ).all()
        by_severity = {row[0]: row[1] for row in sev_rows}

    return {
        "account": account_summary,
        "posture_score_pct": posture_score,
        "total_findings": all_total,
        "resolved_count": resolved_count,
        "open_count": all_total - resolved_count,
        "by_section": by_section,
        "by_severity": by_severity,
        "findings": rows,
        "total": total,
        "skip": skip,
        "limit": limit,
    }


# ---------------------------------------------------------------------------
# GET /cspm/checks
# ---------------------------------------------------------------------------

@router.get("/checks")
async def list_cspm_checks(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    framework: Optional[str] = Query(None),
    section: Optional[str] = Query(None),
    cloud_provider: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    """Browse the CSPM check catalog with optional filters."""
    async with async_session() as session:
        base_q = (
            select(CSPMCheck)
            .order_by(CSPMCheck.framework, CSPMCheck.section, CSPMCheck.check_id)
        )

        if framework:
            base_q = base_q.where(CSPMCheck.framework == framework)
        if section:
            base_q = base_q.where(CSPMCheck.section == section)
        if cloud_provider:
            base_q = base_q.where(
                or_(
                    CSPMCheck.cloud_provider == cloud_provider,
                    CSPMCheck.cloud_provider.is_(None),
                )
            )
        if severity:
            base_q = base_q.where(CSPMCheck.severity == severity)

        total = (
            await session.execute(select(func.count()).select_from(base_q.subquery()))
        ).scalar() or 0

        result = await session.execute(base_q.offset(skip).limit(limit))
        checks = result.scalars().all()

    return {
        "checks": [_check_to_dict(c) for c in checks],
        "total": total,
        "skip": skip,
        "limit": limit,
    }
