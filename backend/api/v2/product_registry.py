"""Product Registry & Cloud Account REST API — v2.

Exposes the product catalogue (internal apps, SaaS, vendor on-prem),
cloud account inventory, and linked vulnerability / CSPM posture data.
All queries use async SQLAlchemy 2.0 style against asyncpg.
"""
from __future__ import annotations

import uuid
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import selectinload

from backend.db.session import async_session
from backend.db.models import (
    ProductRegistryProduct,
    ProductCloudAccount,
    CMDBPerson,
    VMAssetVulnerability,
    VMVulnerability,
    CSPMFinding,
)

router = APIRouter(prefix="/registry", tags=["product-registry"])


# ── Serialisation helpers ─────────────────────────────────────────────────────

def _product_list_row(
    p: ProductRegistryProduct,
    owner_name: Optional[str],
    tech_lead_name: Optional[str],
    open_vuln_count: int,
    open_cspm_count: int,
) -> dict[str, Any]:
    return {
        "id": str(p.id),
        "name": p.name,
        "slug": p.slug,
        "product_type": p.product_type,
        "category": p.category,
        "tier": p.tier,
        "description": p.description,
        "owner_id": str(p.owner_id) if p.owner_id else None,
        "owner_name": owner_name,
        "tech_lead_id": str(p.tech_lead_id) if p.tech_lead_id else None,
        "tech_lead_name": tech_lead_name,
        "team": p.team,
        "url_production": p.url_production,
        "url_staging": p.url_staging,
        "url_docs": p.url_docs,
        "url_repo": p.url_repo,
        "status": p.status,
        "data_classification": p.data_classification,
        "pii_data": p.pii_data,
        "phi_data": p.phi_data,
        "pci_data": p.pci_data,
        "compliance_frameworks": p.compliance_frameworks or [],
        "tech_stack": p.tech_stack or [],
        "deployment_model": p.deployment_model,
        "cloud_account_id": str(p.cloud_account_id) if p.cloud_account_id else None,
        "annual_cost_usd": p.annual_cost_usd,
        "vendor_name": p.vendor_name,
        "vendor_contract_expires": p.vendor_contract_expires.isoformat() if p.vendor_contract_expires else None,
        "sla_uptime_target": p.sla_uptime_target,
        "on_call_slack_channel": p.on_call_slack_channel,
        "incident_runbook_url": p.incident_runbook_url,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
        "open_vuln_count": open_vuln_count,
        "open_cspm_count": open_cspm_count,
    }


def _cloud_account_row(
    a: ProductCloudAccount,
    owner_name: Optional[str],
    product_count: int,
    open_cspm_count: int,
) -> dict[str, Any]:
    return {
        "id": str(a.id),
        "cloud_provider": a.cloud_provider,
        "account_id": a.account_id,
        "account_name": a.account_name,
        "account_type": a.account_type,
        "environment": a.environment,
        "region_primary": a.region_primary,
        "regions": a.regions or [],
        "owner_id": str(a.owner_id) if a.owner_id else None,
        "owner_name": owner_name,
        "technical_lead_id": str(a.technical_lead_id) if a.technical_lead_id else None,
        "billing_email": a.billing_email,
        "monthly_cost_usd": a.monthly_cost_usd,
        "tags": a.tags or {},
        "mfa_enabled": a.mfa_enabled,
        "cloudtrail_enabled": a.cloudtrail_enabled,
        "security_hub_enabled": a.security_hub_enabled,
        "status": a.status,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
        "product_count": product_count,
        "open_cspm_count": open_cspm_count,
    }


# ── GET /registry/products ────────────────────────────────────────────────────

@router.get("/products")
async def list_products(
    product_type: Optional[str] = Query(None, description="internal / vendor_saas / vendor_on_prem"),
    category: Optional[str] = Query(None, description="security / infrastructure / business / developer_tool / data / communication"),
    tier: Optional[str] = Query(None, description="tier1_critical / tier2_important / tier3_standard / tier4_low"),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None, description="Search by product name or slug (case-insensitive)"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> dict[str, Any]:
    """List products with optional filters. Includes owner/tech-lead names and open risk counts."""
    async with async_session() as session:
        filters = []
        if product_type:
            filters.append(ProductRegistryProduct.product_type == product_type)
        if category:
            filters.append(ProductRegistryProduct.category == category)
        if tier:
            filters.append(ProductRegistryProduct.tier == tier)
        if status:
            filters.append(ProductRegistryProduct.status == status)
        if search:
            term = f"%{search.lower()}%"
            filters.append(
                or_(
                    func.lower(ProductRegistryProduct.name).like(term),
                    func.lower(ProductRegistryProduct.slug).like(term),
                )
            )

        count_q = select(func.count()).select_from(ProductRegistryProduct)
        if filters:
            count_q = count_q.where(and_(*filters))
        total: int = (await session.execute(count_q)).scalar() or 0

        data_q = select(ProductRegistryProduct)
        if filters:
            data_q = data_q.where(and_(*filters))
        data_q = data_q.order_by(ProductRegistryProduct.tier, ProductRegistryProduct.name).offset(offset).limit(limit)
        products = (await session.execute(data_q)).scalars().all()

        if not products:
            return {"products": [], "total": total, "offset": offset, "limit": limit}

        product_ids = [p.id for p in products]
        all_person_ids = list(
            {pid for p in products for pid in [p.owner_id, p.tech_lead_id] if pid}
        )

        # Resolve person names in one query
        person_names: dict[uuid.UUID, str] = {}
        if all_person_ids:
            pn_q = select(CMDBPerson.id, CMDBPerson.first_name, CMDBPerson.last_name).where(
                CMDBPerson.id.in_(all_person_ids)
            )
            for row in (await session.execute(pn_q)).all():
                person_names[row.id] = f"{row.first_name} {row.last_name}"

        # Open vuln counts per product
        vc_q = (
            select(VMAssetVulnerability.product_id, func.count(VMAssetVulnerability.id).label("cnt"))
            .where(
                and_(
                    VMAssetVulnerability.product_id.in_(product_ids),
                    VMAssetVulnerability.status == "open",
                )
            )
            .group_by(VMAssetVulnerability.product_id)
        )
        vuln_counts: dict[uuid.UUID, int] = {
            row.product_id: row.cnt for row in (await session.execute(vc_q)).all()
        }

        # Open CSPM finding counts per product
        cc_q = (
            select(CSPMFinding.product_id, func.count(CSPMFinding.id).label("cnt"))
            .where(
                and_(
                    CSPMFinding.product_id.in_(product_ids),
                    CSPMFinding.status == "open",
                )
            )
            .group_by(CSPMFinding.product_id)
        )
        cspm_counts: dict[uuid.UUID, int] = {
            row.product_id: row.cnt for row in (await session.execute(cc_q)).all()
        }

        rows = [
            _product_list_row(
                p,
                owner_name=person_names.get(p.owner_id) if p.owner_id else None,
                tech_lead_name=person_names.get(p.tech_lead_id) if p.tech_lead_id else None,
                open_vuln_count=vuln_counts.get(p.id, 0),
                open_cspm_count=cspm_counts.get(p.id, 0),
            )
            for p in products
        ]
        return {"products": rows, "total": total, "offset": offset, "limit": limit}


# ── GET /registry/products/registry/summary ───────────────────────────────────
# Note: placed BEFORE /{product_id} to avoid FastAPI route shadowing.

@router.get("/products/registry/summary")
async def product_registry_summary() -> dict[str, Any]:
    """Summary: product counts by type/category/tier/classification and total annual cost."""
    async with async_session() as session:
        total: int = (
            await session.execute(select(func.count()).select_from(ProductRegistryProduct))
        ).scalar() or 0

        # By type
        type_q = (
            select(ProductRegistryProduct.product_type, func.count(ProductRegistryProduct.id).label("cnt"))
            .group_by(ProductRegistryProduct.product_type)
        )
        by_type: dict[str, int] = {
            row.product_type: row.cnt for row in (await session.execute(type_q)).all()
        }

        # By category
        cat_q = (
            select(ProductRegistryProduct.category, func.count(ProductRegistryProduct.id).label("cnt"))
            .where(ProductRegistryProduct.category.isnot(None))
            .group_by(ProductRegistryProduct.category)
        )
        by_category: dict[str, int] = {
            row.category: row.cnt for row in (await session.execute(cat_q)).all()
        }

        # By tier
        tier_q = (
            select(ProductRegistryProduct.tier, func.count(ProductRegistryProduct.id).label("cnt"))
            .group_by(ProductRegistryProduct.tier)
        )
        by_tier: dict[str, int] = {
            row.tier: row.cnt for row in (await session.execute(tier_q)).all()
        }

        # By data classification
        cls_q = (
            select(ProductRegistryProduct.data_classification, func.count(ProductRegistryProduct.id).label("cnt"))
            .group_by(ProductRegistryProduct.data_classification)
        )
        by_classification: dict[str, int] = {
            row.data_classification: row.cnt for row in (await session.execute(cls_q)).all()
        }

        # Total annual cost
        cost_q = select(func.coalesce(func.sum(ProductRegistryProduct.annual_cost_usd), 0.0))
        total_annual_cost: float = (await session.execute(cost_q)).scalar() or 0.0

        return {
            "total_products": total,
            "by_type": by_type,
            "by_category": by_category,
            "by_tier": by_tier,
            "by_classification": by_classification,
            "total_annual_cost": round(total_annual_cost, 2),
        }


# ── GET /registry/products/{product_id} ──────────────────────────────────────

@router.get("/products/{product_id}")
async def get_product(product_id: uuid.UUID) -> dict[str, Any]:
    """Full product detail with cloud account, owner contacts, open vulns, and CSPM breakdown."""
    async with async_session() as session:
        q = (
            select(ProductRegistryProduct)
            .options(selectinload(ProductRegistryProduct.cloud_account))
            .where(ProductRegistryProduct.id == product_id)
        )
        product: Optional[ProductRegistryProduct] = (await session.execute(q)).scalar_one_or_none()
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")

        # Resolve owner and tech lead
        owner_data: Optional[dict] = None
        tech_lead_data: Optional[dict] = None
        person_ids_needed = [pid for pid in [product.owner_id, product.tech_lead_id] if pid]
        if person_ids_needed:
            pq = select(CMDBPerson).where(CMDBPerson.id.in_(person_ids_needed))
            persons = {p.id: p for p in (await session.execute(pq)).scalars().all()}
            if product.owner_id and product.owner_id in persons:
                o = persons[product.owner_id]
                owner_data = {
                    "id": str(o.id),
                    "name": f"{o.first_name} {o.last_name}",
                    "email": o.email,
                    "title": o.title,
                }
            if product.tech_lead_id and product.tech_lead_id in persons:
                tl = persons[product.tech_lead_id]
                tech_lead_data = {
                    "id": str(tl.id),
                    "name": f"{tl.first_name} {tl.last_name}",
                    "email": tl.email,
                    "title": tl.title,
                }

        # Cloud account
        cloud_account_data: Optional[dict] = None
        if product.cloud_account:
            ca = product.cloud_account
            cloud_account_data = {
                "id": str(ca.id),
                "account_name": ca.account_name,
                "account_id": ca.account_id,
                "cloud_provider": ca.cloud_provider,
                "environment": ca.environment,
            }

        # Open vulnerabilities (with CVE detail via join)
        vq = (
            select(VMAssetVulnerability, VMVulnerability)
            .join(VMVulnerability, VMVulnerability.id == VMAssetVulnerability.vuln_id)
            .where(
                and_(
                    VMAssetVulnerability.product_id == product.id,
                    VMAssetVulnerability.status == "open",
                )
            )
            .order_by(VMVulnerability.cvss_score.desc().nullslast())
        )
        vuln_rows = (await session.execute(vq)).all()
        open_vulns = [
            {
                "asset_vuln_id": str(av.id),
                "cve_id": v.cve_id,
                "title": v.title,
                "severity": av.severity_override or v.severity,
                "cvss_score": v.cvss_score,
                "status": av.status,
                "discovered_at": av.discovered_at.isoformat() if av.discovered_at else None,
                "remediation_due_date": av.remediation_due_date.isoformat() if av.remediation_due_date else None,
            }
            for av, v in vuln_rows
        ]

        # CSPM findings count by severity
        cspm_sev_q = (
            select(CSPMFinding.severity, func.count(CSPMFinding.id).label("cnt"))
            .where(
                and_(
                    CSPMFinding.product_id == product.id,
                    CSPMFinding.status == "open",
                )
            )
            .group_by(CSPMFinding.severity)
        )
        cspm_by_severity: dict[str, int] = {
            row.severity: row.cnt for row in (await session.execute(cspm_sev_q)).all()
        }

        return {
            "id": str(product.id),
            "name": product.name,
            "slug": product.slug,
            "product_type": product.product_type,
            "category": product.category,
            "tier": product.tier,
            "description": product.description,
            "owner": owner_data,
            "tech_lead": tech_lead_data,
            "team": product.team,
            "url_production": product.url_production,
            "url_staging": product.url_staging,
            "url_docs": product.url_docs,
            "url_repo": product.url_repo,
            "status": product.status,
            "data_classification": product.data_classification,
            "pii_data": product.pii_data,
            "phi_data": product.phi_data,
            "pci_data": product.pci_data,
            "compliance_frameworks": product.compliance_frameworks or [],
            "tech_stack": product.tech_stack or [],
            "deployment_model": product.deployment_model,
            "cloud_account": cloud_account_data,
            "server_names": product.server_names or [],
            "container_names": product.container_names or [],
            "k8s_namespace": product.k8s_namespace,
            "database_types": product.database_types or [],
            "annual_cost_usd": product.annual_cost_usd,
            "vendor_name": product.vendor_name,
            "vendor_contract_expires": product.vendor_contract_expires.isoformat() if product.vendor_contract_expires else None,
            "sla_uptime_target": product.sla_uptime_target,
            "on_call_slack_channel": product.on_call_slack_channel,
            "incident_runbook_url": product.incident_runbook_url,
            "created_at": product.created_at.isoformat() if product.created_at else None,
            "updated_at": product.updated_at.isoformat() if product.updated_at else None,
            "open_vulns": open_vulns,
            "open_vuln_count": len(open_vulns),
            "cspm_findings_by_severity": cspm_by_severity,
            "open_cspm_count": sum(cspm_by_severity.values()),
        }


# ── GET /registry/cloud-accounts/summary ─────────────────────────────────────
# Placed BEFORE /{account_id} to avoid FastAPI route shadowing.

@router.get("/cloud-accounts/summary")
async def cloud_accounts_summary() -> dict[str, Any]:
    """Cloud account summary: counts by provider, total monthly cost, security posture."""
    async with async_session() as session:
        total: int = (
            await session.execute(select(func.count()).select_from(ProductCloudAccount))
        ).scalar() or 0

        # By provider
        prov_q = (
            select(ProductCloudAccount.cloud_provider, func.count(ProductCloudAccount.id).label("cnt"))
            .group_by(ProductCloudAccount.cloud_provider)
        )
        by_provider: dict[str, int] = {
            row.cloud_provider: row.cnt for row in (await session.execute(prov_q)).all()
        }

        # Total monthly cost
        cost_q = select(func.coalesce(func.sum(ProductCloudAccount.monthly_cost_usd), 0.0))
        total_monthly_cost: float = (await session.execute(cost_q)).scalar() or 0.0

        # Security posture: % of accounts with mfa/cloudtrail enabled
        if total > 0:
            mfa_q = select(func.count()).select_from(ProductCloudAccount).where(
                ProductCloudAccount.mfa_enabled.is_(True)
            )
            mfa_count: int = (await session.execute(mfa_q)).scalar() or 0

            ct_q = select(func.count()).select_from(ProductCloudAccount).where(
                ProductCloudAccount.cloudtrail_enabled.is_(True)
            )
            cloudtrail_count: int = (await session.execute(ct_q)).scalar() or 0

            mfa_pct = round(mfa_count / total * 100, 1)
            cloudtrail_pct = round(cloudtrail_count / total * 100, 1)
        else:
            mfa_pct = 0.0
            cloudtrail_pct = 0.0

        return {
            "total_accounts": total,
            "by_provider": by_provider,
            "total_monthly_cost_usd": round(total_monthly_cost, 2),
            "security_posture": {
                "mfa_enabled_pct": mfa_pct,
                "cloudtrail_enabled_pct": cloudtrail_pct,
            },
        }


# ── GET /registry/cloud-accounts ─────────────────────────────────────────────

@router.get("/cloud-accounts")
async def list_cloud_accounts(
    cloud_provider: Optional[str] = Query(None, description="aws / azure / gcp"),
    account_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> dict[str, Any]:
    """List cloud accounts with optional filters. Includes product count and open CSPM count."""
    async with async_session() as session:
        filters = []
        if cloud_provider:
            filters.append(ProductCloudAccount.cloud_provider == cloud_provider)
        if account_type:
            filters.append(ProductCloudAccount.account_type == account_type)
        if status:
            filters.append(ProductCloudAccount.status == status)

        count_q = select(func.count()).select_from(ProductCloudAccount)
        if filters:
            count_q = count_q.where(and_(*filters))
        total: int = (await session.execute(count_q)).scalar() or 0

        data_q = select(ProductCloudAccount)
        if filters:
            data_q = data_q.where(and_(*filters))
        data_q = data_q.order_by(ProductCloudAccount.cloud_provider, ProductCloudAccount.account_name).offset(offset).limit(limit)
        accounts = (await session.execute(data_q)).scalars().all()

        if not accounts:
            return {"accounts": [], "total": total, "offset": offset, "limit": limit}

        account_ids = [a.id for a in accounts]
        all_owner_ids = list({oid for a in accounts for oid in [a.owner_id, a.technical_lead_id] if oid})

        # Owner names
        person_names: dict[uuid.UUID, str] = {}
        if all_owner_ids:
            pn_q = select(CMDBPerson.id, CMDBPerson.first_name, CMDBPerson.last_name).where(
                CMDBPerson.id.in_(all_owner_ids)
            )
            for row in (await session.execute(pn_q)).all():
                person_names[row.id] = f"{row.first_name} {row.last_name}"

        # Product counts per account
        pc_q = (
            select(ProductRegistryProduct.cloud_account_id, func.count(ProductRegistryProduct.id).label("cnt"))
            .where(ProductRegistryProduct.cloud_account_id.in_(account_ids))
            .group_by(ProductRegistryProduct.cloud_account_id)
        )
        prod_counts: dict[uuid.UUID, int] = {
            row.cloud_account_id: row.cnt for row in (await session.execute(pc_q)).all()
        }

        # Open CSPM counts per account
        cspm_q = (
            select(CSPMFinding.cloud_account_id, func.count(CSPMFinding.id).label("cnt"))
            .where(
                and_(
                    CSPMFinding.cloud_account_id.in_(account_ids),
                    CSPMFinding.status == "open",
                )
            )
            .group_by(CSPMFinding.cloud_account_id)
        )
        cspm_counts: dict[uuid.UUID, int] = {
            row.cloud_account_id: row.cnt for row in (await session.execute(cspm_q)).all()
        }

        rows = [
            _cloud_account_row(
                a,
                owner_name=person_names.get(a.owner_id) if a.owner_id else None,
                product_count=prod_counts.get(a.id, 0),
                open_cspm_count=cspm_counts.get(a.id, 0),
            )
            for a in accounts
        ]
        return {"accounts": rows, "total": total, "offset": offset, "limit": limit}


# ── GET /registry/cloud-accounts/{account_id} ────────────────────────────────

@router.get("/cloud-accounts/{account_id}")
async def get_cloud_account(account_id: uuid.UUID) -> dict[str, Any]:
    """Full cloud account detail with products list and CSPM findings summary by severity."""
    async with async_session() as session:
        q = (
            select(ProductCloudAccount)
            .options(selectinload(ProductCloudAccount.products))
            .where(ProductCloudAccount.id == account_id)
        )
        account: Optional[ProductCloudAccount] = (await session.execute(q)).scalar_one_or_none()
        if not account:
            raise HTTPException(status_code=404, detail="Cloud account not found")

        # Resolve owner and technical lead
        owner_data: Optional[dict] = None
        tech_lead_data: Optional[dict] = None
        person_ids_needed = [pid for pid in [account.owner_id, account.technical_lead_id] if pid]
        if person_ids_needed:
            pq = select(CMDBPerson).where(CMDBPerson.id.in_(person_ids_needed))
            persons = {p.id: p for p in (await session.execute(pq)).scalars().all()}
            if account.owner_id and account.owner_id in persons:
                o = persons[account.owner_id]
                owner_data = {
                    "id": str(o.id),
                    "name": f"{o.first_name} {o.last_name}",
                    "email": o.email,
                    "title": o.title,
                }
            if account.technical_lead_id and account.technical_lead_id in persons:
                tl = persons[account.technical_lead_id]
                tech_lead_data = {
                    "id": str(tl.id),
                    "name": f"{tl.first_name} {tl.last_name}",
                    "email": tl.email,
                    "title": tl.title,
                }

        # Products attached to this account
        products_list = [
            {
                "id": str(p.id),
                "name": p.name,
                "slug": p.slug,
                "product_type": p.product_type,
                "category": p.category,
                "tier": p.tier,
                "status": p.status,
                "data_classification": p.data_classification,
            }
            for p in account.products
        ]

        # CSPM findings summary by severity (open only)
        cspm_sev_q = (
            select(CSPMFinding.severity, func.count(CSPMFinding.id).label("cnt"))
            .where(
                and_(
                    CSPMFinding.cloud_account_id == account.id,
                    CSPMFinding.status == "open",
                )
            )
            .group_by(CSPMFinding.severity)
        )
        cspm_by_severity: dict[str, int] = {
            row.severity: row.cnt for row in (await session.execute(cspm_sev_q)).all()
        }

        # Total CSPM findings (all statuses) for historical context
        cspm_total_q = (
            select(CSPMFinding.status, func.count(CSPMFinding.id).label("cnt"))
            .where(CSPMFinding.cloud_account_id == account.id)
            .group_by(CSPMFinding.status)
        )
        cspm_by_status: dict[str, int] = {
            row.status: row.cnt for row in (await session.execute(cspm_total_q)).all()
        }

        return {
            "id": str(account.id),
            "cloud_provider": account.cloud_provider,
            "account_id": account.account_id,
            "account_name": account.account_name,
            "account_type": account.account_type,
            "environment": account.environment,
            "region_primary": account.region_primary,
            "regions": account.regions or [],
            "owner": owner_data,
            "tech_lead": tech_lead_data,
            "billing_email": account.billing_email,
            "monthly_cost_usd": account.monthly_cost_usd,
            "tags": account.tags or {},
            "mfa_enabled": account.mfa_enabled,
            "cloudtrail_enabled": account.cloudtrail_enabled,
            "security_hub_enabled": account.security_hub_enabled,
            "status": account.status,
            "created_at": account.created_at.isoformat() if account.created_at else None,
            "updated_at": account.updated_at.isoformat() if account.updated_at else None,
            "products": products_list,
            "product_count": len(products_list),
            "cspm_findings_open_by_severity": cspm_by_severity,
            "cspm_findings_by_status": cspm_by_status,
            "open_cspm_count": sum(cspm_by_severity.values()),
        }
