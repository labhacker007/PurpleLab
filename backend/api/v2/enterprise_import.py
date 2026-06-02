"""Enterprise data import API — JSON and CSV bulk import for CMDB, Product Registry,
Vulnerability Management, and CSPM.

Roles: admin and engineer only.

Endpoints:
  POST /import/{entity}          — import rows (JSON body or multipart CSV)
  GET  /import/template/{entity} — download CSV/JSON template with example rows
  GET  /import/schemas           — JSON schema for all entities
"""
from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import PlainTextResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import select

from backend.auth.dependencies import get_current_active_user, require_role
from backend.db import models
from backend.db.session import async_session

router = APIRouter(prefix="/import", tags=["enterprise-import"])

# ── Constants ─────────────────────────────────────────────────────────────────

ENTITY_TYPES = {
    "people", "hardware_assets", "cloud_accounts",
    "products", "vulnerabilities", "cspm_findings",
}

MAX_ROWS = 5_000  # per batch

# ── Response models ────────────────────────────────────────────────────────────

class ImportError(BaseModel):
    row: int
    field: str
    message: str

class ImportResult(BaseModel):
    entity: str
    total_rows: int
    imported: int
    updated: int
    skipped: int
    errors: list[ImportError]

# ── Helper utilities ──────────────────────────────────────────────────────────

def _parse_date(val: str | None) -> Optional[datetime]:
    if not val:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%d/%m/%Y", "%m/%d/%Y"):
        try:
            return datetime.strptime(val.strip(), fmt)
        except ValueError:
            continue
    return None

def _parse_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return bool(val)
    if isinstance(val, str):
        return val.strip().lower() in ("true", "yes", "1", "on")
    return False

def _parse_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val)
    except (TypeError, ValueError):
        return default

def _parse_json_field(val: Any) -> Any:
    if val is None or val == "":
        return []
    if isinstance(val, (list, dict)):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except json.JSONDecodeError:
            # Comma-separated string → list
            return [x.strip() for x in val.split(",") if x.strip()]
    return []

def _uid() -> uuid.UUID:
    return uuid.uuid4()

def _now() -> datetime:
    return datetime.utcnow()

async def _parse_body(
    rows_json: Optional[str],
    file: Optional[UploadFile],
) -> tuple[list[dict], str]:
    """Return (rows, format) from either JSON body or uploaded file."""
    if file is not None:
        content = (await file.read()).decode("utf-8-sig", errors="replace")
        if file.filename and file.filename.lower().endswith(".json"):
            try:
                data = json.loads(content)
                rows = data if isinstance(data, list) else data.get("rows", [])
                return rows, "json"
            except json.JSONDecodeError as e:
                raise HTTPException(400, f"Invalid JSON file: {e}")
        # CSV
        reader = csv.DictReader(io.StringIO(content))
        rows = [dict(r) for r in reader]
        return rows, "csv"

    if rows_json:
        try:
            data = json.loads(rows_json)
            rows = data if isinstance(data, list) else data.get("rows", [])
            return rows, "json"
        except json.JSONDecodeError as e:
            raise HTTPException(400, f"Invalid JSON: {e}")

    raise HTTPException(400, "Provide either a JSON body (rows=[...]) or a CSV/JSON file upload")


# ── Import handlers ────────────────────────────────────────────────────────────

async def _import_people(rows: list[dict]) -> ImportResult:
    imported = updated = skipped = 0
    errors: list[ImportError] = []

    async with async_session() as session:
        for i, row in enumerate(rows, 1):
            emp_id = (row.get("employee_id") or "").strip()
            email = (row.get("email") or "").strip()
            first = (row.get("first_name") or "").strip()
            last = (row.get("last_name") or "").strip()

            if not emp_id:
                errors.append(ImportError(row=i, field="employee_id", message="Required"))
                skipped += 1; continue
            if not email:
                errors.append(ImportError(row=i, field="email", message="Required"))
                skipped += 1; continue
            if not first or not last:
                errors.append(ImportError(row=i, field="first_name/last_name", message="Required"))
                skipped += 1; continue

            # Lookup manager by email if provided
            mgr_id: Optional[uuid.UUID] = None
            mgr_email = (row.get("manager_email") or "").strip()
            if mgr_email:
                res = await session.execute(
                    select(models.CMDBPerson).where(models.CMDBPerson.email == mgr_email)
                )
                mgr = res.scalar_one_or_none()
                if mgr:
                    mgr_id = mgr.id

            existing = (await session.execute(
                select(models.CMDBPerson).where(models.CMDBPerson.employee_id == emp_id)
            )).scalar_one_or_none()

            data = dict(
                employee_id=emp_id,
                first_name=first,
                last_name=last,
                email=email,
                phone=(row.get("phone") or "").strip() or None,
                department=(row.get("department") or "").strip() or None,
                title=(row.get("title") or "").strip() or None,
                employment_type=(row.get("employment_type") or "employee").strip(),
                location=(row.get("location") or "").strip() or None,
                status=(row.get("status") or "active").strip(),
                manager_id=mgr_id,
                hire_date=_parse_date(row.get("hire_date")),
                updated_at=_now(),
            )

            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
                updated += 1
            else:
                session.add(models.CMDBPerson(id=_uid(), created_at=_now(), **data))
                imported += 1

        await session.commit()

    return ImportResult(entity="people", total_rows=len(rows),
                        imported=imported, updated=updated, skipped=skipped, errors=errors)


async def _import_hardware_assets(rows: list[dict]) -> ImportResult:
    imported = updated = skipped = 0
    errors: list[ImportError] = []

    async with async_session() as session:
        for i, row in enumerate(rows, 1):
            tag = (row.get("asset_tag") or "").strip()
            atype = (row.get("asset_type") or "").strip()
            if not tag:
                errors.append(ImportError(row=i, field="asset_tag", message="Required"))
                skipped += 1; continue
            if atype not in ("laptop", "desktop", "server", "mobile", "tablet", "network", ""):
                errors.append(ImportError(row=i, field="asset_type",
                              message=f"Unknown type '{atype}'"))
                skipped += 1; continue

            assigned_to_id: Optional[uuid.UUID] = None
            assigned_email = (row.get("assigned_to_email") or "").strip()
            if assigned_email:
                res = await session.execute(
                    select(models.CMDBPerson).where(models.CMDBPerson.email == assigned_email)
                )
                person = res.scalar_one_or_none()
                if person:
                    assigned_to_id = person.id
                else:
                    errors.append(ImportError(row=i, field="assigned_to_email",
                                  message=f"Person '{assigned_email}' not found — skipping assignment"))

            existing = (await session.execute(
                select(models.CMDBHardwareAsset).where(models.CMDBHardwareAsset.asset_tag == tag)
            )).scalar_one_or_none()

            specs_raw = row.get("specs") or {}
            data = dict(
                asset_tag=tag,
                asset_type=atype or "laptop",
                make=(row.get("make") or "").strip() or None,
                model=(row.get("model") or "").strip() or None,
                serial_number=(row.get("serial_number") or "").strip() or None,
                os_type=(row.get("os_type") or "").strip() or None,
                os_version=(row.get("os_version") or "").strip() or None,
                status=(row.get("status") or "assigned").strip(),
                location=(row.get("location") or "").strip() or None,
                assigned_to_id=assigned_to_id,
                assigned_date=_parse_date(row.get("assigned_date")),
                purchase_date=_parse_date(row.get("purchase_date")),
                warranty_expires=_parse_date(row.get("warranty_expires")),
                specs=_parse_json_field(specs_raw) if isinstance(specs_raw, str) else (specs_raw or {}),
                tags=_parse_json_field(row.get("tags") or {}),
                notes=(row.get("notes") or "").strip() or None,
                updated_at=_now(),
            )

            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
                updated += 1
            else:
                session.add(models.CMDBHardwareAsset(id=_uid(), created_at=_now(), **data))
                imported += 1

        await session.commit()

    return ImportResult(entity="hardware_assets", total_rows=len(rows),
                        imported=imported, updated=updated, skipped=skipped, errors=errors)


async def _import_cloud_accounts(rows: list[dict]) -> ImportResult:
    imported = updated = skipped = 0
    errors: list[ImportError] = []

    async with async_session() as session:
        for i, row in enumerate(rows, 1):
            provider = (row.get("cloud_provider") or "").strip().lower()
            acct_id = (row.get("account_id") or "").strip()
            name = (row.get("account_name") or "").strip()

            if provider not in ("aws", "azure", "gcp"):
                errors.append(ImportError(row=i, field="cloud_provider",
                              message=f"Must be aws/azure/gcp, got '{provider}'"))
                skipped += 1; continue
            if not acct_id:
                errors.append(ImportError(row=i, field="account_id", message="Required"))
                skipped += 1; continue
            if not name:
                errors.append(ImportError(row=i, field="account_name", message="Required"))
                skipped += 1; continue

            owner_id: Optional[uuid.UUID] = None
            owner_email = (row.get("owner_email") or "").strip()
            if owner_email:
                res = await session.execute(
                    select(models.CMDBPerson).where(models.CMDBPerson.email == owner_email)
                )
                p = res.scalar_one_or_none()
                if p:
                    owner_id = p.id

            existing = (await session.execute(
                select(models.ProductCloudAccount).where(
                    models.ProductCloudAccount.cloud_provider == provider,
                    models.ProductCloudAccount.account_id == acct_id,
                )
            )).scalar_one_or_none()

            data = dict(
                cloud_provider=provider,
                account_id=acct_id,
                account_name=name,
                account_type=(row.get("account_type") or "production").strip(),
                environment=(row.get("environment") or "prod").strip(),
                region_primary=(row.get("region_primary") or "").strip() or None,
                regions=_parse_json_field(row.get("regions") or []),
                owner_id=owner_id,
                billing_email=(row.get("billing_email") or "").strip() or None,
                monthly_cost_usd=_parse_float(row.get("monthly_cost_usd"), 0.0),
                mfa_enabled=_parse_bool(row.get("mfa_enabled", True)),
                cloudtrail_enabled=_parse_bool(row.get("cloudtrail_enabled", True)),
                security_hub_enabled=_parse_bool(row.get("security_hub_enabled", False)),
                status=(row.get("status") or "active").strip(),
                tags=_parse_json_field(row.get("tags") or {}),
                updated_at=_now(),
            )

            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
                updated += 1
            else:
                session.add(models.ProductCloudAccount(id=_uid(), created_at=_now(), **data))
                imported += 1

        await session.commit()

    return ImportResult(entity="cloud_accounts", total_rows=len(rows),
                        imported=imported, updated=updated, skipped=skipped, errors=errors)


async def _import_products(rows: list[dict]) -> ImportResult:
    imported = updated = skipped = 0
    errors: list[ImportError] = []

    async with async_session() as session:
        # Build lookup caches
        people_cache: dict[str, uuid.UUID] = {}
        account_cache: dict[str, uuid.UUID] = {}

        for i, row in enumerate(rows, 1):
            name = (row.get("name") or "").strip()
            slug = (row.get("slug") or "").strip()
            if not name:
                errors.append(ImportError(row=i, field="name", message="Required"))
                skipped += 1; continue
            if not slug:
                slug = name.lower().replace(" ", "-").replace("/", "-")[:100]

            owner_id: Optional[uuid.UUID] = None
            lead_id: Optional[uuid.UUID] = None
            cloud_acct_id: Optional[uuid.UUID] = None

            for email_field, id_out in [("owner_email", "owner"), ("tech_lead_email", "lead")]:
                email = (row.get(email_field) or "").strip()
                if email:
                    if email not in people_cache:
                        res = await session.execute(
                            select(models.CMDBPerson).where(models.CMDBPerson.email == email)
                        )
                        p = res.scalar_one_or_none()
                        people_cache[email] = p.id if p else None
                    pid = people_cache.get(email)
                    if id_out == "owner":
                        owner_id = pid
                    else:
                        lead_id = pid

            cloud_ref = (row.get("cloud_account_ref") or "").strip()  # "aws:123456789012"
            if cloud_ref and ":" in cloud_ref:
                if cloud_ref not in account_cache:
                    provider, acct_native = cloud_ref.split(":", 1)
                    res = await session.execute(
                        select(models.ProductCloudAccount).where(
                            models.ProductCloudAccount.cloud_provider == provider,
                            models.ProductCloudAccount.account_id == acct_native,
                        )
                    )
                    a = res.scalar_one_or_none()
                    account_cache[cloud_ref] = a.id if a else None
                cloud_acct_id = account_cache.get(cloud_ref)

            existing = (await session.execute(
                select(models.ProductRegistryProduct).where(
                    models.ProductRegistryProduct.slug == slug
                )
            )).scalar_one_or_none()

            data = dict(
                name=name,
                slug=slug,
                product_type=(row.get("product_type") or "internal").strip(),
                category=(row.get("category") or "web_application").strip(),
                tier=(row.get("tier") or "tier2_important").strip(),
                description=(row.get("description") or "").strip() or None,
                owner_id=owner_id,
                tech_lead_id=lead_id,
                team=(row.get("team") or "").strip() or None,
                url_production=(row.get("url_production") or "").strip() or None,
                url_staging=(row.get("url_staging") or "").strip() or None,
                url_docs=(row.get("url_docs") or "").strip() or None,
                url_repo=(row.get("url_repo") or "").strip() or None,
                status=(row.get("status") or "active").strip(),
                data_classification=(row.get("data_classification") or "internal").strip(),
                pii_data=_parse_bool(row.get("pii_data", False)),
                phi_data=_parse_bool(row.get("phi_data", False)),
                pci_data=_parse_bool(row.get("pci_data", False)),
                compliance_frameworks=_parse_json_field(row.get("compliance_frameworks") or []),
                tech_stack=_parse_json_field(row.get("tech_stack") or []),
                deployment_model=(row.get("deployment_model") or "cloud").strip(),
                cloud_account_id=cloud_acct_id,
                server_names=_parse_json_field(row.get("server_names") or []),
                container_names=_parse_json_field(row.get("container_names") or []),
                k8s_namespace=(row.get("k8s_namespace") or "").strip() or None,
                database_types=_parse_json_field(row.get("database_types") or []),
                annual_cost_usd=_parse_float(row.get("annual_cost_usd"), 0.0),
                vendor_name=(row.get("vendor_name") or "").strip() or None,
                vendor_contract_expires=_parse_date(row.get("vendor_contract_expires")),
                sla_uptime_target=_parse_float(row.get("sla_uptime_target"), 99.9),
                on_call_slack_channel=(row.get("on_call_slack_channel") or "").strip() or None,
                updated_at=_now(),
            )

            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
                updated += 1
            else:
                session.add(models.ProductRegistryProduct(id=_uid(), created_at=_now(), **data))
                imported += 1

        await session.commit()

    return ImportResult(entity="products", total_rows=len(rows),
                        imported=imported, updated=updated, skipped=skipped, errors=errors)


async def _import_vulnerabilities(rows: list[dict]) -> ImportResult:
    imported = updated = skipped = 0
    errors: list[ImportError] = []

    async with async_session() as session:
        for i, row in enumerate(rows, 1):
            title = (row.get("title") or "").strip()
            if not title:
                errors.append(ImportError(row=i, field="title", message="Required"))
                skipped += 1; continue

            cve_id = (row.get("cve_id") or "").strip() or None
            severity = (row.get("severity") or "medium").strip().lower()
            if severity not in ("critical", "high", "medium", "low"):
                severity = "medium"

            existing = None
            if cve_id:
                existing = (await session.execute(
                    select(models.VMVulnerability).where(models.VMVulnerability.cve_id == cve_id)
                )).scalar_one_or_none()

            data = dict(
                cve_id=cve_id,
                title=title,
                description=(row.get("description") or "").strip() or None,
                cvss_score=_parse_float(row.get("cvss_score"), 0.0) or None,
                cvss_vector=(row.get("cvss_vector") or "").strip() or None,
                severity=severity,
                cwe_id=(row.get("cwe_id") or "").strip() or None,
                affected_component=(row.get("affected_component") or "").strip() or None,
                affected_versions=_parse_json_field(row.get("affected_versions") or []),
                fixed_version=(row.get("fixed_version") or "").strip() or None,
                epss_score=_parse_float(row.get("epss_score"), 0.0),
                cisa_kev=_parse_bool(row.get("cisa_kev", False)),
                exploit_public=_parse_bool(row.get("exploit_public", False)),
                exploit_type=(row.get("exploit_type") or "").strip() or None,
                attack_vector=(row.get("attack_vector") or "network").strip(),
                attack_complexity=(row.get("attack_complexity") or "low").strip(),
                references=_parse_json_field(row.get("references") or []),
                nvd_published_at=_parse_date(row.get("nvd_published_at")),
                updated_at=_now(),
            )

            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
                updated += 1
            else:
                session.add(models.VMVulnerability(id=_uid(), created_at=_now(), **data))
                imported += 1

        await session.commit()

    return ImportResult(entity="vulnerabilities", total_rows=len(rows),
                        imported=imported, updated=updated, skipped=skipped, errors=errors)


async def _import_cspm_findings(rows: list[dict]) -> ImportResult:
    imported = updated = skipped = 0
    errors: list[ImportError] = []

    async with async_session() as session:
        check_cache: dict[str, int] = {}
        account_cache: dict[str, uuid.UUID] = {}

        for i, row in enumerate(rows, 1):
            check_str = (row.get("check_id") or "").strip()
            resource_id = (row.get("resource_id") or "").strip()
            cloud_ref = (row.get("cloud_account_ref") or "").strip()  # "aws:123456789012"

            if not check_str:
                errors.append(ImportError(row=i, field="check_id", message="Required (e.g. CIS-AWS-1.1)"))
                skipped += 1; continue
            if not resource_id:
                errors.append(ImportError(row=i, field="resource_id", message="Required"))
                skipped += 1; continue
            if not cloud_ref:
                errors.append(ImportError(row=i, field="cloud_account_ref", message="Required (provider:account_id)"))
                skipped += 1; continue

            # Resolve check PK
            if check_str not in check_cache:
                res = await session.execute(
                    select(models.CSPMCheck).where(models.CSPMCheck.check_id == check_str)
                )
                c = res.scalar_one_or_none()
                check_cache[check_str] = c.id if c else None
            check_pk = check_cache.get(check_str)
            if not check_pk:
                errors.append(ImportError(row=i, field="check_id",
                              message=f"Check '{check_str}' not found in catalog"))
                skipped += 1; continue

            # Resolve cloud account UUID
            if cloud_ref not in account_cache:
                if ":" in cloud_ref:
                    provider, acct_native = cloud_ref.split(":", 1)
                    res = await session.execute(
                        select(models.ProductCloudAccount).where(
                            models.ProductCloudAccount.cloud_provider == provider,
                            models.ProductCloudAccount.account_id == acct_native,
                        )
                    )
                    a = res.scalar_one_or_none()
                    account_cache[cloud_ref] = a.id if a else None
                else:
                    account_cache[cloud_ref] = None
            acct_uuid = account_cache.get(cloud_ref)
            if not acct_uuid:
                errors.append(ImportError(row=i, field="cloud_account_ref",
                              message=f"Account '{cloud_ref}' not found"))
                skipped += 1; continue

            severity = (row.get("severity") or "medium").strip().lower()
            if severity not in ("critical", "high", "medium", "low"):
                severity = "medium"

            existing = (await session.execute(
                select(models.CSPMFinding).where(
                    models.CSPMFinding.check_id == check_pk,
                    models.CSPMFinding.cloud_account_id == acct_uuid,
                    models.CSPMFinding.resource_id == resource_id[:500],
                )
            )).scalar_one_or_none()

            now = _now()
            data = dict(
                check_id=check_pk,
                cloud_account_id=acct_uuid,
                resource_id=resource_id[:500],
                resource_type=(row.get("resource_type") or "").strip() or None,
                resource_name=(row.get("resource_name") or "").strip() or None,
                region=(row.get("region") or "").strip() or None,
                status=(row.get("status") or "open").strip(),
                severity=severity,
                title=(row.get("title") or "").strip() or None,
                description=(row.get("description") or "").strip() or None,
                evidence=_parse_json_field(row.get("evidence") or {}),
                remediation_effort=(row.get("remediation_effort") or "low").strip(),
                first_seen_at=_parse_date(row.get("first_seen_at")) or now,
                last_seen_at=_parse_date(row.get("last_seen_at")) or now,
                resolved_at=_parse_date(row.get("resolved_at")),
                suppressed_reason=(row.get("suppressed_reason") or "").strip() or None,
                updated_at=now,
            )

            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
                updated += 1
            else:
                session.add(models.CSPMFinding(id=_uid(), created_at=now, **data))
                imported += 1

        await session.commit()

    return ImportResult(entity="cspm_findings", total_rows=len(rows),
                        imported=imported, updated=updated, skipped=skipped, errors=errors)


# ── CSV / JSON templates ───────────────────────────────────────────────────────

_TEMPLATES: dict[str, dict] = {
    "people": {
        "headers": ["employee_id","first_name","last_name","email","phone","department","title",
                    "employment_type","location","status","hire_date","manager_email"],
        "example_rows": [
            ["EMP2001","Alice","Chen","alice.chen@corp.com","+1-415-555-0101","Engineering",
             "Senior Engineer","employee","San Francisco","active","2022-03-15","bob.smith@corp.com"],
            ["EMP2002","Bob","Smith","bob.smith@corp.com","+1-212-555-0102","Security",
             "Security Analyst","employee","New York","active","2021-07-01",""],
        ],
    },
    "hardware_assets": {
        "headers": ["asset_tag","asset_type","make","model","serial_number","os_type","os_version",
                    "status","location","assigned_to_email","purchase_date","warranty_expires","notes"],
        "example_rows": [
            ["AST-90001","laptop","Apple","MacBook Pro 16 M3","SN-ABC123","macOS 14 Sonoma","",
             "assigned","SF-Office","alice.chen@corp.com","2023-09-01","2026-09-01",""],
            ["AST-90002","server","Dell","PowerEdge R750","SN-DEF456","RHEL 9","9.2",
             "assigned","AWS-us-east-1","","2022-01-15","2027-01-15","Prod web cluster"],
        ],
    },
    "cloud_accounts": {
        "headers": ["cloud_provider","account_id","account_name","account_type","environment",
                    "region_primary","regions","monthly_cost_usd","owner_email","billing_email",
                    "mfa_enabled","cloudtrail_enabled","security_hub_enabled"],
        "example_rows": [
            ["aws","987654321098","AWS New Prod","production","prod","us-east-1",
             "us-east-1,us-west-2","25000","alice.chen@corp.com","billing@corp.com","true","true","false"],
            ["azure","f1a2b3c4-d5e6-7890-abcd-ef1234567890","Azure EU","production","prod",
             "westeurope","westeurope","18000","bob.smith@corp.com","billing@corp.com","true","true","false"],
        ],
    },
    "products": {
        "headers": ["name","slug","product_type","category","tier","data_classification","status",
                    "owner_email","tech_lead_email","cloud_account_ref","url_production",
                    "tech_stack","pii_data","pci_data","annual_cost_usd","vendor_name"],
        "example_rows": [
            ["Order Service","order-service","internal","microservice","tier1_critical","confidential",
             "active","alice.chen@corp.com","bob.smith@corp.com","aws:987654321098",
             "https://order-svc.corp.com","Python,FastAPI,PostgreSQL","true","false","0",""],
            ["ServiceNow ITSM","servicenow","vendor","saas","tier2_important","internal",
             "active","","","","https://corp.service-now.com","","false","false","120000","ServiceNow Inc."],
        ],
    },
    "vulnerabilities": {
        "headers": ["cve_id","title","cvss_score","severity","epss_score","cisa_kev",
                    "exploit_public","affected_component","affected_versions","fixed_version",
                    "description","attack_vector","cwe_id"],
        "example_rows": [
            ["CVE-2025-12345","Example RCE in Acme Framework","9.8","critical","0.8512","true",
             "true","Acme Framework","< 3.2.1","3.2.1","Remote code execution via deserialization",
             "network","CWE-502"],
            ["CVE-2025-67890","SQL Injection in Corp DB Connector","7.5","high","0.3241","false",
             "false","Corp DB Connector","2.x < 2.8.0","2.8.0","SQL injection in login flow",
             "network","CWE-89"],
        ],
    },
    "cspm_findings": {
        "headers": ["check_id","cloud_account_ref","resource_id","resource_type","resource_name",
                    "region","status","severity","title","description","remediation_effort",
                    "first_seen_at","evidence"],
        "example_rows": [
            ["CIS-AWS-4.1","aws:987654321098",
             "arn:aws:ec2:us-east-1:987654321098:security-group/sg-0123456789abcdef",
             "Networking","sg-prod-web","us-east-1","open","critical","SSH open to internet",
             "Port 22 accessible from 0.0.0.0/0","low","2026-05-01",
             "{\"current_value\":\"0.0.0.0/0\",\"port\":22}"],
            ["CIS-AWS-1.2","aws:987654321098",
             "arn:aws:iam::987654321098:user/svc-deploy","IAM","svc-deploy","us-east-1",
             "open","high","IAM user without MFA","Console user lacks MFA","low","2026-04-15",""],
        ],
    },
}

def _rows_to_csv(headers: list[str], rows: list[list[str]]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(headers)
    w.writerows(rows)
    return buf.getvalue()

def _rows_to_json(headers: list[str], rows: list[list[str]]) -> str:
    objects = [dict(zip(headers, r)) for r in rows]
    return json.dumps({"rows": objects}, indent=2)


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/{entity}", response_model=ImportResult)
async def import_entity(
    entity: str,
    rows: Optional[str] = Form(None, description="JSON string: [{...}, ...]"),
    file: Optional[UploadFile] = File(None, description="CSV or JSON file"),
    current_user: models.User = Depends(require_role("admin", "engineer")),
):
    """Bulk import enterprise data. Send either:
    - multipart/form-data with `file` (CSV or JSON) field
    - multipart/form-data with `rows` (JSON string) field
    - application/json body is handled via rows= param

    Max 5,000 rows per call.
    """
    if entity not in ENTITY_TYPES:
        raise HTTPException(404, f"Unknown entity '{entity}'. Valid: {sorted(ENTITY_TYPES)}")

    row_list, fmt = await _parse_body(rows, file)

    if not row_list:
        raise HTTPException(400, "No rows found in import data")
    if len(row_list) > MAX_ROWS:
        raise HTTPException(400, f"Too many rows ({len(row_list)}). Max per batch: {MAX_ROWS}")

    handlers = {
        "people": _import_people,
        "hardware_assets": _import_hardware_assets,
        "cloud_accounts": _import_cloud_accounts,
        "products": _import_products,
        "vulnerabilities": _import_vulnerabilities,
        "cspm_findings": _import_cspm_findings,
    }
    return await handlers[entity](row_list)


@router.post("/json/{entity}", response_model=ImportResult)
async def import_entity_json(
    entity: str,
    body: dict,
    current_user: models.User = Depends(require_role("admin", "engineer")),
):
    """Import via plain JSON body: {"rows": [{...}, ...]}"""
    if entity not in ENTITY_TYPES:
        raise HTTPException(404, f"Unknown entity '{entity}'")

    row_list = body.get("rows", body) if isinstance(body, dict) else body
    if not isinstance(row_list, list):
        raise HTTPException(400, "Body must be {\"rows\": [...]} or a JSON array")
    if not row_list:
        raise HTTPException(400, "No rows provided")
    if len(row_list) > MAX_ROWS:
        raise HTTPException(400, f"Max {MAX_ROWS} rows per batch")

    handlers = {
        "people": _import_people,
        "hardware_assets": _import_hardware_assets,
        "cloud_accounts": _import_cloud_accounts,
        "products": _import_products,
        "vulnerabilities": _import_vulnerabilities,
        "cspm_findings": _import_cspm_findings,
    }
    return await handlers[entity](row_list)


@router.get("/template/{entity}")
async def get_template(
    entity: str,
    format: str = Query("csv", enum=["csv", "json"]),
    current_user: models.User = Depends(require_role("admin", "engineer")),
):
    """Download a CSV or JSON template for the given entity type."""
    if entity not in ENTITY_TYPES:
        raise HTTPException(404, f"Unknown entity '{entity}'")

    tpl = _TEMPLATES[entity]
    headers = tpl["headers"]
    rows = tpl["example_rows"]

    if format == "json":
        content = _rows_to_json(headers, rows)
        return PlainTextResponse(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{entity}_template.json"'},
        )
    else:
        content = _rows_to_csv(headers, rows)
        return PlainTextResponse(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{entity}_template.csv"'},
        )


@router.get("/schemas")
async def get_schemas(
    current_user: models.User = Depends(require_role("admin", "engineer")),
):
    """Return field schemas for all importable entities."""
    return {
        entity: {
            "fields": tpl["headers"],
            "example": dict(zip(tpl["headers"], tpl["example_rows"][0])),
            "endpoint": f"/api/v2/import/{entity}",
            "template_csv": f"/api/v2/import/template/{entity}?format=csv",
            "template_json": f"/api/v2/import/template/{entity}?format=json",
        }
        for entity, tpl in _TEMPLATES.items()
    }
