"""Environment CRUD endpoints — v2 API.

Environments represent a simulated SOC setup: SIEM platform + log sources + config.
Fully persisted to PostgreSQL via SQLAlchemy async.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc

from backend.db.session import async_session
from backend.db.models import Environment, SIEMConnection, TestRun

router = APIRouter(prefix="/environments", tags=["environments"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class EnvironmentCreateRequest(BaseModel):
    name: str = Field(..., max_length=255)
    description: str = Field("", max_length=2000)
    siem_platform: str = Field("splunk", description="splunk|sentinel|elastic|qradar|chronicle")
    log_sources: list[str] = Field(
        default_factory=list,
        description="Log source IDs to enable (e.g. ['windows_sysmon', 'aws_cloudtrail'])",
    )
    settings: dict[str, Any] = Field(default_factory=dict)


class EnvironmentUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    siem_platform: str | None = None
    log_sources: list[str] | None = None
    settings: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("")
async def list_environments(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=200),
):
    """List all environments with SIEM connection counts."""
    async with async_session() as session:
        query = select(Environment).order_by(desc(Environment.created_at))
        query = query.offset(skip).limit(limit)
        result = await session.execute(query)
        environments = result.scalars().all()

        total_result = await session.execute(
            select(func.count()).select_from(Environment)
        )
        total = total_result.scalar() or 0

    return {
        "environments": [await _env_to_dict(e) for e in environments],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.post("")
async def create_environment(req: EnvironmentCreateRequest):
    """Create a new simulated environment."""
    async with async_session() as session:
        env = Environment(
            name=req.name,
            description=req.description,
            siem_platform=req.siem_platform,
            log_sources={"enabled": req.log_sources} if req.log_sources else {},
            settings=req.settings,
        )
        session.add(env)
        await session.commit()
        await session.refresh(env)

    return await _env_to_dict(env)


@router.get("/catalog/products")
async def get_product_catalog_route():
    """Return the full product catalog — all vendor options per category.

    Used by the environment builder UI to let users select which security
    products they have deployed (e.g., CrowdStrike for EDR, Palo Alto for firewall).
    """
    from backend.engine.product_catalog import PRODUCT_CATALOG, DEFAULT_VENDORS

    result = {}
    for category, vendors in PRODUCT_CATALOG.items():
        result[category] = {
            "default": DEFAULT_VENDORS.get(category, ""),
            "vendors": [
                {
                    "vendor": vendor_key,
                    "display": info.get("display", vendor_key),
                    "index": info.get("index", ""),
                    "sourcetype": info.get("sourcetype", ""),
                    "log_format": info.get("log_format", ""),
                }
                for vendor_key, info in vendors.items()
            ],
        }
    return result


@router.get("/{environment_id}")
async def get_environment(environment_id: str):
    """Get environment details with SIEM connections and recent test runs."""
    async with async_session() as session:
        try:
            uid = uuid.UUID(environment_id)
        except ValueError:
            raise HTTPException(400, detail="Invalid environment ID.")

        result = await session.execute(
            select(Environment).where(Environment.id == uid)
        )
        env = result.scalar_one_or_none()
        if not env:
            raise HTTPException(404, detail=f"Environment '{environment_id}' not found.")

        # Get SIEM connections
        conn_result = await session.execute(
            select(SIEMConnection).where(SIEMConnection.environment_id == uid)
        )
        connections = conn_result.scalars().all()

        # Get recent test runs
        test_result = await session.execute(
            select(TestRun)
            .where(TestRun.environment_id == uid)
            .order_by(desc(TestRun.created_at))
            .limit(5)
        )
        test_runs = test_result.scalars().all()

    d = await _env_to_dict(env)
    d["siem_connections"] = [_conn_to_dict(c) for c in connections]
    d["recent_test_runs"] = [_test_run_to_dict(t) for t in test_runs]
    return d


@router.put("/{environment_id}")
async def update_environment(environment_id: str, req: EnvironmentUpdateRequest):
    """Update an environment's configuration."""
    async with async_session() as session:
        try:
            uid = uuid.UUID(environment_id)
        except ValueError:
            raise HTTPException(400, detail="Invalid environment ID.")

        result = await session.execute(
            select(Environment).where(Environment.id == uid)
        )
        env = result.scalar_one_or_none()
        if not env:
            raise HTTPException(404, detail=f"Environment '{environment_id}' not found.")

        if req.name is not None:
            env.name = req.name
        if req.description is not None:
            env.description = req.description
        if req.siem_platform is not None:
            env.siem_platform = req.siem_platform
        if req.log_sources is not None:
            env.log_sources = {"enabled": req.log_sources}
        if req.settings is not None:
            env.settings = req.settings
        env.updated_at = datetime.utcnow()

        await session.commit()
        await session.refresh(env)

    return await _env_to_dict(env)


@router.delete("/{environment_id}")
async def delete_environment(environment_id: str):
    """Delete an environment and all related data (cascade)."""
    async with async_session() as session:
        try:
            uid = uuid.UUID(environment_id)
        except ValueError:
            raise HTTPException(400, detail="Invalid environment ID.")

        result = await session.execute(
            select(Environment).where(Environment.id == uid)
        )
        env = result.scalar_one_or_none()
        if not env:
            raise HTTPException(404, detail=f"Environment '{environment_id}' not found.")

        await session.delete(env)
        await session.commit()

    return {"status": "deleted", "id": environment_id}


@router.put("/{environment_id}/products")
async def update_environment_products(environment_id: str, products: dict[str, str]):
    """Update the product selections for an environment.

    Accepts a dict mapping category → vendor key, e.g.:
      {"edr": "crowdstrike", "firewall": "palo_alto", "cloud": "aws"}

    Stores under environment.settings.products.
    """
    async with async_session() as session:
        try:
            uid = uuid.UUID(environment_id)
        except ValueError:
            raise HTTPException(400, detail="Invalid environment ID.")

        result = await session.execute(
            select(Environment).where(Environment.id == uid)
        )
        env = result.scalar_one_or_none()
        if not env:
            raise HTTPException(404, detail="Environment not found.")

        settings = dict(env.settings or {})
        settings["products"] = products
        env.settings = settings
        env.updated_at = datetime.utcnow()
        await session.commit()
        await session.refresh(env)

    return {
        "environment_id": environment_id,
        "products": products,
        "message": "Product selections saved. Simulations will now use vendor-specific log schemas.",
    }


@router.get("/{environment_id}/products")
async def get_environment_products(environment_id: str):
    """Get the current product selections for an environment."""
    async with async_session() as session:
        try:
            uid = uuid.UUID(environment_id)
        except ValueError:
            raise HTTPException(400, detail="Invalid environment ID.")

        result = await session.execute(
            select(Environment).where(Environment.id == uid)
        )
        env = result.scalar_one_or_none()
        if not env:
            raise HTTPException(404, detail="Environment not found.")

    settings = env.settings or {}
    products = settings.get("products", {})

    from backend.engine.product_catalog import PRODUCT_CATALOG, DEFAULT_VENDORS
    resolved = {}
    for category in PRODUCT_CATALOG:
        vendor = products.get(category) or DEFAULT_VENDORS.get(category, "")
        cat_info = PRODUCT_CATALOG[category].get(vendor, {})
        resolved[category] = {
            "vendor": vendor,
            "display": cat_info.get("display", vendor),
            "index": cat_info.get("index", ""),
            "sourcetype": cat_info.get("sourcetype", ""),
            "is_default": category not in products,
        }

    return {
        "environment_id": environment_id,
        "products": resolved,
    }


@router.get("/{environment_id}/log-sources")
async def get_environment_log_sources(environment_id: str):
    """List enabled log sources for an environment with schema metadata."""
    async with async_session() as session:
        try:
            uid = uuid.UUID(environment_id)
        except ValueError:
            raise HTTPException(400, detail="Invalid environment ID.")
        result = await session.execute(
            select(Environment).where(Environment.id == uid)
        )
        env = result.scalar_one_or_none()
        if not env:
            raise HTTPException(404, detail="Environment not found.")

    enabled = (env.log_sources or {}).get("enabled", [])

    from backend.log_sources.schema_registry import get_registry
    registry = get_registry()
    sources = []
    for source_id in enabled:
        schema = registry.get(source_id)
        if schema:
            sources.append({
                "source_id": source_id,
                "vendor": schema.vendor,
                "product": schema.product,
                "category": schema.category,
                "mitre_techniques": list(schema.mitre_mappings.keys()),
            })
        else:
            sources.append({"source_id": source_id, "status": "schema_not_found"})

    return {
        "environment_id": environment_id,
        "enabled_count": len(enabled),
        "sources": sources,
    }


class InfraNodeDeploy(BaseModel):
    node_id: str
    subtype: str  # endpoint | cloud | email | edr | itsm
    variant: str  # windows | linux | aws | azure | crowdstrike ...
    label: str
    hostname: str = ""
    ip: str = ""
    user_count: int = 0
    services: list[str] = Field(default_factory=list)


class DeployRequest(BaseModel):
    infrastructure: list[InfraNodeDeploy] = Field(default_factory=list)


@router.post("/{environment_id}/deploy")
async def deploy_environment(environment_id: str, req: DeployRequest):
    """Deploy an environment — creates asset records in CMDB from infrastructure nodes.

    Each dropped infrastructure node (endpoint, cloud account, email platform, EDR sensor,
    ITSM) becomes a registered asset. These assets are used by the simulation engine to
    generate realistic, host-specific log events and by the CMDB integration to populate
    asset inventory.
    """
    import re
    import random

    try:
        uid = uuid.UUID(environment_id)
    except ValueError:
        raise HTTPException(400, detail="Invalid environment ID.")

    # Load environment to verify it exists + get current assets
    async with async_session() as session:
        result = await session.execute(select(Environment).where(Environment.id == uid))
        env = result.scalar_one_or_none()
        if not env:
            raise HTTPException(404, detail=f"Environment '{environment_id}' not found.")

    assets_created = 0
    asset_list = []

    for node in req.infrastructure:
        # Generate realistic asset metadata from node config
        hostname = node.hostname or _generate_hostname(node.subtype, node.variant, assets_created)
        ip = node.ip or _generate_ip(node.subtype, assets_created)

        asset = {
            "node_id": node.node_id,
            "subtype": node.subtype,
            "variant": node.variant,
            "label": node.label,
            "hostname": hostname,
            "ip": ip,
            "user_count": node.user_count,
            "services": node.services,
            # Log sources that this asset will generate
            "log_sources": _map_node_to_log_sources(node.subtype, node.variant, node.services),
        }
        asset_list.append(asset)
        assets_created += 1

    # Persist deployed assets into environment settings
    async with async_session() as session:
        result = await session.execute(select(Environment).where(Environment.id == uid))
        env = result.scalar_one_or_none()
        if env:
            settings = dict(env.settings or {})
            settings["deployed_assets"] = asset_list
            settings["deployed_at"] = datetime.utcnow().isoformat()
            env.settings = settings
            env.updated_at = datetime.utcnow()
            await session.commit()

    return {
        "environment_id": environment_id,
        "assets_created": assets_created,
        "assets": asset_list,
        "message": f"Deployed {assets_created} assets. CMDB populated. Log sources mapped.",
    }


def _generate_hostname(subtype: str, variant: str, index: int) -> str:
    prefixes = {
        "endpoint": {"windows": "CORP-WS", "windows-dc": "CORP-DC", "windows-server": "CORP-SRV", "linux": "CORP-LX", "macos": "CORP-MAC"},
        "cloud": {"aws": "AWS-ACCT", "azure": "AZ-TENANT", "gcp": "GCP-PROJ"},
        "email": {"exchange": "EXCH-SRV", "gsuite": "GSUITE", "proofpoint": "PP-GW", "mimecast": "MC-GW"},
        "edr": {"crowdstrike": "CS-SENSOR", "defender": "MDE-AGENT", "sentinelone": "S1-AGENT", "carbonblack": "CB-AGENT", "xsiam": "XDR-AGENT"},
        "itsm": {"servicenow": "SNOW-CMDB", "jira": "JIRA-JSM"},
    }
    prefix = prefixes.get(subtype, {}).get(variant, "NODE")
    return f"{prefix}-{index + 1:03d}"


def _generate_ip(subtype: str, index: int) -> str:
    base = {"endpoint": "10.10.1", "cloud": "10.20.0", "email": "10.10.3", "edr": "10.10.1", "itsm": "10.10.4"}
    third = base.get(subtype, "10.99.0")
    return f"{third}.{(index % 254) + 1}"


def _map_node_to_log_sources(subtype: str, variant: str, services: list[str]) -> list[str]:
    mapping: dict[str, list[str]] = {
        "endpoint:windows": ["windows_security", "windows_sysmon", "windows_system"],
        "endpoint:windows-dc": ["windows_security", "windows_sysmon", "windows_system", "ad_audit"],
        "endpoint:windows-server": ["windows_security", "windows_sysmon", "iis_access"],
        "endpoint:linux": ["linux_auth", "linux_syslog", "auditd"],
        "endpoint:macos": ["macos_unified_log", "macos_edr"],
        "cloud:aws": ["aws_cloudtrail", "aws_guardduty", "aws_vpc_flow"],
        "cloud:azure": ["azure_activity", "azure_signin", "azure_defender"],
        "cloud:gcp": ["gcp_cloudaudit", "gcp_cloudlogging"],
        "email:exchange": ["exchange_messagetracking", "exchange_audit"],
        "email:gsuite": ["gsuite_login", "gsuite_drive", "gsuite_admin"],
        "email:proofpoint": ["proofpoint_tap", "proofpoint_filter"],
        "email:mimecast": ["mimecast_email", "mimecast_threat"],
        "edr:crowdstrike": ["crowdstrike_falcon", "crowdstrike_dnr"],
        "edr:defender": ["defender_atp", "defender_edr"],
        "edr:sentinelone": ["sentinelone_threats", "sentinelone_activity"],
        "edr:carbonblack": ["carbonblack_defense", "carbonblack_audit"],
        "edr:xsiam": ["xsiam_xdr", "xsiam_cortex"],
        "itsm:servicenow": ["servicenow_incidents", "servicenow_cmdb"],
        "itsm:jira": ["jira_issues", "jira_audit"],
    }
    key = f"{subtype}:{variant}"
    sources = list(mapping.get(key, [f"{subtype}_{variant}"]))
    # Add cloud service-specific sources
    for svc in services:
        svc_map = {"guardduty": "aws_guardduty", "cloudtrail": "aws_cloudtrail", "aad": "azure_signin", "defender": "azure_defender"}
        if svc in svc_map and svc_map[svc] not in sources:
            sources.append(svc_map[svc])
    return sources


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _env_to_dict(env: Environment) -> dict[str, Any]:
    return {
        "id": str(env.id),
        "name": env.name,
        "description": env.description,
        "siem_platform": env.siem_platform,
        "log_sources": env.log_sources or {},
        "settings": env.settings or {},
        "created_at": env.created_at.isoformat(),
        "updated_at": env.updated_at.isoformat(),
    }


def _conn_to_dict(c: SIEMConnection) -> dict[str, Any]:
    return {
        "id": str(c.id),
        "name": c.name,
        "siem_type": c.siem_type,
        "base_url": c.base_url,
        "is_connected": c.is_connected,
        "last_sync_at": c.last_sync_at.isoformat() if c.last_sync_at else None,
    }


def _test_run_to_dict(t: TestRun) -> dict[str, Any]:
    return {
        "id": str(t.id),
        "status": t.status,
        "total_rules": t.total_rules,
        "rules_passed": t.rules_passed,
        "rules_failed": t.rules_failed,
        "coverage_pct": t.coverage_pct,
        "created_at": t.created_at.isoformat(),
    }
