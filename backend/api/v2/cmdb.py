"""CMDB REST API — v2.

Exposes the Configuration Management Database: people (HR directory),
hardware assets, department summaries, and org-wide CMDB summary.
All queries use async SQLAlchemy 2.0 style against asyncpg.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select, func, or_, and_
from sqlalchemy.orm import selectinload

from backend.db.session import async_session
from backend.db.models import CMDBPerson, CMDBHardwareAsset, VMAssetVulnerability

router = APIRouter(prefix="/cmdb", tags=["cmdb"])


# ── Serialisation helpers ─────────────────────────────────────────────────────

def _person_summary(p: CMDBPerson, asset_count: int = 0) -> dict[str, Any]:
    return {
        "id": str(p.id),
        "employee_id": p.employee_id,
        "first_name": p.first_name,
        "last_name": p.last_name,
        "email": p.email,
        "department": p.department,
        "title": p.title,
        "status": p.status,
        "location": p.location,
        "asset_count": asset_count,
    }


def _person_detail(p: CMDBPerson, assets: list[dict], open_vuln_count: int) -> dict[str, Any]:
    return {
        "id": str(p.id),
        "employee_id": p.employee_id,
        "first_name": p.first_name,
        "last_name": p.last_name,
        "email": p.email,
        "phone": p.phone,
        "department": p.department,
        "title": p.title,
        "employment_type": p.employment_type,
        "manager_id": str(p.manager_id) if p.manager_id else None,
        "location": p.location,
        "status": p.status,
        "hire_date": p.hire_date.isoformat() if p.hire_date else None,
        "slack_handle": p.slack_handle,
        "avatar_initials": p.avatar_initials,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
        "hardware_assets": assets,
        "open_vuln_count": open_vuln_count,
    }


def _asset_summary(a: CMDBHardwareAsset) -> dict[str, Any]:
    return {
        "id": str(a.id),
        "asset_tag": a.asset_tag,
        "asset_type": a.asset_type,
        "make": a.make,
        "model": a.model,
        "status": a.status,
    }


def _asset_detail(a: CMDBHardwareAsset, assigned_to_name: Optional[str], open_vuln_count: int) -> dict[str, Any]:
    return {
        "id": str(a.id),
        "asset_tag": a.asset_tag,
        "asset_type": a.asset_type,
        "make": a.make,
        "model": a.model,
        "serial_number": a.serial_number,
        "purchase_date": a.purchase_date.isoformat() if a.purchase_date else None,
        "warranty_expires": a.warranty_expires.isoformat() if a.warranty_expires else None,
        "os_type": a.os_type,
        "os_version": a.os_version,
        "status": a.status,
        "assigned_to_id": str(a.assigned_to_id) if a.assigned_to_id else None,
        "assigned_to_name": assigned_to_name,
        "assigned_date": a.assigned_date.isoformat() if a.assigned_date else None,
        "location": a.location,
        "specs": a.specs or {},
        "tags": a.tags or {},
        "notes": a.notes,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
        "open_vuln_count": open_vuln_count,
    }


def _asset_list_row(a: CMDBHardwareAsset) -> dict[str, Any]:
    assigned_name: Optional[str] = None
    if a.assigned_to:
        assigned_name = f"{a.assigned_to.first_name} {a.assigned_to.last_name}"
    return {
        "id": str(a.id),
        "asset_tag": a.asset_tag,
        "asset_type": a.asset_type,
        "make": a.make,
        "model": a.model,
        "serial_number": a.serial_number,
        "os_type": a.os_type,
        "os_version": a.os_version,
        "status": a.status,
        "assigned_to_id": str(a.assigned_to_id) if a.assigned_to_id else None,
        "assigned_to_name": assigned_name,
        "assigned_date": a.assigned_date.isoformat() if a.assigned_date else None,
        "location": a.location,
        "purchase_date": a.purchase_date.isoformat() if a.purchase_date else None,
        "warranty_expires": a.warranty_expires.isoformat() if a.warranty_expires else None,
        "specs": a.specs or {},
        "tags": a.tags or {},
        "notes": a.notes,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
    }


# ── GET /cmdb/people ──────────────────────────────────────────────────────────

@router.get("/people")
async def list_people(
    department: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    employment_type: Optional[str] = Query(None),
    search: Optional[str] = Query(None, description="Search by name or email (case-insensitive)"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> dict[str, Any]:
    """List people with optional filters. Returns summary rows with asset_count."""
    async with async_session() as session:
        # --- count query ---
        count_q = select(func.count()).select_from(CMDBPerson)
        filters = []
        if department:
            filters.append(CMDBPerson.department == department)
        if status:
            filters.append(CMDBPerson.status == status)
        if employment_type:
            filters.append(CMDBPerson.employment_type == employment_type)
        if search:
            term = f"%{search.lower()}%"
            filters.append(
                or_(
                    func.lower(CMDBPerson.email).like(term),
                    func.lower(CMDBPerson.first_name).like(term),
                    func.lower(CMDBPerson.last_name).like(term),
                    func.lower(
                        func.concat(CMDBPerson.first_name, " ", CMDBPerson.last_name)
                    ).like(term),
                )
            )
        if filters:
            count_q = count_q.where(and_(*filters))
        total: int = (await session.execute(count_q)).scalar() or 0

        # --- data query ---
        data_q = select(CMDBPerson)
        if filters:
            data_q = data_q.where(and_(*filters))
        data_q = data_q.order_by(CMDBPerson.last_name, CMDBPerson.first_name).offset(offset).limit(limit)
        people = (await session.execute(data_q)).scalars().all()

        if not people:
            return {"people": [], "total": total, "offset": offset, "limit": limit}

        # --- asset counts per person (single aggregation query) ---
        person_ids = [p.id for p in people]
        ac_q = (
            select(CMDBHardwareAsset.assigned_to_id, func.count(CMDBHardwareAsset.id).label("cnt"))
            .where(CMDBHardwareAsset.assigned_to_id.in_(person_ids))
            .group_by(CMDBHardwareAsset.assigned_to_id)
        )
        ac_rows = (await session.execute(ac_q)).all()
        asset_counts: dict[uuid.UUID, int] = {row.assigned_to_id: row.cnt for row in ac_rows}

        return {
            "people": [_person_summary(p, asset_counts.get(p.id, 0)) for p in people],
            "total": total,
            "offset": offset,
            "limit": limit,
        }


# ── GET /cmdb/people/{person_id} ──────────────────────────────────────────────

@router.get("/people/{person_id}")
async def get_person(person_id: uuid.UUID) -> dict[str, Any]:
    """Full person detail including hardware assets and open vulnerability count."""
    async with async_session() as session:
        # Person + eager-load hardware_assets
        q = (
            select(CMDBPerson)
            .options(selectinload(CMDBPerson.hardware_assets))
            .where(CMDBPerson.id == person_id)
        )
        person: Optional[CMDBPerson] = (await session.execute(q)).scalar_one_or_none()
        if not person:
            raise HTTPException(status_code=404, detail="Person not found")

        assets = [_asset_summary(a) for a in person.hardware_assets]
        asset_ids = [a.id for a in person.hardware_assets]

        # Open vuln count across all assigned hardware
        open_vuln_count = 0
        if asset_ids:
            vc_q = (
                select(func.count(VMAssetVulnerability.id))
                .where(
                    and_(
                        VMAssetVulnerability.hardware_asset_id.in_(asset_ids),
                        VMAssetVulnerability.status == "open",
                    )
                )
            )
            open_vuln_count = (await session.execute(vc_q)).scalar() or 0

        return _person_detail(person, assets, open_vuln_count)


# ── GET /cmdb/assets ──────────────────────────────────────────────────────────

@router.get("/assets")
async def list_assets(
    asset_type: Optional[str] = Query(None, description="laptop / mac / windows_laptop / phone / tablet / server"),
    status: Optional[str] = Query(None),
    os_type: Optional[str] = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> dict[str, Any]:
    """List hardware assets with optional filters. Includes assigned-to person name."""
    async with async_session() as session:
        filters = []
        if asset_type:
            filters.append(CMDBHardwareAsset.asset_type == asset_type)
        if status:
            filters.append(CMDBHardwareAsset.status == status)
        if os_type:
            filters.append(CMDBHardwareAsset.os_type == os_type)

        count_q = select(func.count()).select_from(CMDBHardwareAsset)
        if filters:
            count_q = count_q.where(and_(*filters))
        total: int = (await session.execute(count_q)).scalar() or 0

        data_q = (
            select(CMDBHardwareAsset)
            .options(selectinload(CMDBHardwareAsset.assigned_to))
        )
        if filters:
            data_q = data_q.where(and_(*filters))
        data_q = data_q.order_by(CMDBHardwareAsset.asset_tag).offset(offset).limit(limit)
        assets = (await session.execute(data_q)).scalars().all()

        return {
            "assets": [_asset_list_row(a) for a in assets],
            "total": total,
            "offset": offset,
            "limit": limit,
        }


# ── GET /cmdb/assets/{asset_id} ───────────────────────────────────────────────

@router.get("/assets/{asset_id}")
async def get_asset(asset_id: uuid.UUID) -> dict[str, Any]:
    """Full asset detail including assigned person and open vulnerability count."""
    async with async_session() as session:
        q = (
            select(CMDBHardwareAsset)
            .options(selectinload(CMDBHardwareAsset.assigned_to))
            .where(CMDBHardwareAsset.id == asset_id)
        )
        asset: Optional[CMDBHardwareAsset] = (await session.execute(q)).scalar_one_or_none()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")

        assigned_to_name: Optional[str] = None
        if asset.assigned_to:
            assigned_to_name = f"{asset.assigned_to.first_name} {asset.assigned_to.last_name}"

        vc_q = (
            select(func.count(VMAssetVulnerability.id))
            .where(
                and_(
                    VMAssetVulnerability.hardware_asset_id == asset.id,
                    VMAssetVulnerability.status == "open",
                )
            )
        )
        open_vuln_count: int = (await session.execute(vc_q)).scalar() or 0

        return _asset_detail(asset, assigned_to_name, open_vuln_count)


# ── GET /cmdb/departments ─────────────────────────────────────────────────────

@router.get("/departments")
async def list_departments() -> dict[str, Any]:
    """Return each department with its people count and assigned asset count."""
    async with async_session() as session:
        # People counts per department
        pc_q = (
            select(CMDBPerson.department, func.count(CMDBPerson.id).label("people_count"))
            .where(CMDBPerson.department.isnot(None))
            .group_by(CMDBPerson.department)
            .order_by(CMDBPerson.department)
        )
        pc_rows = (await session.execute(pc_q)).all()

        if not pc_rows:
            return {"departments": []}

        dept_names = [row.department for row in pc_rows]

        # Asset counts per department: join hardware_assets → person
        ac_q = (
            select(CMDBPerson.department, func.count(CMDBHardwareAsset.id).label("asset_count"))
            .join(CMDBHardwareAsset, CMDBHardwareAsset.assigned_to_id == CMDBPerson.id, isouter=True)
            .where(CMDBPerson.department.in_(dept_names))
            .group_by(CMDBPerson.department)
        )
        ac_rows = (await session.execute(ac_q)).all()
        asset_counts: dict[str, int] = {row.department: row.asset_count for row in ac_rows}

        departments = [
            {
                "department": row.department,
                "people_count": row.people_count,
                "asset_count": asset_counts.get(row.department, 0),
            }
            for row in pc_rows
        ]
        return {"departments": departments}


# ── GET /cmdb/summary ─────────────────────────────────────────────────────────

@router.get("/summary")
async def cmdb_summary() -> dict[str, Any]:
    """Org-wide CMDB summary: headcount, assets by type/status, recent hires."""
    async with async_session() as session:
        # Total people
        total_people: int = (
            await session.execute(select(func.count()).select_from(CMDBPerson))
        ).scalar() or 0

        # People by department
        dept_q = (
            select(CMDBPerson.department, func.count(CMDBPerson.id).label("cnt"))
            .where(CMDBPerson.department.isnot(None))
            .group_by(CMDBPerson.department)
        )
        by_department: dict[str, int] = {
            row.department: row.cnt
            for row in (await session.execute(dept_q)).all()
        }

        # Total assets
        total_assets: int = (
            await session.execute(select(func.count()).select_from(CMDBHardwareAsset))
        ).scalar() or 0

        # Assets by type
        at_q = (
            select(CMDBHardwareAsset.asset_type, func.count(CMDBHardwareAsset.id).label("cnt"))
            .group_by(CMDBHardwareAsset.asset_type)
        )
        by_asset_type: dict[str, int] = {
            row.asset_type: row.cnt
            for row in (await session.execute(at_q)).all()
        }

        # Assets by status
        as_q = (
            select(CMDBHardwareAsset.status, func.count(CMDBHardwareAsset.id).label("cnt"))
            .group_by(CMDBHardwareAsset.status)
        )
        by_status: dict[str, int] = {
            row.status: row.cnt
            for row in (await session.execute(as_q)).all()
        }

        # Recent hires (last 90 days)
        cutoff = datetime.utcnow() - timedelta(days=90)
        recent_hires: int = (
            await session.execute(
                select(func.count())
                .select_from(CMDBPerson)
                .where(CMDBPerson.hire_date >= cutoff)
            )
        ).scalar() or 0

        return {
            "total_people": total_people,
            "by_department": by_department,
            "total_assets": total_assets,
            "by_asset_type": by_asset_type,
            "by_status": by_status,
            "recent_hires": recent_hires,
        }
