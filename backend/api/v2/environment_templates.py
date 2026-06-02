"""Environment template management REST API.

Pre-built and custom environment topology templates that can be used to
spin up simulated SOC environments (K8s, CSPM, VM, HR, etc.).
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select

from backend.auth.dependencies import require_role
from backend.db.models import EnvironmentTemplate
from backend.db.session import async_session

router = APIRouter(prefix="/environment-templates", tags=["environment-templates"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class TemplateCreateRequest(BaseModel):
    name: str = Field(..., max_length=255)
    slug: str = Field(..., max_length=100)
    category: str = Field(..., description="cspm|k8s|vm|cmdb|hr|asm|product")
    description: str = ""
    topology: dict[str, Any] = Field(default_factory=dict)
    default_log_sources: list[str] = Field(default_factory=list)
    default_settings: dict[str, Any] = Field(default_factory=dict)
    icon: str | None = None


class TemplateUpdateRequest(BaseModel):
    name: str | None = None
    category: str | None = None
    description: str | None = None
    topology: dict[str, Any] | None = None
    default_log_sources: list[str] | None = None
    default_settings: dict[str, Any] | None = None
    icon: str | None = None


def _template_to_dict(t: EnvironmentTemplate) -> dict[str, Any]:
    return {
        "id": str(t.id),
        "name": t.name,
        "slug": t.slug,
        "category": t.category,
        "description": t.description,
        "topology": t.topology,
        "default_log_sources": t.default_log_sources,
        "default_settings": t.default_settings,
        "icon": t.icon,
        "is_builtin": t.is_builtin,
        "created_at": t.created_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("")
async def list_templates(
    category: str | None = Query(None, description="Filter by category (cspm, k8s, vm, cmdb, hr, asm, product)"),
) -> dict[str, Any]:
    """List all environment templates, optionally filtered by category."""
    async with async_session() as session:
        q = select(EnvironmentTemplate).order_by(EnvironmentTemplate.is_builtin.desc(), EnvironmentTemplate.name)
        if category:
            q = q.where(EnvironmentTemplate.category == category)
        result = await session.execute(q)
        templates = result.scalars().all()

    return {"templates": [_template_to_dict(t) for t in templates], "total": len(templates)}


@router.get("/{template_id}")
async def get_template(template_id: uuid.UUID) -> dict[str, Any]:
    """Get a single environment template by ID."""
    async with async_session() as session:
        result = await session.execute(
            select(EnvironmentTemplate).where(EnvironmentTemplate.id == template_id)
        )
        template = result.scalar_one_or_none()

    if not template:
        raise HTTPException(status_code=404, detail=f"Template {template_id} not found")
    return _template_to_dict(template)


@router.post("", dependencies=[Depends(require_role("admin", "engineer"))])
async def create_template(body: TemplateCreateRequest) -> dict[str, Any]:
    """Create a custom environment template (admin/engineer only)."""
    async with async_session() as session:
        # Check slug uniqueness
        existing = await session.scalar(
            select(EnvironmentTemplate).where(EnvironmentTemplate.slug == body.slug)
        )
        if existing:
            raise HTTPException(status_code=409, detail=f"Template with slug '{body.slug}' already exists")

        template = EnvironmentTemplate(
            name=body.name,
            slug=body.slug,
            category=body.category,
            description=body.description,
            topology=body.topology,
            default_log_sources=body.default_log_sources,
            default_settings=body.default_settings,
            icon=body.icon,
            is_builtin=False,
        )
        session.add(template)
        await session.commit()
        await session.refresh(template)

    return _template_to_dict(template)


@router.put("/{template_id}", dependencies=[Depends(require_role("admin", "engineer"))])
async def update_template(template_id: uuid.UUID, body: TemplateUpdateRequest) -> dict[str, Any]:
    """Update a custom environment template (admin/engineer only; builtin templates cannot be modified)."""
    async with async_session() as session:
        result = await session.execute(
            select(EnvironmentTemplate).where(EnvironmentTemplate.id == template_id)
        )
        template = result.scalar_one_or_none()

        if not template:
            raise HTTPException(status_code=404, detail=f"Template {template_id} not found")
        if template.is_builtin:
            raise HTTPException(status_code=403, detail="Built-in templates cannot be modified")

        updates = body.model_dump(exclude_none=True)
        for field, value in updates.items():
            setattr(template, field, value)

        await session.commit()
        await session.refresh(template)

    return _template_to_dict(template)


@router.delete("/{template_id}", dependencies=[Depends(require_role("admin", "engineer"))])
async def delete_template(template_id: uuid.UUID) -> dict[str, Any]:
    """Delete a custom environment template (admin/engineer only; builtin templates cannot be deleted)."""
    async with async_session() as session:
        result = await session.execute(
            select(EnvironmentTemplate).where(EnvironmentTemplate.id == template_id)
        )
        template = result.scalar_one_or_none()

        if not template:
            raise HTTPException(status_code=404, detail=f"Template {template_id} not found")
        if template.is_builtin:
            raise HTTPException(status_code=403, detail="Built-in templates cannot be deleted")

        await session.delete(template)
        await session.commit()

    return {"status": "deleted", "id": str(template_id)}
