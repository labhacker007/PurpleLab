"""Environment threat profile management REST API.

Manages CVE, TTP, threat actor, and IOC profiles attached to a specific
environment. Supports manual entry, bulk import, and TIP search stub.
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select

from backend.auth.dependencies import require_role
from backend.db.models import Environment, EnvironmentThreatProfile
from backend.db.session import async_session

router = APIRouter(prefix="/environments/{env_id}/threat-profiles", tags=["threat-profiles"])

_VALID_PROFILE_TYPES = {"cve", "ttp", "actor", "ioc"}


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class ThreatProfileCreateRequest(BaseModel):
    profile_type: str = Field(..., description="cve|ttp|actor|ioc")
    name: str = Field(..., max_length=255)
    data: dict[str, Any] = Field(default_factory=dict, description="Flexible JSONB profile payload")
    source: str = Field("manual", description="manual|upload|tip_api|mcp")


class BulkImportRequest(BaseModel):
    profiles: list[ThreatProfileCreateRequest]
    source: str = Field("upload", description="Source label applied to all imported profiles")


def _profile_to_dict(p: EnvironmentThreatProfile) -> dict[str, Any]:
    return {
        "id": str(p.id),
        "environment_id": str(p.environment_id),
        "profile_type": p.profile_type,
        "name": p.name,
        "data": p.data,
        "source": p.source,
        "created_by": p.created_by,
        "created_at": p.created_at.isoformat(),
    }


async def _get_environment_or_404(session: Any, env_id: uuid.UUID) -> Environment:
    env = await session.scalar(select(Environment).where(Environment.id == env_id))
    if not env:
        raise HTTPException(status_code=404, detail=f"Environment {env_id} not found")
    return env


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("")
async def list_threat_profiles(env_id: uuid.UUID) -> dict[str, Any]:
    """List all threat profiles for the given environment."""
    async with async_session() as session:
        await _get_environment_or_404(session, env_id)
        result = await session.execute(
            select(EnvironmentThreatProfile)
            .where(EnvironmentThreatProfile.environment_id == env_id)
            .order_by(EnvironmentThreatProfile.created_at.desc())
        )
        profiles = result.scalars().all()

    return {"profiles": [_profile_to_dict(p) for p in profiles], "total": len(profiles)}


@router.post("", dependencies=[Depends(require_role("admin", "engineer", "analyst"))])
async def create_threat_profile(
    env_id: uuid.UUID,
    body: ThreatProfileCreateRequest,
    current_user: Any = Depends(require_role("admin", "engineer", "analyst")),
) -> dict[str, Any]:
    """Create a new threat profile for the environment."""
    if body.profile_type not in _VALID_PROFILE_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid profile_type '{body.profile_type}'. Must be one of: {sorted(_VALID_PROFILE_TYPES)}",
        )

    async with async_session() as session:
        await _get_environment_or_404(session, env_id)

        profile = EnvironmentThreatProfile(
            environment_id=env_id,
            profile_type=body.profile_type,
            name=body.name,
            data=body.data,
            source=body.source,
            created_by=current_user.email,
        )
        session.add(profile)
        await session.commit()
        await session.refresh(profile)

    return _profile_to_dict(profile)


@router.post("/bulk-import", dependencies=[Depends(require_role("admin", "engineer", "analyst"))])
async def bulk_import_profiles(
    env_id: uuid.UUID,
    body: BulkImportRequest,
    current_user: Any = Depends(require_role("admin", "engineer", "analyst")),
) -> dict[str, Any]:
    """Bulk-import threat profiles from a JSON array (e.g. from CSV/JSON file upload).

    Validates profile_type for each entry. Invalid entries are skipped and reported.
    """
    async with async_session() as session:
        await _get_environment_or_404(session, env_id)

        imported: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []

        for idx, item in enumerate(body.profiles):
            if item.profile_type not in _VALID_PROFILE_TYPES:
                errors.append({"index": idx, "name": item.name, "error": f"Invalid profile_type '{item.profile_type}'"})
                continue

            profile = EnvironmentThreatProfile(
                environment_id=env_id,
                profile_type=item.profile_type,
                name=item.name,
                data=item.data,
                source=body.source,
                created_by=current_user.email,
            )
            session.add(profile)
            imported.append({"index": idx, "name": item.name, "profile_type": item.profile_type})

        await session.commit()

    return {
        "imported": len(imported),
        "skipped": len(errors),
        "errors": errors,
        "profiles": imported,
    }


@router.delete("/{profile_id}", dependencies=[Depends(require_role("admin", "engineer", "analyst"))])
async def delete_threat_profile(env_id: uuid.UUID, profile_id: uuid.UUID) -> dict[str, Any]:
    """Delete a threat profile from the environment."""
    async with async_session() as session:
        result = await session.execute(
            select(EnvironmentThreatProfile).where(
                EnvironmentThreatProfile.id == profile_id,
                EnvironmentThreatProfile.environment_id == env_id,
            )
        )
        profile = result.scalar_one_or_none()

        if not profile:
            raise HTTPException(status_code=404, detail=f"Threat profile {profile_id} not found in environment {env_id}")

        await session.delete(profile)
        await session.commit()

    return {"status": "deleted", "id": str(profile_id)}


@router.get("/tip-search")
async def tip_search(
    env_id: uuid.UUID,
    q: str = Query("", description="Search query"),
    type: str | None = Query(None, description="Filter by type: ttp|actor|ioc|cve"),
) -> dict[str, Any]:
    """Search for TTPs, actors, or IOCs via TIP integration.

    Returns a stub response — connect a TIP integration to enable live search.
    """
    return {
        "results": [],
        "total": 0,
        "query": q,
        "type": type,
        "message": "Connect TIP integration to enable live search",
        "tip_connected": False,
    }
