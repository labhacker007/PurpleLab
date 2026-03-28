"""Environment CRUD endpoints for v2 API.

Environments represent a simulated SOC setup with a specific SIEM platform,
log sources, and configuration.
"""
from __future__ import annotations

from fastapi import APIRouter

from backend.core.schemas import EnvironmentCreate, EnvironmentResponse, StatusResponse

router = APIRouter(prefix="/environments", tags=["environments"])


@router.get("")
async def list_environments():
    """List all environments.

    TODO: Query Environment table with pagination.
    """
    return {"environments": [], "total": 0}


@router.post("")
async def create_environment(request: EnvironmentCreate):
    """Create a new simulated environment.

    TODO: Create Environment record in database.
    TODO: Initialize default log sources for the selected SIEM platform.
    """
    return {
        "id": "",
        "name": request.name,
        "siem_platform": request.siem_platform,
        "status": "created",
    }


@router.get("/{environment_id}")
async def get_environment(environment_id: str):
    """Get environment details.

    TODO: Fetch from Environment table with related SIEM connections and log sources.
    """
    return {"id": environment_id, "status": "not_found"}


@router.put("/{environment_id}")
async def update_environment(environment_id: str, request: EnvironmentCreate):
    """Update an environment's configuration.

    TODO: Update Environment record.
    """
    return {"id": environment_id, "status": "updated"}


@router.delete("/{environment_id}")
async def delete_environment(environment_id: str):
    """Delete an environment and associated data.

    TODO: Cascade delete SIEM connections, test runs, etc.
    """
    return StatusResponse(status="deleted")
