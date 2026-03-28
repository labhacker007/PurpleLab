"""Session CRUD + start/stop endpoints for v2 API.

These endpoints wrap the simulation engine with database persistence
and richer response models.
"""
from __future__ import annotations

from fastapi import APIRouter

from backend.core.schemas import StatusResponse

router = APIRouter(prefix="/sessions", tags=["sessions"])


@router.get("")
async def list_sessions():
    """List all simulation sessions with status.

    TODO: Query SimulationSession table with pagination and filtering.
    """
    return {"sessions": [], "total": 0}


@router.post("")
async def create_session(name: str = "Untitled Session"):
    """Create a new simulation session.

    TODO: Create SimulationSession record in database.
    TODO: Accept full session config in request body.
    """
    return {"id": "", "name": name, "status": "stopped"}


@router.get("/{session_id}")
async def get_session(session_id: str):
    """Get full session details including stats.

    TODO: Fetch from database with related events count.
    """
    return {"id": session_id, "status": "not_found"}


@router.put("/{session_id}")
async def update_session(session_id: str):
    """Update session configuration.

    TODO: Update SimulationSession record.
    TODO: Restart scheduler if session is running.
    """
    return {"id": session_id, "status": "updated"}


@router.delete("/{session_id}")
async def delete_session(session_id: str):
    """Delete a session and all its events.

    TODO: Stop session if running, cascade delete events.
    """
    return StatusResponse(status="deleted")


@router.post("/{session_id}/start")
async def start_session(session_id: str):
    """Start event generation for a session.

    TODO: Wire up engine scheduler.
    TODO: Update session status in database.
    """
    return StatusResponse(status="started")


@router.post("/{session_id}/stop")
async def stop_session(session_id: str):
    """Stop event generation for a session.

    TODO: Wire up engine scheduler stop.
    TODO: Update session status in database.
    """
    return StatusResponse(status="stopped")
