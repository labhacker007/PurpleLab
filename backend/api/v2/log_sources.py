"""Log source generation endpoints for v2 API.

Generates realistic log data from various sources (Windows EventLog,
Sysmon, Linux audit, firewall, proxy, DNS, CloudTrail) for testing
detection rules.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Query

router = APIRouter(prefix="/log-sources", tags=["log-sources"])


@router.get("/types")
async def list_log_source_types():
    """List available log source types.

    TODO: Return from constants or LogSourceSchema table.
    """
    from backend.core.constants import LOG_SOURCE_TYPES
    return {"types": LOG_SOURCE_TYPES}


@router.get("/schemas")
async def list_schemas():
    """List log source schemas with field definitions.

    TODO: Query LogSourceSchema table.
    """
    return {"schemas": [], "total": 0}


@router.post("/generate")
async def generate_logs(
    source_type: str,
    count: int = Query(10, ge=1, le=1000),
    include_malicious: bool = True,
    malicious_ratio: float = Query(0.1, ge=0.0, le=1.0),
    mitre_technique: Optional[str] = None,
):
    """Generate synthetic log data for a given source type.

    Produces a mix of benign noise and malicious events matching
    the specified parameters.

    Args:
        source_type: The log source type (e.g., "sysmon", "windows_eventlog").
        count: Number of events to generate.
        include_malicious: Whether to include malicious events.
        malicious_ratio: Fraction of events that should be malicious.
        mitre_technique: Optional MITRE technique to simulate.

    TODO: Wire up log_sources/ generators.
    TODO: Support output in CIM, ASIM, and ECS formats via data models.
    """
    return {
        "source_type": source_type,
        "events": [],
        "count": 0,
        "malicious_count": 0,
    }


@router.post("/generate-batch")
async def generate_batch():
    """Generate logs from multiple sources simultaneously.

    Useful for creating a realistic mixed-source environment
    for testing correlation rules.

    TODO: Accept list of source configs and generate in parallel.
    """
    return {"sources": [], "total_events": 0}
