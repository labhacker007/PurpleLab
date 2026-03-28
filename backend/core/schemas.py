"""Shared Pydantic v2 request/response models used across the API.

These are generic schemas shared by multiple modules. Module-specific
schemas live closer to their respective routers.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Generic ──────────────────────────────────────────────────────────────────

class StatusResponse(BaseModel):
    """Generic status response."""
    status: str = "ok"
    message: str = ""


class PaginatedResponse(BaseModel):
    """Wrapper for paginated list responses."""
    items: list[Any] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 50


class ErrorResponse(BaseModel):
    """Standard error response body."""
    error: str
    detail: str = ""
    status_code: int = 500


# ── Chat / Agent ─────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    """Request body for POST /api/v2/chat."""
    message: str
    conversation_id: Optional[str] = None
    environment_id: Optional[str] = None
    context: dict[str, Any] = Field(default_factory=dict)


class ChatChunk(BaseModel):
    """A single SSE chunk from the chat stream."""
    type: str  # "text", "tool_call", "tool_result", "done", "error"
    content: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


# ── Environment ──────────────────────────────────────────────────────────────

class EnvironmentCreate(BaseModel):
    """Request to create a new simulated environment."""
    name: str
    description: str = ""
    siem_platform: str = "splunk"
    log_sources: list[str] = Field(default_factory=list)
    settings: dict[str, Any] = Field(default_factory=dict)


class EnvironmentResponse(BaseModel):
    """Response for an environment."""
    id: str
    name: str
    description: str
    siem_platform: str
    log_sources: list[str]
    created_at: datetime
    updated_at: datetime


# ── SIEM Connection ──────────────────────────────────────────────────────────

class SIEMConnectionCreate(BaseModel):
    """Request to register a SIEM connection."""
    name: str
    siem_type: str  # "splunk", "sentinel", "elastic"
    base_url: str
    credentials: dict[str, str] = Field(default_factory=dict)
    settings: dict[str, Any] = Field(default_factory=dict)


class SIEMConnectionResponse(BaseModel):
    """Response for a SIEM connection (credentials redacted)."""
    id: str
    name: str
    siem_type: str
    base_url: str
    connected: bool = False
    last_sync_at: Optional[datetime] = None


# ── Detection Rules ──────────────────────────────────────────────────────────

class RuleImportRequest(BaseModel):
    """Request to import detection rules."""
    source: str  # "siem", "file", "url", "sigma"
    connection_id: Optional[str] = None
    content: Optional[str] = None
    url: Optional[str] = None


class RuleResponse(BaseModel):
    """Response for a detection rule."""
    id: str
    name: str
    language: str
    severity: str
    mitre_techniques: list[str] = Field(default_factory=list)
    enabled: bool = True


# ── Threat Intel ─────────────────────────────────────────────────────────────

class ThreatActorResponse(BaseModel):
    """Response for a threat actor."""
    id: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    mitre_groups: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)


# ── Test Run ─────────────────────────────────────────────────────────────────

class TestRunCreate(BaseModel):
    """Request to start a detection test run."""
    environment_id: str
    rule_ids: list[str] = Field(default_factory=list)
    scenario: Optional[str] = None


class TestRunResponse(BaseModel):
    """Response for a test run."""
    id: str
    status: str  # "pending", "running", "completed", "failed"
    total_rules: int = 0
    rules_passed: int = 0
    rules_failed: int = 0
    coverage_pct: float = 0.0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
