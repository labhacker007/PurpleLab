"""SQLAlchemy ORM models for PurpleLab.

All tables use SQLAlchemy 2.0 Mapped[] type hints.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


def _now() -> datetime:
    return datetime.utcnow()


# ── Conversation & Messages ──────────────────────────────────────────────────

class Conversation(Base):
    __tablename__ = "conversations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    title: Mapped[str] = mapped_column(String(255), default="New Conversation")
    environment_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("environments.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())

    messages: Mapped[list[Message]] = relationship("Message", back_populates="conversation", cascade="all, delete-orphan")


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("conversations.id", ondelete="CASCADE")
    )
    role: Mapped[str] = mapped_column(String(20))  # "user", "assistant", "system", "tool"
    content: Mapped[str] = mapped_column(Text, default="")
    tool_calls: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    tool_results: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())

    conversation: Mapped[Conversation] = relationship("Conversation", back_populates="messages")


# ── Environment ──────────────────────────────────────────────────────────────

class Environment(Base):
    __tablename__ = "environments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    siem_platform: Mapped[str] = mapped_column(String(50), default="splunk")
    log_sources: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    settings: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())

    siem_connections: Mapped[list[SIEMConnection]] = relationship("SIEMConnection", back_populates="environment")
    test_runs: Mapped[list[TestRun]] = relationship("TestRun", back_populates="environment")


# ── SIEM Connection ──────────────────────────────────────────────────────────

class SIEMConnection(Base):
    __tablename__ = "siem_connections"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    environment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("environments.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(255))
    siem_type: Mapped[str] = mapped_column(String(50))  # "splunk", "sentinel", "elastic"
    base_url: Mapped[str] = mapped_column(String(500))
    encrypted_credentials: Mapped[str] = mapped_column(Text, default="")  # Fernet-encrypted JSON
    settings: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    is_connected: Mapped[bool] = mapped_column(Boolean, default=False)
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())

    environment: Mapped[Environment] = relationship("Environment", back_populates="siem_connections")


# ── Imported Detection Rules ─────────────────────────────────────────────────

class ImportedRule(Base):
    __tablename__ = "imported_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    environment_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("environments.id", ondelete="SET NULL"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    language: Mapped[str] = mapped_column(String(20))  # "spl", "kql", "esql", "sigma", "yara_l"
    source_query: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    mitre_techniques: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # list of technique IDs
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(50), default="manual")  # "siem", "file", "sigma", "manual"
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())


# ── Threat Intelligence ──────────────────────────────────────────────────────

class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    aliases: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # list of strings
    description: Mapped[str] = mapped_column(Text, default="")
    mitre_groups: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # list of group IDs
    techniques: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # list of technique IDs
    ttps: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # structured TTP data
    source: Mapped[str] = mapped_column(String(50), default="mitre")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())


class MITRETechnique(Base):
    __tablename__ = "mitre_techniques"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    technique_id: Mapped[str] = mapped_column(String(20), unique=True)  # e.g. "T1059.001"
    name: Mapped[str] = mapped_column(String(255))
    tactic: Mapped[str] = mapped_column(String(50))
    description: Mapped[str] = mapped_column(Text, default="")
    platforms: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # list of platforms
    data_sources: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # list of data sources
    detection_guidance: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())


# ── Test Runs & Results ──────────────────────────────────────────────────────

class TestRun(Base):
    __tablename__ = "test_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    environment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("environments.id", ondelete="CASCADE")
    )
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending, running, completed, failed
    total_rules: Mapped[int] = mapped_column(Integer, default=0)
    rules_passed: Mapped[int] = mapped_column(Integer, default=0)
    rules_failed: Mapped[int] = mapped_column(Integer, default=0)
    coverage_pct: Mapped[float] = mapped_column(Float, default=0.0)
    config: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())

    environment: Mapped[Environment] = relationship("Environment", back_populates="test_runs")
    results: Mapped[list[RuleTestResult]] = relationship("RuleTestResult", back_populates="test_run", cascade="all, delete-orphan")


class RuleTestResult(Base):
    __tablename__ = "rule_test_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    test_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("test_runs.id", ondelete="CASCADE")
    )
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("imported_rules.id", ondelete="CASCADE")
    )
    passed: Mapped[bool] = mapped_column(Boolean, default=False)
    matched_events: Mapped[int] = mapped_column(Integer, default=0)
    false_positives: Mapped[int] = mapped_column(Integer, default=0)
    execution_time_ms: Mapped[float] = mapped_column(Float, default=0.0)
    details: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())

    test_run: Mapped[TestRun] = relationship("TestRun", back_populates="results")


# ── Simulation Sessions & Events ─────────────────────────────────────────────

class SimulationSession(Base):
    __tablename__ = "simulation_sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), default="Untitled Session")
    config: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # Full SessionConfig JSON
    status: Mapped[str] = mapped_column(String(20), default="stopped")  # stopped, running, paused
    events_sent: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[int] = mapped_column(Integer, default=0)
    last_event_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())

    events: Mapped[list[GeneratedEvent]] = relationship("GeneratedEvent", back_populates="session", cascade="all, delete-orphan")


class GeneratedEvent(Base):
    __tablename__ = "generated_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("simulation_sessions.id", ondelete="CASCADE")
    )
    product_type: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(500), default="")
    payload: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    target_url: Mapped[str] = mapped_column(String(500), default="")
    status_code: Mapped[int] = mapped_column(Integer, default=0)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())

    session: Mapped[SimulationSession] = relationship("SimulationSession", back_populates="events")


# ── LLM Model Function Config ────────────────────────────────────────────────

class ModelFunctionConfig(Base):
    """Admin-configurable LLM model routing — one row per function."""
    __tablename__ = "model_function_configs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    function_name: Mapped[str] = mapped_column(String(50), unique=True)  # LLMFunction value
    provider: Mapped[str] = mapped_column(String(20))                    # LLMProvider value
    model_id: Mapped[str] = mapped_column(String(100))
    temperature: Mapped[float] = mapped_column(Float, default=0.3)
    max_tokens: Mapped[int] = mapped_column(Integer, default=4096)
    base_url: Mapped[str] = mapped_column(String(500), default="")       # Ollama / Azure
    api_key_override: Mapped[str] = mapped_column(Text, default="")      # Encrypted if set
    extra_params: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    fallback_config_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())


# ── HITL Approval Requests ───────────────────────────────────────────────────

class HITLApprovalRequest(Base):
    """Human-in-the-Loop approval request for a platform action."""
    __tablename__ = "hitl_approval_requests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    action_type: Mapped[str] = mapped_column(String(100))       # e.g. "run_attack_chain", "push_rule"
    action_payload: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    level: Mapped[int] = mapped_column(Integer, default=1)       # L0-L3
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|approved|rejected|expired|auto_approved
    requested_by: Mapped[str] = mapped_column(String(255), default="agent")
    reviewed_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    review_note: Mapped[str] = mapped_column(Text, default="")
    magic_link_token: Mapped[Optional[str]] = mapped_column(String(128), unique=True, nullable=True)
    magic_link_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    notification_channels: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # {slack_channel, email, pagerduty_key}
    notifications_sent: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    auto_approve_after_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # L0 grace period
    context: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # Extra metadata
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


# ── HITL Action Config ────────────────────────────────────────────────────────

class HITLActionConfig(Base):
    """Admin-configured HITL level per action type."""
    __tablename__ = "hitl_action_configs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    action_type: Mapped[str] = mapped_column(String(100), unique=True)
    level: Mapped[int] = mapped_column(Integer, default=1)
    description: Mapped[str] = mapped_column(Text, default="")
    notification_channels: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    auto_approve_after_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())


# ── Log Source Schemas ───────────────────────────────────────────────────────

class LogSourceSchema(Base):
    __tablename__ = "log_source_schemas"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255))
    source_type: Mapped[str] = mapped_column(String(50))  # "windows_eventlog", "sysmon", etc.
    schema_definition: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # Field definitions
    sample_event: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())


# ── Organizations ────────────────────────────────────────────────────────────

class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(100), unique=True)
    plan: Mapped[str] = mapped_column(String(20), default="free")  # free/pro/enterprise
    settings: Mapped[Optional[dict]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())

    users: Mapped[list["User"]] = relationship("User", back_populates="org")


# ── Users ─────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    hashed_password: Mapped[str] = mapped_column(Text)
    full_name: Mapped[str] = mapped_column(String(200), default="")
    role: Mapped[str] = mapped_column(String(20), default="analyst")  # admin/engineer/analyst/viewer
    org_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_superadmin: Mapped[bool] = mapped_column(Boolean, default=False)
    api_key: Mapped[Optional[str]] = mapped_column(String(128), unique=True, nullable=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())

    org: Mapped[Optional[Organization]] = relationship("Organization", back_populates="users")
    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")


# ── Audit Log ─────────────────────────────────────────────────────────────────

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(100))  # e.g. "login", "approve_hitl", "push_rule"
    resource_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    payload: Mapped[Optional[dict]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())

    user: Mapped[Optional[User]] = relationship("User", back_populates="audit_logs")


# ── Pipeline Config ───────────────────────────────────────────────────────────

class PipelineConfig(Base):
    __tablename__ = "pipeline_configs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    schedule_cron: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # e.g. "0 2 * * *"
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    chain_ids: Mapped[Optional[dict]] = mapped_column(JSONB)  # list of attack chain IDs
    siem_connection_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("siem_connections.id", ondelete="SET NULL"), nullable=True
    )
    hitl_level_override: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    notify_slack_channel: Mapped[str] = mapped_column(String(200), default="")
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())

    runs: Mapped[list["PipelineRun"]] = relationship("PipelineRun", back_populates="pipeline", cascade="all, delete-orphan")


# ── Pipeline Run ──────────────────────────────────────────────────────────────

class PipelineRun(Base):
    __tablename__ = "pipeline_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    pipeline_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("pipeline_configs.id", ondelete="CASCADE")
    )
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending/running/completed/failed/cancelled
    triggered_by: Mapped[str] = mapped_column(String(50), default="scheduler")  # scheduler/manual/api
    chains_run: Mapped[int] = mapped_column(Integer, default=0)
    events_generated: Mapped[int] = mapped_column(Integer, default=0)
    detections_fired: Mapped[int] = mapped_column(Integer, default=0)
    des_before: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    des_after: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    report_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())

    pipeline: Mapped[PipelineConfig] = relationship("PipelineConfig", back_populates="runs")
