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
    text,
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
    edr_persona: Mapped[Optional[str]] = mapped_column(String(60), nullable=True)
    siem_persona: Mapped[Optional[str]] = mapped_column(String(60), nullable=True)
    idp_persona: Mapped[Optional[str]] = mapped_column(String(60), nullable=True)
    firewall_persona: Mapped[Optional[str]] = mapped_column(String(60), nullable=True)
    network_persona: Mapped[Optional[str]] = mapped_column(String(60), nullable=True)
    log_sources: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    settings: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())

    siem_connections: Mapped[list[SIEMConnection]] = relationship("SIEMConnection", back_populates="environment")
    test_runs: Mapped[list[TestRun]] = relationship("TestRun", back_populates="environment")
    threat_profiles: Mapped[list["EnvironmentThreatProfile"]] = relationship("EnvironmentThreatProfile", back_populates="environment", cascade="all, delete-orphan")


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
    stopped_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
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

class ProviderApiKey(Base):
    """Persisted provider API keys (encrypted at rest)."""
    __tablename__ = "provider_api_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    provider: Mapped[str] = mapped_column(String(50), unique=True)  # anthropic, openai, google, etc.
    encrypted_key: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(20), default="ui")  # "ui" | "env"
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())


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


# ── Use Cases ─────────────────────────────────────────────────────────────────

class UseCase(Base):
    """A specific attack scenario that should be detectable.

    Represents a named test scenario tied to one or more MITRE techniques.
    The platform simulates the scenario, runs detection rules against the
    generated logs, and scores pass/fail to validate detection coverage.
    """
    __tablename__ = "use_cases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(300))  # e.g. "Mimikatz LSASS Dump"
    description: Mapped[str] = mapped_column(Text, default="")
    technique_ids: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # ["T1003.001"]
    tactic: Mapped[str] = mapped_column(String(100), default="")  # e.g. "credential-access"
    threat_actor: Mapped[str] = mapped_column(String(200), default="")  # e.g. "APT29"
    attack_chain_id: Mapped[str] = mapped_column(String(100), default="")  # link to builtin chain id
    expected_log_sources: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # ["windows_security", "sysmon"]
    severity: Mapped[str] = mapped_column(String(20), default="high")  # critical/high/medium/low
    tags: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # ["windows", "credential", "apt"]
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)   # continuously tested in pipeline
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)  # comes from seed library
    last_validated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())

    runs: Mapped[list["UseCaseRun"]] = relationship(
        "UseCaseRun", back_populates="use_case", cascade="all, delete-orphan"
    )


class UseCaseRun(Base):
    """A single execution of a use case validation cycle.

    Created each time a use case is validated — stores the full results
    of simulating the attack scenario and testing detection rules against
    the generated logs.
    """
    __tablename__ = "use_case_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    use_case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("use_cases.id", ondelete="CASCADE")
    )
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending/running/passed/failed/partial/error
    triggered_by: Mapped[str] = mapped_column(String(50), default="manual")  # manual/pipeline/scheduled/agent
    events_generated: Mapped[int] = mapped_column(Integer, default=0)
    rules_tested: Mapped[int] = mapped_column(Integer, default=0)
    rules_fired: Mapped[int] = mapped_column(Integer, default=0)
    pass_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)  # rules_fired/rules_tested
    run_details: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # per-rule results
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())

    use_case: Mapped[UseCase] = relationship("UseCase", back_populates="runs")


# ── Knowledge Base ───────────────────────────────────────────────────────────

class KnowledgeDocument(Base):
    """A document stored in the knowledge base for agent retrieval.

    Supports procedures, playbooks, runbooks, techniques, and custom content.
    Embeddings are stored in ChromaDB; status tracks indexing lifecycle.
    """
    __tablename__ = "knowledge_documents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    title: Mapped[str] = mapped_column(String(500))
    content: Mapped[str] = mapped_column(Text, default="")
    doc_type: Mapped[str] = mapped_column(String(50), default="custom")  # procedure/playbook/runbook/technique/custom
    tags: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)   # list of tag strings
    source_url: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    embedding_status: Mapped[str] = mapped_column(String(20), default="pending")  # pending/indexed/failed
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())


# ── Reports ───────────────────────────────────────────────────────────────────

class Report(Base):
    """A generated report (coverage, use_cases, pipeline, or full).

    Stores the computed report data as JSONB and optionally a file path
    for HTML exports. Status transitions: generating → ready | failed.
    """
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(300))
    type: Mapped[str] = mapped_column(String(30))  # coverage | use_cases | pipeline | full
    format: Mapped[str] = mapped_column(String(10), default="json")  # json | html
    status: Mapped[str] = mapped_column(String(20), default="generating")  # generating | ready | failed
    data: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    file_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())


# ── TTP Event Template Library ────────────────────────────────────────────────

class TTPEventTemplate(Base):
    """Pre-seeded + LLM-cached TTP behavior templates for token-efficient simulation."""
    __tablename__ = "ttp_event_templates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    tactic: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    log_source: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, server_default="medium")
    title_template: Mapped[str] = mapped_column(String(500), nullable=False, server_default="")
    payload_template: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    variables: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    is_builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())


# ── Simulation Scenarios ───────────────────────────────────────────────────────

class SimulationScenario(Base):
    """Saved and replayable simulation event sequences."""
    __tablename__ = "simulation_scenarios"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    threat_actor_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    technique_ids: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    events: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    asset_snapshot: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    ioc_snapshot: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    source_session_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    environment_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    use_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())


# ── Security Simulation Models ─────────────────────────────────────────────────

class SimulatedEndpoint(Base):
    """Managed endpoints in the simulated EDR environment."""
    __tablename__ = "simulated_endpoints"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    environment_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("environments.id", ondelete="CASCADE"), nullable=True
    )
    hostname: Mapped[str] = mapped_column(String(255))
    ip_address: Mapped[str] = mapped_column(String(45))
    os_platform: Mapped[str] = mapped_column(String(50), default="windows")
    os_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    edr_vendor: Mapped[str] = mapped_column(String(50), default="crowdstrike")
    agent_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="online")  # online | isolated | offline | degraded
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_now)
    tags: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    extra: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())


class SimulatedUser(Base):
    """User accounts in the simulated identity provider (Okta/Entra/AD)."""
    __tablename__ = "simulated_users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    environment_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("environments.id", ondelete="CASCADE"), nullable=True
    )
    username: Mapped[str] = mapped_column(String(255))
    email: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    department: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    title: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    identity_vendor: Mapped[str] = mapped_column(String(50), default="okta")
    status: Mapped[str] = mapped_column(String(30), default="active")  # active | locked | disabled | suspended
    mfa_enrolled: Mapped[bool] = mapped_column(Boolean, default=True)
    risk_level: Mapped[str] = mapped_column(String(20), default="low")  # low | medium | high | critical
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    attributes: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())


class ContainmentAction(Base):
    """Immutable audit log of every containment action executed in the simulation."""
    __tablename__ = "containment_actions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    environment_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("environments.id", ondelete="SET NULL"), nullable=True
    )
    # isolate_host | release_host | block_hash | block_process | block_ip
    # block_domain | unblock_ip | unblock_domain | lock_user | unlock_user
    # disable_user | enable_user | revoke_sessions | force_mfa | run_command
    action_type: Mapped[str] = mapped_column(String(50))
    target_type: Mapped[str] = mapped_column(String(30))  # endpoint | user | ip | domain | hash | process
    target_value: Mapped[str] = mapped_column(String(500))
    target_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    requester: Mapped[str] = mapped_column(String(255), default="api")
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="success")  # success | failed | pending | reversed
    result_detail: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    reversed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    reversed_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    executed_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())


class BlockListEntry(Base):
    """Active block list entries across all simulated security controls.

    Covers IP (firewall), domain (proxy/DNS), file hash (EDR/AV), process name.
    """
    __tablename__ = "block_list_entries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    environment_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("environments.id", ondelete="CASCADE"), nullable=True
    )
    block_type: Mapped[str] = mapped_column(String(30))  # ip | domain | hash | process | url
    value: Mapped[str] = mapped_column(String(500))
    hash_type: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)  # md5 | sha1 | sha256
    direction: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)  # inbound | outbound | both
    vendor: Mapped[str] = mapped_column(String(50), default="crowdstrike")
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    added_by: Mapped[str] = mapped_column(String(255), default="api")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())


# ── CMDB — People / HR Directory ─────────────────────────────────────────────

class CMDBPerson(Base):
    __tablename__ = "cmdb_people"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    employee_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    phone: Mapped[Optional[str]] = mapped_column(String(50))
    department: Mapped[Optional[str]] = mapped_column(String(100))
    title: Mapped[Optional[str]] = mapped_column(String(150))
    employment_type: Mapped[str] = mapped_column(String(20), default="employee")
    manager_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("cmdb_people.id"), nullable=True)
    location: Mapped[Optional[str]] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20), default="active")
    hire_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    slack_handle: Mapped[Optional[str]] = mapped_column(String(100))
    avatar_initials: Mapped[Optional[str]] = mapped_column(String(4))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    hardware_assets: Mapped[list["CMDBHardwareAsset"]] = relationship("CMDBHardwareAsset", back_populates="assigned_to", foreign_keys="CMDBHardwareAsset.assigned_to_id")


# ── CMDB — Hardware Assets ────────────────────────────────────────────────────

class CMDBHardwareAsset(Base):
    __tablename__ = "cmdb_hardware_assets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    asset_tag: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    asset_type: Mapped[str] = mapped_column(String(30), nullable=False)
    make: Mapped[Optional[str]] = mapped_column(String(80))
    model: Mapped[Optional[str]] = mapped_column(String(150))
    serial_number: Mapped[Optional[str]] = mapped_column(String(100))
    purchase_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    warranty_expires: Mapped[Optional[datetime]] = mapped_column(DateTime)
    os_type: Mapped[Optional[str]] = mapped_column(String(30))
    os_version: Mapped[Optional[str]] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20), default="assigned")
    assigned_to_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("cmdb_people.id"), nullable=True)
    assigned_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    location: Mapped[Optional[str]] = mapped_column(String(100))
    specs: Mapped[Optional[Any]] = mapped_column(JSONB, default=dict)
    tags: Mapped[Optional[Any]] = mapped_column(JSONB, default=dict)
    notes: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    assigned_to: Mapped[Optional["CMDBPerson"]] = relationship("CMDBPerson", back_populates="hardware_assets", foreign_keys=[assigned_to_id])
    vulnerabilities: Mapped[list["VMAssetVulnerability"]] = relationship("VMAssetVulnerability", back_populates="hardware_asset", foreign_keys="VMAssetVulnerability.hardware_asset_id")


# ── Product Registry — Cloud Accounts ────────────────────────────────────────

class ProductCloudAccount(Base):
    __tablename__ = "product_registry_cloud_accounts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    cloud_provider: Mapped[str] = mapped_column(String(10), nullable=False)
    account_id: Mapped[str] = mapped_column(String(50), nullable=False)
    account_name: Mapped[str] = mapped_column(String(150), nullable=False)
    account_type: Mapped[str] = mapped_column(String(30), default="production")
    environment: Mapped[str] = mapped_column(String(20), default="prod")
    region_primary: Mapped[Optional[str]] = mapped_column(String(50))
    regions: Mapped[Optional[Any]] = mapped_column(JSONB, default=list)
    owner_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("cmdb_people.id"), nullable=True)
    technical_lead_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("cmdb_people.id"), nullable=True)
    billing_email: Mapped[Optional[str]] = mapped_column(String(200))
    monthly_cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    tags: Mapped[Optional[Any]] = mapped_column(JSONB, default=dict)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    cloudtrail_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    security_hub_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    products: Mapped[list["ProductRegistryProduct"]] = relationship("ProductRegistryProduct", back_populates="cloud_account", foreign_keys="ProductRegistryProduct.cloud_account_id")
    cspm_findings: Mapped[list["CSPMFinding"]] = relationship("CSPMFinding", back_populates="cloud_account", foreign_keys="CSPMFinding.cloud_account_id")


# ── Product Registry — Products ───────────────────────────────────────────────

class ProductRegistryProduct(Base):
    __tablename__ = "product_registry_products"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    product_type: Mapped[str] = mapped_column(String(30), default="internal")
    category: Mapped[Optional[str]] = mapped_column(String(50))
    tier: Mapped[str] = mapped_column(String(20), default="tier2_important")
    description: Mapped[Optional[str]] = mapped_column(Text)
    owner_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("cmdb_people.id"), nullable=True)
    tech_lead_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("cmdb_people.id"), nullable=True)
    team: Mapped[Optional[str]] = mapped_column(String(100))
    url_production: Mapped[Optional[str]] = mapped_column(String(500))
    url_staging: Mapped[Optional[str]] = mapped_column(String(500))
    url_docs: Mapped[Optional[str]] = mapped_column(String(500))
    url_repo: Mapped[Optional[str]] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(20), default="active")
    data_classification: Mapped[str] = mapped_column(String(20), default="internal")
    pii_data: Mapped[bool] = mapped_column(Boolean, default=False)
    phi_data: Mapped[bool] = mapped_column(Boolean, default=False)
    pci_data: Mapped[bool] = mapped_column(Boolean, default=False)
    compliance_frameworks: Mapped[Optional[Any]] = mapped_column(JSONB, default=list)
    tech_stack: Mapped[Optional[Any]] = mapped_column(JSONB, default=list)
    deployment_model: Mapped[str] = mapped_column(String(20), default="cloud")
    cloud_account_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("product_registry_cloud_accounts.id"), nullable=True)
    server_names: Mapped[Optional[Any]] = mapped_column(JSONB, default=list)
    container_names: Mapped[Optional[Any]] = mapped_column(JSONB, default=list)
    k8s_namespace: Mapped[Optional[str]] = mapped_column(String(100))
    database_types: Mapped[Optional[Any]] = mapped_column(JSONB, default=list)
    annual_cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    vendor_name: Mapped[Optional[str]] = mapped_column(String(150))
    vendor_contract_expires: Mapped[Optional[datetime]] = mapped_column(DateTime)
    sla_uptime_target: Mapped[float] = mapped_column(Float, default=99.9)
    on_call_slack_channel: Mapped[Optional[str]] = mapped_column(String(100))
    incident_runbook_url: Mapped[Optional[str]] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    cloud_account: Mapped[Optional["ProductCloudAccount"]] = relationship("ProductCloudAccount", back_populates="products", foreign_keys=[cloud_account_id])
    vulnerabilities: Mapped[list["VMAssetVulnerability"]] = relationship("VMAssetVulnerability", back_populates="product", foreign_keys="VMAssetVulnerability.product_id")
    cspm_findings: Mapped[list["CSPMFinding"]] = relationship("CSPMFinding", back_populates="product", foreign_keys="CSPMFinding.product_id")


# ── Vulnerability Management — CVE Library ────────────────────────────────────

class VMVulnerability(Base):
    __tablename__ = "vm_vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    cve_id: Mapped[Optional[str]] = mapped_column(String(30), unique=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(15), nullable=False)
    cwe_id: Mapped[Optional[str]] = mapped_column(String(30))
    affected_component: Mapped[Optional[str]] = mapped_column(String(200))
    affected_versions: Mapped[Optional[Any]] = mapped_column(JSONB, default=list)
    fixed_version: Mapped[Optional[str]] = mapped_column(String(100))
    epss_score: Mapped[float] = mapped_column(Float, default=0.0)
    cisa_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_public: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_type: Mapped[Optional[str]] = mapped_column(String(100))
    attack_vector: Mapped[Optional[str]] = mapped_column(String(20))
    attack_complexity: Mapped[Optional[str]] = mapped_column(String(10))
    references: Mapped[Optional[Any]] = mapped_column(JSONB, default=list)
    nvd_published_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    asset_instances: Mapped[list["VMAssetVulnerability"]] = relationship("VMAssetVulnerability", back_populates="vulnerability", foreign_keys="VMAssetVulnerability.vuln_id")


# ── Vulnerability Management — Asset Instances ────────────────────────────────

class VMAssetVulnerability(Base):
    __tablename__ = "vm_asset_vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    vuln_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("vm_vulnerabilities.id"), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(20), nullable=False)
    hardware_asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("cmdb_hardware_assets.id"), nullable=True)
    product_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("product_registry_products.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="open")
    severity_override: Mapped[Optional[str]] = mapped_column(String(15))
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    assigned_to_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("cmdb_people.id"), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    remediation_due_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    scan_source: Mapped[Optional[str]] = mapped_column(String(50))
    notes: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    vulnerability: Mapped["VMVulnerability"] = relationship("VMVulnerability", back_populates="asset_instances", foreign_keys=[vuln_id])
    hardware_asset: Mapped[Optional["CMDBHardwareAsset"]] = relationship("CMDBHardwareAsset", back_populates="vulnerabilities", foreign_keys=[hardware_asset_id])
    product: Mapped[Optional["ProductRegistryProduct"]] = relationship("ProductRegistryProduct", back_populates="vulnerabilities", foreign_keys=[product_id])


# ── CSPM — Check Catalog ──────────────────────────────────────────────────────

class CSPMCheck(Base):
    __tablename__ = "cspm_checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    check_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    framework: Mapped[str] = mapped_column(String(30), nullable=False)
    cloud_provider: Mapped[Optional[str]] = mapped_column(String(10))
    section: Mapped[Optional[str]] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    remediation_steps: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(15), nullable=False)
    automated: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    findings: Mapped[list["CSPMFinding"]] = relationship("CSPMFinding", back_populates="check", foreign_keys="CSPMFinding.check_id")


# ── CSPM — Findings ───────────────────────────────────────────────────────────

class CSPMFinding(Base):
    __tablename__ = "cspm_findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    check_id: Mapped[int] = mapped_column(Integer, ForeignKey("cspm_checks.id"), nullable=False)
    cloud_account_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("product_registry_cloud_accounts.id"), nullable=False)
    product_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("product_registry_products.id"), nullable=True)
    resource_id: Mapped[str] = mapped_column(String(500), nullable=False)
    resource_type: Mapped[Optional[str]] = mapped_column(String(100))
    resource_name: Mapped[Optional[str]] = mapped_column(String(300))
    region: Mapped[Optional[str]] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20), default="open")
    severity: Mapped[str] = mapped_column(String(15), nullable=False)
    title: Mapped[Optional[str]] = mapped_column(String(300))
    description: Mapped[Optional[str]] = mapped_column(Text)
    evidence: Mapped[Optional[Any]] = mapped_column(JSONB, default=dict)
    remediation_effort: Mapped[str] = mapped_column(String(10), default="low")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    suppressed_reason: Mapped[Optional[str]] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    check: Mapped["CSPMCheck"] = relationship("CSPMCheck", back_populates="findings", foreign_keys=[check_id])
    cloud_account: Mapped["ProductCloudAccount"] = relationship("ProductCloudAccount", back_populates="cspm_findings", foreign_keys=[cloud_account_id])
    product: Mapped[Optional["ProductRegistryProduct"]] = relationship("ProductRegistryProduct", back_populates="cspm_findings", foreign_keys=[product_id])


# ── Environment Templates ────────────────────────────────────────────────────

class EnvironmentTemplate(Base):
    """Pre-built environment topology templates (K8s, CSPM, VM, HR, etc.)."""
    __tablename__ = "environment_templates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255))
    slug: Mapped[str] = mapped_column(String(100), unique=True)
    category: Mapped[str] = mapped_column(String(50))  # cspm, k8s, vm, cmdb, hr, asm, product
    description: Mapped[str] = mapped_column(Text, default="")
    topology: Mapped[dict] = mapped_column(JSONB, default=dict)  # nodes + edges for ReactFlow
    default_log_sources: Mapped[list] = mapped_column(JSONB, default=list)
    default_settings: Mapped[dict] = mapped_column(JSONB, default=dict)
    icon: Mapped[Optional[str]] = mapped_column(String(50))
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


# ── Environment Threat Profile ────────────────────────────────────────────────

class EnvironmentThreatProfile(Base):
    """Custom threat profiles (CVEs, TTPs, actors) attached to environments."""
    __tablename__ = "environment_threat_profiles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    environment_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("environments.id", ondelete="CASCADE"))
    profile_type: Mapped[str] = mapped_column(String(30))  # cve | ttp | actor | ioc
    name: Mapped[str] = mapped_column(String(255))
    data: Mapped[dict] = mapped_column(JSONB, default=dict)  # full profile payload
    source: Mapped[str] = mapped_column(String(50), default="manual")  # manual | upload | tip_api | mcp
    created_by: Mapped[Optional[str]] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    environment: Mapped["Environment"] = relationship("Environment", back_populates="threat_profiles")


# ── Sigma Rule Library ─────────────────────────────────────────────────────────

class SigmaRuleSource(Base):
    """Registered open-source Sigma rule repositories."""
    __tablename__ = "sigma_rule_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255))
    github_url: Mapped[str] = mapped_column(String(500))
    github_api_path: Mapped[str] = mapped_column(String(500))  # API path for fetching
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_synced_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    rule_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    rules: Mapped[list["SigmaLibraryRule"]] = relationship("SigmaLibraryRule", back_populates="source")


class SigmaLibraryRule(Base):
    """Sigma rule stored locally from open-source repos."""
    __tablename__ = "sigma_library_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    source_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("sigma_rule_sources.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    rule_yaml: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="stable")  # stable|experimental|deprecated
    level: Mapped[str] = mapped_column(String(20), default="medium")  # critical|high|medium|low|informational
    category: Mapped[Optional[str]] = mapped_column(String(100))
    product: Mapped[Optional[str]] = mapped_column(String(100))
    service: Mapped[Optional[str]] = mapped_column(String(100))
    technique_ids: Mapped[list] = mapped_column(JSONB, default=list)  # ["T1059", ...]
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    file_path: Mapped[Optional[str]] = mapped_column(String(500))
    sha256: Mapped[Optional[str]] = mapped_column(String(64))  # for dedup
    added_by: Mapped[Optional[str]] = mapped_column(String(255))  # null = synced, email = manual
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    source: Mapped[Optional["SigmaRuleSource"]] = relationship("SigmaRuleSource", back_populates="rules")


class SessionSigmaRule(Base):
    """Rules deployed to a specific simulation session."""
    __tablename__ = "session_sigma_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    session_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("simulation_sessions.id", ondelete="CASCADE"))
    sigma_rule_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("sigma_library_rules.id", ondelete="CASCADE"))
    deployed_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    deployed_by: Mapped[Optional[str]] = mapped_column(String(255))

    rule: Mapped["SigmaLibraryRule"] = relationship("SigmaLibraryRule")


# ── Data Normalization Schemas ────────────────────────────────────────────────

class NormalizationSchema(Base):
    """SIEM data normalization / field mapping schema with versioning."""
    __tablename__ = "normalization_schemas"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255))
    version_label: Mapped[str] = mapped_column(String(100))  # user-defined e.g. "Splunk CIM v4.2"
    siem_platform: Mapped[str] = mapped_column(String(50))  # splunk|elastic|sentinel|qradar|sumo|custom
    description: Mapped[str] = mapped_column(Text, default="")
    fields: Mapped[list] = mapped_column(JSONB, default=list)  # [{name, siem_name, type, description, example}]
    datasets: Mapped[list] = mapped_column(JSONB, default=list)  # dataset/index names
    data_models: Mapped[list] = mapped_column(JSONB, default=list)  # data model definitions
    ai_parsed: Mapped[bool] = mapped_column(Boolean, default=False)
    ai_parse_notes: Mapped[Optional[str]] = mapped_column(Text)
    source_file_name: Mapped[Optional[str]] = mapped_column(String(255))
    source_format: Mapped[Optional[str]] = mapped_column(String(20))  # json|csv|tsv|pdf
    created_by: Mapped[Optional[str]] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    versions: Mapped[list["NormalizationSchemaVersion"]] = relationship("NormalizationSchemaVersion", back_populates="schema", order_by="NormalizationSchemaVersion.version_num.desc()")


class NormalizationSchemaVersion(Base):
    """Immutable snapshot of a normalization schema at a point in time."""
    __tablename__ = "normalization_schema_versions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    schema_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("normalization_schemas.id", ondelete="CASCADE"))
    version_num: Mapped[int] = mapped_column(Integer, default=1)
    version_label: Mapped[str] = mapped_column(String(100))
    fields_snapshot: Mapped[list] = mapped_column(JSONB, default=list)
    datasets_snapshot: Mapped[list] = mapped_column(JSONB, default=list)
    data_models_snapshot: Mapped[list] = mapped_column(JSONB, default=list)
    change_summary: Mapped[Optional[str]] = mapped_column(Text)
    created_by: Mapped[Optional[str]] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    schema: Mapped["NormalizationSchema"] = relationship("NormalizationSchema", back_populates="versions")


# ── LLM Usage Log ─────────────────────────────────────────────────────────────

class LLMUsageLog(Base):
    """Per-call LLM usage tracking for cost monitoring and auditing."""
    __tablename__ = "llm_usage_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    function_name: Mapped[str] = mapped_column(String(50), nullable=False)
    provider: Mapped[str] = mapped_column(String(30), nullable=False)
    model_id: Mapped[str] = mapped_column(String(100), nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="success")  # success|error|cached
    error_msg: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    request_context: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())


# ── AI Guardrail Config ───────────────────────────────────────────────────────

class AIGuardrailConfig(Base):
    """Per-function AI guardrail configuration."""
    __tablename__ = "ai_guardrail_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    function_name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    max_input_tokens: Mapped[int] = mapped_column(Integer, default=32000)
    max_output_tokens: Mapped[int] = mapped_column(Integer, default=8192)
    rate_limit_per_minute: Mapped[int] = mapped_column(Integer, default=60)  # 0 = unlimited
    block_patterns: Mapped[list] = mapped_column(JSONB, default=list)
    require_json_output: Mapped[bool] = mapped_column(Boolean, default=False)
    pii_masking_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    system_prompt_override: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    notes: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())


# ── Vendor Emulation — Response Actions ──────────────────────────────────────

class ResponseAction(Base):
    """Immutable audit log of SOAR actions executed against simulated vendor APIs."""
    __tablename__ = "response_actions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("simulation_sessions.id", ondelete="CASCADE")
    )
    action_type: Mapped[str] = mapped_column(String(60))   # block_ioc, isolate_host, etc.
    actor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)   # "joti_soar" | "analyst@corp.com"
    target: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)  # hostname / IP / hash
    params: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    result: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)   # {success, message, state_change}
    persona_key: Mapped[Optional[str]] = mapped_column(String(60), nullable=True)  # which vendor API was called
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())


# ── Vendor Emulation — Deployed Detections ───────────────────────────────────

class DeployedDetection(Base):
    """Sigma/SPL/KQL rules deployed to the simulated SIEM for validation."""
    __tablename__ = "deployed_detections"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    session_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("simulation_sessions.id", ondelete="CASCADE"), nullable=True
    )
    environment_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("environments.id", ondelete="CASCADE"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(500))
    sigma_yaml: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    query_spl: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    query_kql: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    technique_ids: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # ["T1059.001", ...]
    status: Mapped[str] = mapped_column(String(30), default="deployed")  # deployed|disabled|testing
    validation: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)   # {fired, matched_count, fp_count, tested_at}
    deployed_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())


# ── Tabletop Exercises ────────────────────────────────────────────────────────

class TabletopExercise(Base):
    """Multi-phase tabletop exercise with injects, decision gates, and scoring."""
    __tablename__ = "tabletop_exercises"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scenario_key: Mapped[Optional[str]] = mapped_column(String(60), nullable=True)   # built-in scenario template
    script: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)   # [{phase, inject, decisions, timer_minutes}]
    status: Mapped[str] = mapped_column(String(30), default="draft")  # draft|running|completed|cancelled
    session_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("simulation_sessions.id", ondelete="SET NULL"), nullable=True
    )
    environment_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("environments.id", ondelete="SET NULL"), nullable=True
    )
    team_size: Mapped[int] = mapped_column(Integer, default=4)
    current_phase: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    responses: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # [{phase, decision, rationale, time_seconds, score}]
    report: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)    # after-action report
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now, server_default=func.now())
