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
