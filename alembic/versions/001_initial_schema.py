"""Initial schema — all tables for Joti Sim v2.

Revision ID: 001
Revises: None
Create Date: 2026-03-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Environments
    op.create_table(
        "environments",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("siem_platform", sa.String(50), server_default="splunk"),
        sa.Column("log_sources", JSONB, nullable=True),
        sa.Column("settings", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )

    # Conversations
    op.create_table(
        "conversations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("title", sa.String(255), server_default="New Conversation"),
        sa.Column("environment_id", UUID(as_uuid=True), sa.ForeignKey("environments.id"), nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )

    # Messages
    op.create_table(
        "messages",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("conversation_id", UUID(as_uuid=True), sa.ForeignKey("conversations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("content", sa.Text, server_default=""),
        sa.Column("tool_calls", JSONB, nullable=True),
        sa.Column("tool_results", JSONB, nullable=True),
        sa.Column("metadata", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )

    # SIEM Connections
    op.create_table(
        "siem_connections",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("environment_id", UUID(as_uuid=True), sa.ForeignKey("environments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("siem_type", sa.String(50), nullable=False),
        sa.Column("base_url", sa.String(500), nullable=False),
        sa.Column("encrypted_credentials", sa.Text, server_default=""),
        sa.Column("settings", JSONB, nullable=True),
        sa.Column("is_connected", sa.Boolean, server_default="false"),
        sa.Column("last_sync_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )

    # Imported Rules
    op.create_table(
        "imported_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("environment_id", UUID(as_uuid=True), sa.ForeignKey("environments.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("language", sa.String(20), nullable=False),
        sa.Column("source_query", sa.Text, server_default=""),
        sa.Column("severity", sa.String(20), server_default="medium"),
        sa.Column("mitre_techniques", JSONB, nullable=True),
        sa.Column("enabled", sa.Boolean, server_default="true"),
        sa.Column("source", sa.String(50), server_default="manual"),
        sa.Column("metadata", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )

    # Threat Actors
    op.create_table(
        "threat_actors",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), unique=True, nullable=False),
        sa.Column("aliases", JSONB, nullable=True),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("mitre_groups", JSONB, nullable=True),
        sa.Column("techniques", JSONB, nullable=True),
        sa.Column("ttps", JSONB, nullable=True),
        sa.Column("source", sa.String(50), server_default="mitre"),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )

    # MITRE Techniques
    op.create_table(
        "mitre_techniques",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("technique_id", sa.String(20), unique=True, nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("tactic", sa.String(50), nullable=False),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("platforms", JSONB, nullable=True),
        sa.Column("data_sources", JSONB, nullable=True),
        sa.Column("detection_guidance", sa.Text, server_default=""),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )

    # Test Runs
    op.create_table(
        "test_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("environment_id", UUID(as_uuid=True), sa.ForeignKey("environments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(20), server_default="pending"),
        sa.Column("total_rules", sa.Integer, server_default="0"),
        sa.Column("rules_passed", sa.Integer, server_default="0"),
        sa.Column("rules_failed", sa.Integer, server_default="0"),
        sa.Column("coverage_pct", sa.Float, server_default="0.0"),
        sa.Column("config", JSONB, nullable=True),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )

    # Rule Test Results
    op.create_table(
        "rule_test_results",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("test_run_id", UUID(as_uuid=True), sa.ForeignKey("test_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_id", UUID(as_uuid=True), sa.ForeignKey("imported_rules.id", ondelete="CASCADE"), nullable=False),
        sa.Column("passed", sa.Boolean, server_default="false"),
        sa.Column("matched_events", sa.Integer, server_default="0"),
        sa.Column("false_positives", sa.Integer, server_default="0"),
        sa.Column("execution_time_ms", sa.Float, server_default="0.0"),
        sa.Column("details", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )

    # Simulation Sessions
    op.create_table(
        "simulation_sessions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), server_default="Untitled Session"),
        sa.Column("config", JSONB, nullable=True),
        sa.Column("status", sa.String(20), server_default="stopped"),
        sa.Column("events_sent", sa.Integer, server_default="0"),
        sa.Column("errors", sa.Integer, server_default="0"),
        sa.Column("last_event_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )

    # Generated Events
    op.create_table(
        "generated_events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("session_id", UUID(as_uuid=True), sa.ForeignKey("simulation_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("product_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("title", sa.String(500), server_default=""),
        sa.Column("payload", JSONB, nullable=True),
        sa.Column("target_url", sa.String(500), server_default=""),
        sa.Column("status_code", sa.Integer, server_default="0"),
        sa.Column("success", sa.Boolean, server_default="false"),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )

    # Log Source Schemas
    op.create_table(
        "log_source_schemas",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("source_type", sa.String(50), nullable=False),
        sa.Column("schema_definition", JSONB, nullable=True),
        sa.Column("sample_event", JSONB, nullable=True),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )

    # Indexes
    op.create_index("ix_messages_conversation_id", "messages", ["conversation_id"])
    op.create_index("ix_generated_events_session_id", "generated_events", ["session_id"])
    op.create_index("ix_generated_events_created_at", "generated_events", ["created_at"])
    op.create_index("ix_imported_rules_language", "imported_rules", ["language"])
    op.create_index("ix_imported_rules_severity", "imported_rules", ["severity"])
    op.create_index("ix_mitre_techniques_technique_id", "mitre_techniques", ["technique_id"])
    op.create_index("ix_mitre_techniques_tactic", "mitre_techniques", ["tactic"])


def downgrade() -> None:
    op.drop_table("log_source_schemas")
    op.drop_table("generated_events")
    op.drop_table("simulation_sessions")
    op.drop_table("rule_test_results")
    op.drop_table("test_runs")
    op.drop_table("mitre_techniques")
    op.drop_table("threat_actors")
    op.drop_table("imported_rules")
    op.drop_table("siem_connections")
    op.drop_table("messages")
    op.drop_table("conversations")
    op.drop_table("environments")
