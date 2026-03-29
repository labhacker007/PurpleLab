"""Add missing tables and columns — model_function_configs, hitl tables,
organizations, users, audit_logs, pipeline tables, use_cases, reports,
and stopped_at on simulation_sessions.

Revision ID: 002
Revises: 001
Create Date: 2026-03-29
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

# revision identifiers, used by Alembic.
revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Model Function Configs ─────────────────────────────────────────────
    op.create_table(
        "model_function_configs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("function_name", sa.String(50), nullable=False, unique=True),
        sa.Column("provider", sa.String(20), nullable=False),
        sa.Column("model_id", sa.String(100), nullable=False),
        sa.Column("temperature", sa.Float, server_default="0.3"),
        sa.Column("max_tokens", sa.Integer, server_default="4096"),
        sa.Column("base_url", sa.String(500), server_default=""),
        sa.Column("api_key_override", sa.Text, server_default=""),
        sa.Column("extra_params", JSONB, nullable=True),
        sa.Column("fallback_config_json", sa.Text, nullable=True),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )

    # ── HITL Approval Requests ─────────────────────────────────────────────
    op.create_table(
        "hitl_approval_requests",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("action_type", sa.String(100), nullable=False),
        sa.Column("action_payload", JSONB, nullable=True),
        sa.Column("level", sa.Integer, server_default="1"),
        sa.Column("status", sa.String(20), server_default="pending"),
        sa.Column("requested_by", sa.String(255), server_default="agent"),
        sa.Column("reviewed_by", sa.String(255), nullable=True),
        sa.Column("review_note", sa.Text, server_default=""),
        sa.Column("magic_link_token", sa.String(128), unique=True, nullable=True),
        sa.Column("magic_link_expires_at", sa.DateTime, nullable=True),
        sa.Column("notification_channels", JSONB, nullable=True),
        sa.Column("notifications_sent", JSONB, nullable=True),
        sa.Column("auto_approve_after_seconds", sa.Integer, nullable=True),
        sa.Column("context", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime, nullable=True),
    )

    # ── HITL Action Configs ────────────────────────────────────────────────
    op.create_table(
        "hitl_action_configs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("action_type", sa.String(100), nullable=False, unique=True),
        sa.Column("level", sa.Integer, server_default="1"),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("notification_channels", JSONB, nullable=True),
        sa.Column("auto_approve_after_seconds", sa.Integer, nullable=True),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )

    # ── Organizations ──────────────────────────────────────────────────────
    op.create_table(
        "organizations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False, unique=True),
        sa.Column("plan", sa.String(20), server_default="free"),
        sa.Column("settings", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )

    # ── Users ──────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False, unique=True),
        sa.Column("hashed_password", sa.Text, nullable=False),
        sa.Column("full_name", sa.String(200), server_default=""),
        sa.Column("role", sa.String(20), server_default="analyst"),
        sa.Column(
            "org_id",
            UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("is_superadmin", sa.Boolean, server_default="false"),
        sa.Column("api_key", sa.String(128), unique=True, nullable=True),
        sa.Column("last_login_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )

    # ── Audit Logs ─────────────────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(100), nullable=True),
        sa.Column("resource_id", sa.String(200), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("payload", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )

    # ── Pipeline Configs ───────────────────────────────────────────────────
    op.create_table(
        "pipeline_configs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("schedule_cron", sa.String(100), nullable=True),
        sa.Column("enabled", sa.Boolean, server_default="true"),
        sa.Column("chain_ids", JSONB, nullable=True),
        sa.Column(
            "siem_connection_id",
            UUID(as_uuid=True),
            sa.ForeignKey("siem_connections.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("hitl_level_override", sa.Integer, nullable=True),
        sa.Column("notify_slack_channel", sa.String(200), server_default=""),
        sa.Column(
            "created_by",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )

    # ── Pipeline Runs ──────────────────────────────────────────────────────
    op.create_table(
        "pipeline_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "pipeline_id",
            UUID(as_uuid=True),
            sa.ForeignKey("pipeline_configs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(20), server_default="pending"),
        sa.Column("triggered_by", sa.String(50), server_default="scheduler"),
        sa.Column("chains_run", sa.Integer, server_default="0"),
        sa.Column("events_generated", sa.Integer, server_default="0"),
        sa.Column("detections_fired", sa.Integer, server_default="0"),
        sa.Column("des_before", sa.Float, nullable=True),
        sa.Column("des_after", sa.Float, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("report_url", sa.String(500), nullable=True),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )

    # ── Use Cases ──────────────────────────────────────────────────────────
    op.create_table(
        "use_cases",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("technique_ids", JSONB, nullable=True),
        sa.Column("tactic", sa.String(100), server_default=""),
        sa.Column("threat_actor", sa.String(200), server_default=""),
        sa.Column("attack_chain_id", sa.String(100), server_default=""),
        sa.Column("expected_log_sources", JSONB, nullable=True),
        sa.Column("severity", sa.String(20), server_default="high"),
        sa.Column("tags", JSONB, nullable=True),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("is_builtin", sa.Boolean, server_default="false"),
        sa.Column("last_validated_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )

    # ── Use Case Runs ──────────────────────────────────────────────────────
    op.create_table(
        "use_case_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "use_case_id",
            UUID(as_uuid=True),
            sa.ForeignKey("use_cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(20), server_default="pending"),
        sa.Column("triggered_by", sa.String(50), server_default="manual"),
        sa.Column("events_generated", sa.Integer, server_default="0"),
        sa.Column("rules_tested", sa.Integer, server_default="0"),
        sa.Column("rules_fired", sa.Integer, server_default="0"),
        sa.Column("pass_rate", sa.Float, nullable=True),
        sa.Column("run_details", JSONB, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )

    # ── Reports ────────────────────────────────────────────────────────────
    op.create_table(
        "reports",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("type", sa.String(30), nullable=False),
        sa.Column("format", sa.String(10), server_default="json"),
        sa.Column("status", sa.String(20), server_default="generating"),
        sa.Column("data", JSONB, nullable=True),
        sa.Column("created_by", sa.String(200), nullable=True),
        sa.Column("file_path", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )

    # ── Add stopped_at column to simulation_sessions ───────────────────────
    op.add_column(
        "simulation_sessions",
        sa.Column("stopped_at", sa.DateTime, nullable=True),
    )

    # ── Indexes ────────────────────────────────────────────────────────────
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_org_id", "users", ["org_id"])
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_index("ix_pipeline_runs_pipeline_id", "pipeline_runs", ["pipeline_id"])
    op.create_index("ix_use_case_runs_use_case_id", "use_case_runs", ["use_case_id"])
    op.create_index("ix_hitl_approval_requests_status", "hitl_approval_requests", ["status"])


def downgrade() -> None:
    # Drop indexes first
    op.drop_index("ix_hitl_approval_requests_status", table_name="hitl_approval_requests")
    op.drop_index("ix_use_case_runs_use_case_id", table_name="use_case_runs")
    op.drop_index("ix_pipeline_runs_pipeline_id", table_name="pipeline_runs")
    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_action", table_name="audit_logs")
    op.drop_index("ix_audit_logs_user_id", table_name="audit_logs")
    op.drop_index("ix_users_org_id", table_name="users")
    op.drop_index("ix_users_email", table_name="users")

    # Remove added column
    op.drop_column("simulation_sessions", "stopped_at")

    # Drop tables in reverse dependency order
    op.drop_table("reports")
    op.drop_table("use_case_runs")
    op.drop_table("use_cases")
    op.drop_table("pipeline_runs")
    op.drop_table("pipeline_configs")
    op.drop_table("audit_logs")
    op.drop_table("users")
    op.drop_table("organizations")
    op.drop_table("hitl_action_configs")
    op.drop_table("hitl_approval_requests")
    op.drop_table("model_function_configs")
