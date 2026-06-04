"""Add product persona columns + response_actions + deployed_detections + tabletop tables

Revision ID: 008_product_personas
Revises: 007_simulation_library
Create Date: 2026-06-04
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "008_product_personas"
down_revision = "007_simulation_library"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Extend environments with persona columns ────────────────────────────
    op.add_column("environments", sa.Column("edr_persona",      sa.String(60), nullable=True))
    op.add_column("environments", sa.Column("siem_persona",     sa.String(60), nullable=True))
    op.add_column("environments", sa.Column("idp_persona",      sa.String(60), nullable=True))
    op.add_column("environments", sa.Column("firewall_persona",  sa.String(60), nullable=True))
    op.add_column("environments", sa.Column("network_persona",   sa.String(60), nullable=True))

    # Backfill defaults from existing siem_platform column
    op.execute("""
        UPDATE environments
        SET edr_persona  = 'crowdstrike_falcon',
            siem_persona = CASE
                WHEN siem_platform = 'splunk'   THEN 'splunk_es'
                WHEN siem_platform = 'sentinel' THEN 'microsoft_sentinel'
                WHEN siem_platform = 'elastic'  THEN 'elastic_siem'
                WHEN siem_platform = 'qradar'   THEN 'qradar'
                ELSE 'splunk_es'
            END,
            idp_persona      = 'okta',
            firewall_persona = 'palo_alto_ngfw'
        WHERE edr_persona IS NULL
    """)

    # ── Response actions audit table ────────────────────────────────────────
    op.create_table(
        "response_actions",
        sa.Column("id",          UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("session_id",  UUID(as_uuid=True), sa.ForeignKey("simulation_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action_type", sa.String(60),  nullable=False),   # block_ioc, isolate_host, etc.
        sa.Column("actor",       sa.String(255), nullable=True),    # "joti_soar" | "analyst@corp.com"
        sa.Column("target",      sa.String(500), nullable=True),    # hostname / IP / hash
        sa.Column("params",      JSONB,          nullable=True),
        sa.Column("result",      JSONB,          nullable=True),    # {success, message, state_change}
        sa.Column("persona_key", sa.String(60),  nullable=True),    # which vendor API was called
        sa.Column("created_at",  sa.DateTime,    server_default=sa.text("now()")),
    )
    op.create_index("ix_response_actions_session", "response_actions", ["session_id"])

    # ── Deployed detections (simulated SIEM rules) ──────────────────────────
    op.create_table(
        "deployed_detections",
        sa.Column("id",           UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("session_id",   UUID(as_uuid=True), sa.ForeignKey("simulation_sessions.id", ondelete="CASCADE"), nullable=True),
        sa.Column("environment_id", UUID(as_uuid=True), sa.ForeignKey("environments.id", ondelete="CASCADE"), nullable=True),
        sa.Column("name",         sa.String(500),  nullable=False),
        sa.Column("sigma_yaml",   sa.Text,         nullable=True),
        sa.Column("query_spl",    sa.Text,         nullable=True),
        sa.Column("query_kql",    sa.Text,         nullable=True),
        sa.Column("technique_ids", JSONB,          nullable=True),   # ["T1059.001", ...]
        sa.Column("status",       sa.String(30),   server_default="deployed"),  # deployed|disabled|testing
        sa.Column("validation",   JSONB,           nullable=True),   # {fired, matched_count, fp_count, tested_at}
        sa.Column("deployed_by",  sa.String(255),  nullable=True),
        sa.Column("created_at",   sa.DateTime,     server_default=sa.text("now()")),
        sa.Column("updated_at",   sa.DateTime,     server_default=sa.text("now()")),
    )
    op.create_index("ix_deployed_detections_session",     "deployed_detections", ["session_id"])
    op.create_index("ix_deployed_detections_environment", "deployed_detections", ["environment_id"])

    # ── Tabletop exercise definitions ───────────────────────────────────────
    op.create_table(
        "tabletop_exercises",
        sa.Column("id",           UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name",         sa.String(255),  nullable=False),
        sa.Column("description",  sa.Text,         nullable=True),
        sa.Column("scenario_key", sa.String(60),   nullable=True),   # built-in scenario template
        sa.Column("script",       JSONB,           nullable=True),   # [{phase, inject, decisions, timer_minutes}]
        sa.Column("status",       sa.String(30),   server_default="draft"),  # draft|running|completed|cancelled
        sa.Column("session_id",   UUID(as_uuid=True), sa.ForeignKey("simulation_sessions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("environment_id", UUID(as_uuid=True), sa.ForeignKey("environments.id",  ondelete="SET NULL"), nullable=True),
        sa.Column("team_size",    sa.Integer,      server_default="4"),
        sa.Column("current_phase", sa.Integer,     server_default="0"),
        sa.Column("started_at",   sa.DateTime,     nullable=True),
        sa.Column("ended_at",     sa.DateTime,     nullable=True),
        sa.Column("score",        sa.Float,        nullable=True),
        sa.Column("responses",    JSONB,           nullable=True),   # [{phase, decision, rationale, time_seconds, score}]
        sa.Column("report",       JSONB,           nullable=True),   # after-action report
        sa.Column("created_at",   sa.DateTime,     server_default=sa.text("now()")),
        sa.Column("updated_at",   sa.DateTime,     server_default=sa.text("now()")),
    )
    op.create_index("ix_tabletop_exercises_status", "tabletop_exercises", ["status"])


def downgrade() -> None:
    op.drop_table("tabletop_exercises")
    op.drop_table("deployed_detections")
    op.drop_table("response_actions")
    for col in ["network_persona", "firewall_persona", "idp_persona", "siem_persona", "edr_persona"]:
        op.drop_column("environments", col)
