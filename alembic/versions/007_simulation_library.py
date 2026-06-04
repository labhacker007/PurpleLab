"""Simulation library — TTP event templates and scenario snapshots

Revision ID: 007_simulation_library
Revises: 006
Create Date: 2026-06-04
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB

revision = "007_simulation_library"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Ensure pgcrypto is available for gen_random_uuid()
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # ── ttp_event_templates ──────────────────────────────────────────────────
    op.create_table(
        "ttp_event_templates",
        sa.Column(
            "id",
            PGUUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("technique_id", sa.String(20), nullable=False),
        sa.Column("tactic", sa.String(50), nullable=True),
        sa.Column("log_source", sa.String(50), nullable=False),
        sa.Column(
            "severity",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'medium'"),
        ),
        sa.Column(
            "title_template",
            sa.String(500),
            nullable=False,
            server_default=sa.text("''"),
        ),
        sa.Column(
            "payload_template",
            JSONB,
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("variables", JSONB, nullable=True),
        sa.Column(
            "is_builtin",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "hit_count",
            sa.Integer,
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP,
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    op.create_index(
        "ix_ttp_event_templates_technique_id",
        "ttp_event_templates",
        ["technique_id"],
    )

    # ── simulation_scenarios ─────────────────────────────────────────────────
    op.create_table(
        "simulation_scenarios",
        sa.Column(
            "id",
            PGUUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("threat_actor_name", sa.String(255), nullable=True),
        sa.Column(
            "technique_ids",
            JSONB,
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column(
            "events",
            JSONB,
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column("asset_snapshot", JSONB, nullable=True),
        sa.Column("ioc_snapshot", JSONB, nullable=True),
        sa.Column(
            "source_session_id",
            PGUUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "environment_id",
            PGUUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "use_count",
            sa.Integer,
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP,
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP,
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )


def downgrade() -> None:
    op.drop_table("simulation_scenarios")
    op.drop_index(
        "ix_ttp_event_templates_technique_id",
        table_name="ttp_event_templates",
    )
    op.drop_table("ttp_event_templates")
