"""LLM usage tracking and AI guardrail configs

Revision ID: 006
Revises: 005
Create Date: 2026-06-02
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # LLM per-call usage log
    op.create_table(
        "llm_usage_logs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("function_name", sa.String(50), nullable=False),
        sa.Column("provider", sa.String(30), nullable=False),
        sa.Column("model_id", sa.String(100), nullable=False),
        sa.Column("input_tokens", sa.Integer, default=0),
        sa.Column("output_tokens", sa.Integer, default=0),
        sa.Column("latency_ms", sa.Integer, default=0),
        sa.Column("status", sa.String(20), default="success"),
        sa.Column("error_msg", sa.String(500), nullable=True),
        sa.Column("user_id", sa.String(255), nullable=True),
        sa.Column("request_context", JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_llm_usage_logs_function_name", "llm_usage_logs", ["function_name"])
    op.create_index("ix_llm_usage_logs_created_at", "llm_usage_logs", ["created_at"])
    op.create_index("ix_llm_usage_logs_provider", "llm_usage_logs", ["provider"])

    # Per-function AI guardrail configuration
    op.create_table(
        "ai_guardrail_configs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("function_name", sa.String(50), unique=True, nullable=False),
        sa.Column("enabled", sa.Boolean, default=True),
        sa.Column("max_input_tokens", sa.Integer, default=32000),
        sa.Column("max_output_tokens", sa.Integer, default=8192),
        sa.Column("rate_limit_per_minute", sa.Integer, default=60),
        sa.Column("block_patterns", JSONB, nullable=True),
        sa.Column("require_json_output", sa.Boolean, default=False),
        sa.Column("pii_masking_enabled", sa.Boolean, default=False),
        sa.Column("system_prompt_override", sa.Text, nullable=True),
        sa.Column("notes", sa.String(500), default=""),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_ai_guardrail_configs_function_name",
        "ai_guardrail_configs",
        ["function_name"],
        unique=True,
    )

    # Seed default guardrail configs for high-risk / high-volume functions
    conn = op.get_bind()
    defaults = [
        # LOG_GENERATION — high volume, no PII needed, JSON not required
        ("LOG_GENERATION", True, 16000, 8192, 120, False, False),
        # DETECTION_GENERATE — medium volume, JSON output needed
        ("DETECTION_GENERATE", True, 32000, 8192, 30, False, False),
        # NORMALIZATION_PARSE — medium volume, JSON output needed
        ("NORMALIZATION_PARSE", True, 32000, 8192, 30, False, False),
        # THREAT_ENRICH — medium volume, JSON output needed
        ("THREAT_ENRICH", True, 32000, 8192, 30, False, False),
        # EXERCISE_REPORT — low volume, large output
        ("EXERCISE_REPORT", True, 64000, 16000, 10, False, False),
    ]

    for fn, enabled, max_in, max_out, rate, pii, req_json in defaults:
        conn.execute(
            sa.text(
                "INSERT INTO ai_guardrail_configs "
                "(function_name, enabled, max_input_tokens, max_output_tokens, "
                "rate_limit_per_minute, pii_masking_enabled, require_json_output, "
                "block_patterns, notes) "
                "VALUES (:fn, :enabled, :max_in, :max_out, :rate, :pii, :req_json, "
                "cast(:patterns as jsonb), :notes) "
                "ON CONFLICT (function_name) DO NOTHING"
            ),
            {
                "fn": fn,
                "enabled": enabled,
                "max_in": max_in,
                "max_out": max_out,
                "rate": rate,
                "pii": pii,
                "req_json": req_json,
                "patterns": "[]",
                "notes": "Default config seeded on install",
            }
        )


def downgrade() -> None:
    op.drop_table("ai_guardrail_configs")
    op.drop_table("llm_usage_logs")
