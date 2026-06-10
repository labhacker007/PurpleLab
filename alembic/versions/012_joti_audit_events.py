"""Add joti_audit_events table for Joti TIP audit log forwarding.

Revision ID: 012_joti_audit_events
Revises: 011_use_case_sim_metadata
Create Date: 2026-06-10
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "012_joti_audit_events"
down_revision: Union[str, Sequence[str], None] = "011_use_case_sim_metadata"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Use raw SQL with IF NOT EXISTS to be idempotent (table may exist from create_all)
    op.execute("""
        CREATE TABLE IF NOT EXISTS joti_audit_events (
            id UUID NOT NULL PRIMARY KEY,
            joti_event_id INTEGER,
            event_type VARCHAR(64) NOT NULL,
            action TEXT NOT NULL DEFAULT '',
            user_email VARCHAR(256),
            ip_address VARCHAR(64),
            resource_type VARCHAR(64),
            resource_id INTEGER,
            correlation_id VARCHAR(128),
            details JSONB,
            created_at_joti TIMESTAMP WITHOUT TIME ZONE,
            received_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now()
        )
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_joti_audit_events_event_type
            ON joti_audit_events (event_type)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_joti_audit_events_joti_event_id
            ON joti_audit_events (joti_event_id)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_joti_audit_events_received_at
            ON joti_audit_events (received_at)
    """)


def downgrade() -> None:
    op.drop_table("joti_audit_events")
