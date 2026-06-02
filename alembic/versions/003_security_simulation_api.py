"""Security simulation API — EDR endpoints, users, containment actions, block lists.

Revision ID: 003
Revises: 002
Create Date: 2026-06-02
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "simulated_endpoints",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("environment_id", UUID(as_uuid=True), sa.ForeignKey("environments.id", ondelete="CASCADE"), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("os_platform", sa.String(50), server_default="windows"),
        sa.Column("os_version", sa.String(100), nullable=True),
        sa.Column("edr_vendor", sa.String(50), server_default="crowdstrike"),
        sa.Column("agent_version", sa.String(50), nullable=True),
        sa.Column("status", sa.String(30), server_default="online"),
        sa.Column("last_seen", sa.DateTime, server_default=sa.func.now()),
        sa.Column("tags", JSONB, nullable=True),
        sa.Column("extra", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index("ix_simulated_endpoints_env", "simulated_endpoints", ["environment_id"])
    op.create_index("ix_simulated_endpoints_status", "simulated_endpoints", ["status"])

    op.create_table(
        "simulated_users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("environment_id", UUID(as_uuid=True), sa.ForeignKey("environments.id", ondelete="CASCADE"), nullable=True),
        sa.Column("username", sa.String(255), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=True),
        sa.Column("department", sa.String(100), nullable=True),
        sa.Column("title", sa.String(100), nullable=True),
        sa.Column("identity_vendor", sa.String(50), server_default="okta"),
        sa.Column("status", sa.String(30), server_default="active"),
        sa.Column("mfa_enrolled", sa.Boolean, server_default="true"),
        sa.Column("risk_level", sa.String(20), server_default="low"),
        sa.Column("last_login", sa.DateTime, nullable=True),
        sa.Column("attributes", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index("ix_simulated_users_env", "simulated_users", ["environment_id"])
    op.create_index("ix_simulated_users_status", "simulated_users", ["status"])

    op.create_table(
        "containment_actions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("environment_id", UUID(as_uuid=True), sa.ForeignKey("environments.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action_type", sa.String(50), nullable=False),
        sa.Column("target_type", sa.String(30), nullable=False),
        sa.Column("target_value", sa.String(500), nullable=False),
        sa.Column("target_id", sa.String(255), nullable=True),
        sa.Column("requester", sa.String(255), server_default="api"),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("status", sa.String(20), server_default="success"),
        sa.Column("result_detail", JSONB, nullable=True),
        sa.Column("reversed_at", sa.DateTime, nullable=True),
        sa.Column("reversed_by", sa.String(255), nullable=True),
        sa.Column("executed_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index("ix_containment_actions_env", "containment_actions", ["environment_id"])
    op.create_index("ix_containment_actions_type", "containment_actions", ["action_type"])
    op.create_index("ix_containment_actions_target", "containment_actions", ["target_value"])

    op.create_table(
        "block_list_entries",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("environment_id", UUID(as_uuid=True), sa.ForeignKey("environments.id", ondelete="CASCADE"), nullable=True),
        sa.Column("block_type", sa.String(30), nullable=False),
        sa.Column("value", sa.String(500), nullable=False),
        sa.Column("hash_type", sa.String(10), nullable=True),
        sa.Column("direction", sa.String(10), nullable=True),
        sa.Column("vendor", sa.String(50), server_default="crowdstrike"),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("comment", sa.Text, nullable=True),
        sa.Column("added_by", sa.String(255), server_default="api"),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("expires_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index("ix_block_list_type_value", "block_list_entries", ["block_type", "value"])
    op.create_index("ix_block_list_active", "block_list_entries", ["is_active"])


def downgrade() -> None:
    op.drop_table("block_list_entries")
    op.drop_table("containment_actions")
    op.drop_table("simulated_users")
    op.drop_table("simulated_endpoints")
