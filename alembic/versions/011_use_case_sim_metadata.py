"""Add sim_metadata JSONB column to use_cases.

Revision ID: 011_use_case_sim_metadata
Revises: 010_merge_legacy_branch
Create Date: 2026-06-09
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "011_use_case_sim_metadata"
down_revision: Union[str, Sequence[str], None] = "010_merge_legacy_branch"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "use_cases",
        sa.Column("sim_metadata", JSONB, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("use_cases", "sim_metadata")
