"""Merge legacy api_keys branch into main chain.

Revision ID: 010_merge_legacy_branch
Revises: 009_conversation_context, 003_api_keys_legacy
Create Date: 2026-06-05
"""
from typing import Sequence, Union

revision: str = "010_merge_legacy_branch"
down_revision: Union[str, Sequence[str], None] = (
    "009_conversation_context",
    "003_api_keys_legacy",
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass  # merge point — no schema changes


def downgrade() -> None:
    pass
