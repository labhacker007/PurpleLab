"""Retired migration — superseded by 003_security_simulation_api.py.

This file is intentionally disconnected from the main migration chain.
It exists only as a historical record. Alembic requires a `revision`
variable to be present, so we declare an orphaned root here.

Revision ID: 003ret
Revises: (none — orphaned root, not in main chain)
"""
from alembic import op  # noqa: F401  (imported for alembic compatibility)

revision = "003ret"
down_revision = None
branch_labels = ("retired_003",)
depends_on = None


def upgrade() -> None:
    pass  # intentional no-op — this migration was retired


def downgrade() -> None:
    pass  # intentional no-op
