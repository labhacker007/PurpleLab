"""Legacy migration — provider_api_keys table (superseded by 003_security_simulation_api).

Revision ID: 003_api_keys_legacy
Revises: 002_add_missing_tables
Create Date: 2026-03-30

NOTE: This is a no-op placeholder kept so alembic can parse the migration chain.
The actual provider_api_keys table was created in the main chain via
003_security_simulation_api.py. This branch is merged in 010_merge_legacy_branch.
"""
from typing import Sequence, Union

revision: str = "003_api_keys_legacy"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = ("api_keys_legacy",)
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass  # no-op — superseded by 003_security_simulation_api.py


def downgrade() -> None:
    pass
