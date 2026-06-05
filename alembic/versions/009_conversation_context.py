"""Add goal and context_state to conversations table

Revision ID: 009_conversation_context
Revises: 008_product_personas
Create Date: 2026-06-05
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '009_conversation_context'
down_revision = '008_product_personas'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('conversations',
        sa.Column('goal', sa.String(100), nullable=True))
    op.add_column('conversations',
        sa.Column('context_state', postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    op.drop_column('conversations', 'context_state')
    op.drop_column('conversations', 'goal')
