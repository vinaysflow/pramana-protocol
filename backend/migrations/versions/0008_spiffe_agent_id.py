"""Add spiffe_id column to agents table for SPIFFE/SPIRE identity bridging

Revision ID: 0008_spiffe_agent_id
Revises: 0007_security_hardening
Create Date: 2026-03-06

"""

from alembic import op
import sqlalchemy as sa

revision = "0008_spiffe_agent_id"
down_revision = "0007_security_hardening"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agents",
        sa.Column("spiffe_id", sa.String(500), nullable=True),
    )
    op.create_index("ix_agents_spiffe_id", "agents", ["spiffe_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_agents_spiffe_id", table_name="agents")
    op.drop_column("agents", "spiffe_id")
