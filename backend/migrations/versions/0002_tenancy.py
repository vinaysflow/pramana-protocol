"""tenancy

Revision ID: 0002_tenancy
Revises: 0001_initial
Create Date: 2025-12-23

"""

from alembic import op
import sqlalchemy as sa

revision = "0002_tenancy"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(length=100), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    for table in ["agents", "keys", "credentials", "status_lists", "audit_events"]:
        op.add_column(table, sa.Column("tenant_id", sa.String(length=100), nullable=False, server_default="default"))
        op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"], unique=False)

    # Remove server defaults after backfill
    for table in ["agents", "keys", "credentials", "status_lists", "audit_events"]:
        op.alter_column(table, "tenant_id", server_default=None)


def downgrade() -> None:
    for table in ["agents", "keys", "credentials", "status_lists", "audit_events"]:
        op.drop_index(f"ix_{table}_tenant_id", table_name=table)
        op.drop_column(table, "tenant_id")

    op.drop_table("tenants")
