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

    bind = op.get_bind()
    is_sqlite = bind is not None and bind.dialect.name == "sqlite"

    for table in ["agents", "keys", "credentials", "status_lists", "audit_events"]:
        # SQLite needs batch mode for reliable ALTER TABLE operations.
        if is_sqlite:
            with op.batch_alter_table(table) as batch:
                batch.add_column(sa.Column("tenant_id", sa.String(length=100), nullable=False, server_default="default"))
                batch.create_index(f"ix_{table}_tenant_id", ["tenant_id"], unique=False)
            # Keep server_default on SQLite (dropping defaults requires table rebuild).
        else:
            op.add_column(table, sa.Column("tenant_id", sa.String(length=100), nullable=False, server_default="default"))
            op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"], unique=False)

    # Remove server defaults after backfill (non-SQLite)
    if not is_sqlite:
        for table in ["agents", "keys", "credentials", "status_lists", "audit_events"]:
            op.alter_column(table, "tenant_id", server_default=None)


def downgrade() -> None:
    for table in ["agents", "keys", "credentials", "status_lists", "audit_events"]:
        bind = op.get_bind()
        is_sqlite = bind is not None and bind.dialect.name == "sqlite"
        if is_sqlite:
            with op.batch_alter_table(table) as batch:
                batch.drop_index(f"ix_{table}_tenant_id")
                batch.drop_column("tenant_id")
        else:
            op.drop_index(f"ix_{table}_tenant_id", table_name=table)
            op.drop_column(table, "tenant_id")

    op.drop_table("tenants")
