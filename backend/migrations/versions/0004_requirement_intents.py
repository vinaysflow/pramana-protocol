"""requirement intents

Revision ID: 0004_requirement_intents
Revises: 0003_key_rotation_active
Create Date: 2025-12-25

"""

from alembic import op
import sqlalchemy as sa

revision = "0004_requirement_intents"
down_revision = "0003_key_rotation_active"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "requirement_intents",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=100), nullable=False, server_default="default"),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="requires_input"),
        sa.Column("subject_did", sa.String(length=600), nullable=True),
        sa.Column("issuer_name", sa.String(length=200), nullable=True),
        sa.Column("subject_name", sa.String(length=200), nullable=True),
        sa.Column("requirements", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("options", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("idempotency_key", sa.String(length=200), nullable=True),
        sa.Column("request_hash", sa.String(length=64), nullable=True),
        sa.Column("confirm_idempotency_key", sa.String(length=200), nullable=True),
        sa.Column("confirm_request_hash", sa.String(length=64), nullable=True),
        sa.Column("decision", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("proof_bundle", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_index("ix_requirement_intents_tenant_id", "requirement_intents", ["tenant_id"], unique=False)
    op.create_index("ix_requirement_intents_status", "requirement_intents", ["status"], unique=False)
    op.create_index("ix_requirement_intents_idempotency_key", "requirement_intents", ["idempotency_key"], unique=False)
    op.create_index(
        "ix_requirement_intents_confirm_idempotency_key",
        "requirement_intents",
        ["confirm_idempotency_key"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_requirement_intents_confirm_idempotency_key", table_name="requirement_intents")
    op.drop_index("ix_requirement_intents_idempotency_key", table_name="requirement_intents")
    op.drop_index("ix_requirement_intents_status", table_name="requirement_intents")
    op.drop_index("ix_requirement_intents_tenant_id", table_name="requirement_intents")
    op.drop_table("requirement_intents")


