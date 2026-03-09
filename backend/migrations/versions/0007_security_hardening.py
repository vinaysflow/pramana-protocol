"""add next_index to status_lists, prev_hash+signature to audit_events, mandate_spend table

Revision ID: 0007_security_hardening
Revises: 0006_webhooks
Create Date: 2026-03-06

"""

from alembic import op
import sqlalchemy as sa

revision = "0007_security_hardening"
down_revision = "0006_webhooks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Atomic status list index counter
    op.add_column("status_lists", sa.Column("next_index", sa.Integer(), nullable=False, server_default="0"))

    # 2. Tamper-evident audit log columns
    op.add_column("audit_events", sa.Column("prev_hash", sa.String(64), nullable=True))
    op.add_column("audit_events", sa.Column("chain_signature", sa.String(200), nullable=True))
    op.add_column("audit_events", sa.Column("event_hash", sa.String(64), nullable=True))

    # 3. Mandate spend ledger
    op.create_table(
        "mandate_spends",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(100), nullable=False, index=True),
        sa.Column("intent_jti", sa.String(255), nullable=False, index=True),
        sa.Column("cart_jti", sa.String(255), nullable=False, unique=True),
        sa.Column("amount", sa.Numeric(precision=18, scale=6), nullable=False),
        sa.Column("currency", sa.String(10), nullable=False),
        sa.Column("merchant_did", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 4. JTI deduplication table (persistent across restarts)
    op.create_table(
        "seen_jtis",
        sa.Column("jti", sa.String(255), primary_key=True),
        sa.Column("endpoint", sa.String(100), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False, index=True),
    )

    # 5. Delegation registry for cascade revocation tracking
    op.create_table(
        "delegation_registry",
        sa.Column("jti", sa.String(255), primary_key=True),
        sa.Column("tenant_id", sa.String(100), nullable=False, index=True),
        sa.Column("issuer_did", sa.String(500), nullable=False),
        sa.Column("subject_did", sa.String(500), nullable=False),
        sa.Column("parent_jti", sa.String(255), nullable=True, index=True),
        sa.Column("status_list_id", sa.String(36), nullable=True),
        sa.Column("status_list_index", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("delegation_registry")
    op.drop_table("seen_jtis")
    op.drop_table("mandate_spends")
    op.drop_column("audit_events", "event_hash")
    op.drop_column("audit_events", "chain_signature")
    op.drop_column("audit_events", "prev_hash")
    op.drop_column("status_lists", "next_index")
