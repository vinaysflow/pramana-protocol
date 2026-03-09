"""trust events

Revision ID: 0005_trust_events
Revises: 0004_requirement_intents
Create Date: 2026-03-06

"""

from alembic import op
import sqlalchemy as sa

revision = "0005_trust_events"
down_revision = "0004_requirement_intents"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "trust_events",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=100), nullable=False, server_default="default"),
        sa.Column("agent_did", sa.String(length=600), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("credential_jti", sa.String(length=200), nullable=True),
        sa.Column("score_delta", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_index("ix_trust_events_tenant_id", "trust_events", ["tenant_id"], unique=False)
    op.create_index("ix_trust_events_agent_did", "trust_events", ["agent_did"], unique=False)
    op.create_index("ix_trust_events_event_type", "trust_events", ["event_type"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_trust_events_event_type", table_name="trust_events")
    op.drop_index("ix_trust_events_agent_did", table_name="trust_events")
    op.drop_index("ix_trust_events_tenant_id", table_name="trust_events")
    op.drop_table("trust_events")
