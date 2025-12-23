"""key active flag

Revision ID: 0003_key_rotation_active
Revises: 0002_tenancy
Create Date: 2025-12-23

"""

from alembic import op
import sqlalchemy as sa

revision = "0003_key_rotation_active"
down_revision = "0002_tenancy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('keys', sa.Column('active', sa.Boolean(), nullable=False, server_default=sa.text('1')))
    op.alter_column('keys', 'active', server_default=None)


def downgrade() -> None:
    op.drop_column('keys', 'active')
