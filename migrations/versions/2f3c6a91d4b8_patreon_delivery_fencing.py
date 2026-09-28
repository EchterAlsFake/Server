"""Fence stale Patreon delivery workers.

Revision ID: 2f3c6a91d4b8
Revises: c941e9a30210
"""

import sqlalchemy as sa
from alembic import op

revision = "2f3c6a91d4b8"
down_revision = "c941e9a30210"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("patreon_license_deliveries") as batch:
        batch.add_column(sa.Column("lease_token", sa.String(64), nullable=True))


def downgrade():
    with op.batch_alter_table("patreon_license_deliveries") as batch:
        batch.drop_column("lease_token")
