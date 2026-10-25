"""Add an optional encrypted crypto license delivery outbox.

Revision ID: b46c3d791e02
Revises: 8d1e5b902a77
"""

from alembic import op
import sqlalchemy as sa

revision = "b46c3d791e02"
down_revision = "8d1e5b902a77"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "crypto_license_deliveries",
        sa.Column("session_id", sa.String(64), primary_key=True),
        sa.Column("recipient_encrypted", sa.Text(), nullable=True),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("delivery_status", sa.String(16), nullable=False),
        sa.Column("lease_token", sa.String(64), nullable=True),
        sa.Column("lease_expires_at", sa.String(40), nullable=True),
        sa.Column("sent_at", sa.String(40), nullable=True),
    )


def downgrade():
    op.drop_table("crypto_license_deliveries")
