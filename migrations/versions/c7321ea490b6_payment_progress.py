"""Store minimal checkout progress and throttle provider status polling.

Revision ID: c7321ea490b6
Revises: b46c3d791e02
"""

from alembic import op
import sqlalchemy as sa

revision = "c7321ea490b6"
down_revision = "b46c3d791e02"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "payment_progress",
        sa.Column("session_id", sa.String(64), primary_key=True),
        sa.Column("nowpayments_state", sa.String(32), nullable=False),
        sa.Column("nowpayments_payment_id", sa.String(128), nullable=True),
        sa.Column("nowpayments_updated_at", sa.String(40), nullable=True),
        sa.Column("onramp_state", sa.String(32), nullable=True),
        sa.Column("onramp_updated_at", sa.String(40), nullable=True),
        sa.Column("checkout_url", sa.Text(), nullable=True),
        sa.Column("checked_at", sa.String(40), nullable=True),
        sa.Column("poll_lease_until", sa.String(40), nullable=True),
        sa.Column("poll_token", sa.String(64), nullable=True),
        sa.Column("refresh_unavailable", sa.Boolean(), nullable=False),
    )


def downgrade():
    op.drop_table("payment_progress")
