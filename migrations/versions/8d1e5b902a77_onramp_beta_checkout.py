"""Add Onramp beta checkout consent and delivery outbox.

Revision ID: 8d1e5b902a77
Revises: 6a30f2b917c4
"""

from alembic import op
import sqlalchemy as sa

revision = "8d1e5b902a77"
down_revision = "6a30f2b917c4"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "onramp_checkouts",
        sa.Column("session_id", sa.String(64), primary_key=True),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("consent_version", sa.String(32), nullable=False),
        sa.Column("accepted_at", sa.String(40)),
        sa.Column("stage", sa.String(20), nullable=False),
        sa.Column("beta", sa.Boolean(), nullable=False),
        sa.Column("recipient_encrypted", sa.Text()),
        sa.Column("checkout_encrypted", sa.Text()),
        sa.Column("tracking_encrypted", sa.Text()),
        sa.Column("callback_digest", sa.String(64), unique=True),
        sa.Column("callback_seen_at", sa.String(40)),
        sa.Column("charge_amount", sa.String(32)),
        sa.Column("charge_currency", sa.String(8), nullable=False),
        sa.Column("payment_state", sa.String(32), nullable=False),
        sa.Column("delivery_status", sa.String(16), nullable=False),
        sa.Column("lease_token", sa.String(64)),
        sa.Column("lease_expires_at", sa.String(40)),
        sa.Column("sent_at", sa.String(40)),
    )


def downgrade():
    op.drop_table("onramp_checkouts")
