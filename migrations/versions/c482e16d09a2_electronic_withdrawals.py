"""Receive electronic withdrawals and retry durable receipts independently."""
from alembic import op
import sqlalchemy as sa

revision = "c482e16d09a2"
down_revision = "bf371c20a913"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("withdrawal_requests",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("submission_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("details_encrypted", sa.Text(), nullable=False),
        sa.Column("receipt_encrypted", sa.Text(), nullable=False),
        sa.Column("received_at", sa.String(40), nullable=False),
        sa.Column("reviewed_at", sa.String(40), nullable=True))
    op.create_table("withdrawal_deliveries",
        sa.Column("request_id", sa.String(64), sa.ForeignKey("withdrawal_requests.id"), primary_key=True),
        sa.Column("audience", sa.String(16), primary_key=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.String(40), nullable=False),
        sa.Column("lease_token", sa.String(64), nullable=True),
        sa.Column("lease_expires_at", sa.String(40), nullable=True),
        sa.Column("sent_at", sa.String(40), nullable=True))


def downgrade():
    op.drop_table("withdrawal_deliveries")
    op.drop_table("withdrawal_requests")
