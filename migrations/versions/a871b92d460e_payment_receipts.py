"""Persist authenticated payment receipts for asynchronous fulfillment."""

from alembic import op
import sqlalchemy as sa

revision = "a871b92d460e"
down_revision = "d0316abb213c"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "payment_receipts",
        sa.Column("receipt_id", sa.String(64), primary_key=True),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.Column("next_attempt_at", sa.String(40), nullable=False),
        sa.Column("lease_token", sa.String(64), nullable=True),
        sa.Column("lease_expires_at", sa.String(40), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
    )
    op.create_index("ix_payment_receipts_due", "payment_receipts", ["status", "next_attempt_at"])


def downgrade():
    op.drop_index("ix_payment_receipts_due", table_name="payment_receipts")
    op.drop_table("payment_receipts")
