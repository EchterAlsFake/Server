"""Add independent Stripe checkout and recovery grants."""

from alembic import op
import sqlalchemy as sa

revision = "b871f925a603"
down_revision = ("34ddbc4909f1", "2f3c6a91d4b8", "7d921a6c0b53")
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "stripe_grants",
        sa.Column("digest", sa.String(64), primary_key=True),
        sa.Column("configuration", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.String(40), nullable=False),
        sa.Column("order_id", sa.String(64), nullable=True),
    )
    op.create_table(
        "stripe_checkouts",
        sa.Column(
            "session_id",
            sa.String(64),
            sa.ForeignKey("transaction.session_id"),
            primary_key=True,
        ),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("idempotency_key", sa.String(64), nullable=False, unique=True),
        sa.Column("pricing_version", sa.String(40), nullable=False),
        sa.Column("country_code", sa.String(2), nullable=False),
        sa.Column("payment_id", sa.String(128), nullable=True, unique=True),
        sa.Column("payment_intent_id", sa.String(128), nullable=True),
        sa.Column("checkout_url", sa.Text(), nullable=True),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("first_attempt_at", sa.String(40), nullable=True),
        sa.Column("checked_at", sa.String(40), nullable=True),
        sa.Column("next_attempt_at", sa.String(40), nullable=False),
        sa.Column("lease_token", sa.String(64), nullable=True),
        sa.Column("lease_expires_at", sa.String(40), nullable=True),
        sa.Column("notification_version", sa.Integer(), nullable=False),
        sa.Column("processed_notification_version", sa.Integer(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.String(40), nullable=True),
        sa.Column("refunded_amount", sa.String(32), nullable=False),
        sa.Column("chargeback_amount", sa.String(32), nullable=False),
    )
    op.create_index(
        "ix_stripe_checkouts_next_attempt_at", "stripe_checkouts", ["next_attempt_at"]
    )

    op.create_index(
        "ix_stripe_checkouts_payment_intent_id",
        "stripe_checkouts",
        ["payment_intent_id"],
    )


def downgrade():
    op.drop_table("stripe_checkouts")
    op.drop_table("stripe_grants")
