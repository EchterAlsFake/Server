"""Add independent, private Mollie test checkout and reconciliation."""

from alembic import op
import sqlalchemy as sa

revision = "7d921a6c0b53"
down_revision = "a49f02b731ce"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("transaction") as batch:
        batch.add_column(
            sa.Column(
                "provider", sa.String(20), nullable=False, server_default="nowpayments"
            )
        )
        batch.create_index("ix_transaction_provider", ["provider"])
    op.create_table(
        "mollie_grants",
        sa.Column("digest", sa.String(64), primary_key=True),
        sa.Column("configuration", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.String(40), nullable=False),
        sa.Column("order_id", sa.String(64), nullable=True),
    )
    op.create_table(
        "mollie_checkouts",
        sa.Column(
            "session_id",
            sa.String(64),
            sa.ForeignKey("transaction.session_id"),
            primary_key=True,
        ),
        sa.Column("profile_id", sa.String(64), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("idempotency_key", sa.String(64), nullable=False, unique=True),
        sa.Column("pricing_version", sa.String(40), nullable=False),
        sa.Column("country_code", sa.String(2), nullable=False),
        sa.Column("payment_id", sa.String(128), nullable=True, unique=True),
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
        "ix_mollie_checkouts_next_attempt_at", "mollie_checkouts", ["next_attempt_at"]
    )


def downgrade():
    op.drop_table("mollie_checkouts")
    op.drop_table("mollie_grants")
    with op.batch_alter_table("transaction") as batch:
        batch.drop_index("ix_transaction_provider")
        batch.drop_column("provider")
