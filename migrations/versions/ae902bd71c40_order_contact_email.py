"""Retain encrypted email references for new crypto orders.

Existing orders are intentionally not backfilled: their delivery addresses
were collected under the previous short-lived retention policy.
"""
from alembic import op
import sqlalchemy as sa

revision = "ae902bd71c40"
down_revision = "f0c29a461d87"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("transaction", sa.Column("customer_email_encrypted", sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table("transaction") as batch:
        batch.drop_column("customer_email_encrypted")
