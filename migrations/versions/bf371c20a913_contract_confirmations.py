"""Persist checkout evidence and immutable delivery confirmations; no historical backfill."""
from alembic import op
import sqlalchemy as sa
revision = "bf371c20a913"
down_revision = "ae902bd71c40"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("checkout_agreements", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("snapshot", sa.Text(), nullable=False), sa.Column("created_at", sa.String(40), nullable=False))
    op.add_column("transaction", sa.Column("contract_snapshot", sa.Text(), nullable=True))
    op.add_column("transaction", sa.Column("confirmation_pdf", sa.LargeBinary(), nullable=True))
    op.add_column("patreon_license_deliveries", sa.Column("recipient_encrypted", sa.Text(), nullable=True))
    op.add_column("patreon_license_deliveries", sa.Column("confirmation_pdf", sa.LargeBinary(), nullable=True))

def downgrade():
    for table, fields in (("transaction", ("contract_snapshot", "confirmation_pdf")),
                          ("patreon_license_deliveries", ("recipient_encrypted", "confirmation_pdf"))):
        with op.batch_alter_table(table) as batch:
            for field in fields:
                batch.drop_column(field)
    op.drop_table("checkout_agreements")
