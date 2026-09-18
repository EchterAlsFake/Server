"""Distinguish sandbox checkout volume from production revenue."""

from alembic import op
import sqlalchemy as sa


revision = "34ddbc4909f1"
down_revision = "c941e9a30210"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("transaction") as batch:
        batch.add_column(
            sa.Column(
                "environment",
                sa.String(length=16),
                nullable=False,
                server_default="production",
            )
        )
    op.execute(
        "UPDATE \"transaction\" SET environment='sandbox' "
        "WHERE provider_payment_id LIKE 'mock-%'"
    )


def downgrade():
    with op.batch_alter_table("transaction") as batch:
        batch.drop_column("environment")
