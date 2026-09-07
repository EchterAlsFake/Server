"""Persist Keygen issuance identity and signed delivery credential."""
from alembic import op
import sqlalchemy as sa

revision = "c941e9a30210"
down_revision = "780a881b8b94"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("license") as batch:
        batch.add_column(sa.Column("keygen_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("signed_key", sa.Text(), nullable=True))
        batch.create_unique_constraint("uq_license_keygen_id", ["keygen_id"])


def downgrade():
    with op.batch_alter_table("license") as batch:
        batch.drop_constraint("uq_license_keygen_id", type_="unique")
        batch.drop_column("signed_key")
        batch.drop_column("keygen_id")
