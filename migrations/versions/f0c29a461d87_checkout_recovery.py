"""Short-lived hashed checkout recovery tokens."""

from alembic import op
import sqlalchemy as sa

revision = "f0c29a461d87"
down_revision = "a871b92d460e"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("checkout_recovery",
        sa.Column("session_id", sa.String(64), primary_key=True),
        sa.Column("token_digest", sa.String(64), nullable=True, unique=True),
        sa.Column("created_at", sa.String(40), nullable=False))


def downgrade():
    op.drop_table("checkout_recovery")
