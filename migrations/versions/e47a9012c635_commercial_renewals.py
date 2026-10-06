"""Commercial renewal intents, keeping provider charge bindings immutable."""
from alembic import op
import sqlalchemy as sa

revision = 'e47a9012c635'
down_revision = '5d9e45e626f8'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('transaction', sa.Column('renewal_license_id', sa.String(36), nullable=True))
    op.create_table('license_renewal',
                    sa.Column('reference_hash', sa.String(64), primary_key=True),
                    sa.Column('keygen_id', sa.String(36), nullable=False),
                    sa.Column('completed', sa.Boolean(), nullable=False))


def downgrade():
    # The ledger is intentionally retained. Roll back the image, not payment history.
    raise RuntimeError('Renewal audit history must not be discarded by downgrade')
