"""Short-lived email and receipt order proof for browser license retrieval."""
from alembic import op
import sqlalchemy as sa

revision = 'e8b42f930d16'
down_revision = 'e1839c02aa41'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('patreon_shop_lookups',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('email_digest', sa.String(64), nullable=False),
        sa.Column('order_digest', sa.String(64), nullable=False),
        sa.Column('created_at', sa.Float(), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('license_key', sa.String(), sa.ForeignKey('license.license_key')))
    op.create_index('ix_patreon_shop_lookups_created_at', 'patreon_shop_lookups', ['created_at'])


def downgrade():
    op.drop_table('patreon_shop_lookups')
