"""Record worker progress for purchase loading screens."""
from alembic import op
import sqlalchemy as sa

revision = 'a49f02b731ce'
down_revision = ('e8b42f930d16', 'ae902bd71c40')
branch_labels = None
depends_on = None


def upgrade():
    for table, prefix in (('payment_progress', 'fulfillment'),
                          ('patreon_shop_customers', 'progress'),
                          ('patreon_shop_lookups', 'progress')):
        op.add_column(table, sa.Column(prefix + '_stage', sa.String(32)))
        op.add_column(table, sa.Column(prefix + '_updated_at', sa.Float()))


def downgrade():
    for table, prefix in (('patreon_shop_lookups', 'progress'),
                          ('patreon_shop_customers', 'progress'),
                          ('payment_progress', 'fulfillment')):
        with op.batch_alter_table(table) as batch:
            batch.drop_column(prefix + '_updated_at')
            batch.drop_column(prefix + '_stage')
