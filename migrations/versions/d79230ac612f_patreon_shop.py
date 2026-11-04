"""Email-only Patreon Shop activation and durable issuance."""
from alembic import op
import sqlalchemy as sa
revision = 'd79230ac612f'
down_revision = 'c482e16d09a2'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('patreon_shop_customers',
        sa.Column('email_digest', sa.String(64), primary_key=True),
        sa.Column('recipient_encrypted', sa.Text(), nullable=False),
        sa.Column('pending', sa.Boolean(), nullable=False),
        sa.Column('requested_at', sa.Float(), nullable=False),
        sa.Column('completed_at', sa.Float()),
        sa.Column('next_attempt_at', sa.Float(), nullable=False),
        sa.Column('delivery_key', sa.String(), sa.ForeignKey('license.license_key')),
        sa.Column('last_key', sa.String(), sa.ForeignKey('license.license_key')),
        sa.Column('fallback_key', sa.String(), sa.ForeignKey('license.license_key')),
        sa.Column('fallback_created_at', sa.Float()),
        sa.Column('reason', sa.String(32)))
    op.create_table('patreon_shop_purchases',
        sa.Column('order_id', sa.String(128), primary_key=True),
        sa.Column('email_digest', sa.String(64), sa.ForeignKey('patreon_shop_customers.email_digest'), nullable=False),
        sa.Column('purchased_at', sa.Float(), nullable=False),
        sa.Column('eligible', sa.Boolean(), nullable=False),
        sa.Column('license_key', sa.String(), sa.ForeignKey('license.license_key'), unique=True))
    op.create_index('ix_patreon_shop_purchases_email_digest', 'patreon_shop_purchases', ['email_digest'])
    op.create_table('patreon_shop_health', sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('retry_at', sa.Float(), nullable=False), sa.Column('last_success_at', sa.Float()), sa.Column('reason', sa.String(32)))


def downgrade():
    op.drop_table('patreon_shop_health')
    op.drop_table('patreon_shop_purchases')
    op.drop_table('patreon_shop_customers')
