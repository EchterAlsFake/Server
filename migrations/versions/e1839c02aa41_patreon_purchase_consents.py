"""Immutable Patreon pre-purchase consent and mailbox verification evidence."""
from alembic import op
import sqlalchemy as sa

revision = 'e1839c02aa41'
down_revision = 'd79230ac612f'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('patreon_shop_purchases', sa.Column('license_sent_at', sa.Float()))
    op.create_table('patreon_email_challenges',
        sa.Column('token_digest', sa.String(64), primary_key=True),
        sa.Column('email_digest', sa.String(64), nullable=False),
        sa.Column('email_encrypted', sa.Text(), nullable=False),
        sa.Column('code_digest', sa.String(64), nullable=False),
        sa.Column('created_at', sa.Float(), nullable=False),
        sa.Column('expires_at', sa.Float(), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('verified_at', sa.Float()))
    op.create_index('ix_patreon_email_challenges_email_digest', 'patreon_email_challenges', ['email_digest'])
    op.create_table('purchase_conditions',
        sa.Column('hash', sa.String(64), primary_key=True), sa.Column('text', sa.Text(), nullable=False))
    op.create_table('purchase_consents',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('product_id', sa.String(128), nullable=False),
        sa.Column('agreement_version', sa.String(64), nullable=False),
        sa.Column('agreement_text', sa.Text(), nullable=False),
        sa.Column('agreement_hash', sa.String(64), nullable=False),
        sa.Column('agreement_language', sa.String(8), nullable=False),
        sa.Column('accepted', sa.Boolean(), nullable=False),
        sa.Column('accepted_at', sa.Float(), nullable=False),
        sa.Column('created_at', sa.Float(), nullable=False),
        sa.Column('token_digest', sa.String(64), nullable=False, unique=True),
        sa.Column('verified_customer_id', sa.String(64)),
        sa.Column('verified_email_encrypted', sa.Text()),
        sa.Column('identity_verified_at', sa.Float()),
        sa.Column('conditions_hash', sa.String(64), sa.ForeignKey('purchase_conditions.hash'), nullable=False))
    op.create_index('ix_purchase_consents_verified_customer_id', 'purchase_consents', ['verified_customer_id'])
    op.create_table('purchase_consent_matches',
        sa.Column('patreon_order_id', sa.String(128), sa.ForeignKey('patreon_shop_purchases.order_id'), primary_key=True),
        sa.Column('consent_id', sa.String(36), sa.ForeignKey('purchase_consents.id'), unique=True),
        sa.Column('purchase_match_status', sa.String(40), nullable=False),
        sa.Column('patreon_purchase_at', sa.Float()),
        sa.Column('assessed_at', sa.Float(), nullable=False),
        sa.Column('conditions_hash', sa.String(64), sa.ForeignKey('purchase_conditions.hash'), nullable=False))
    if op.get_bind().dialect.name == 'sqlite':
        for table in ('purchase_consents', 'purchase_consent_matches', 'purchase_conditions'):
            op.execute(f"CREATE TRIGGER {table}_immutable BEFORE UPDATE ON {table} BEGIN SELECT RAISE(ABORT, 'Historical consent evidence cannot be edited'); END")


def downgrade():
    if op.get_bind().dialect.name == 'sqlite':
        for table in ('purchase_consents', 'purchase_consent_matches', 'purchase_conditions'):
            op.execute(f'DROP TRIGGER IF EXISTS {table}_immutable')
    op.drop_table('purchase_consent_matches')
    op.drop_table('purchase_consents')
    op.drop_table('purchase_conditions')
    op.drop_table('patreon_email_challenges')
    with op.batch_alter_table('patreon_shop_purchases') as batch:
        batch.drop_column('license_sent_at')
