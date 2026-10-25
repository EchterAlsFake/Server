"""merge commercial renewals and checkout progress

Revision ID: d0316abb213c
Revises: c7321ea490b6, e47a9012c635
Create Date: 2026-10-25 13:53:50.689240

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd0316abb213c'
down_revision = ('c7321ea490b6', 'e47a9012c635')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
