"""Initial server schema.

Revision ID: 780a881b8b94
Revises:
Create Date: 2026-09-01

This baseline represents the clean schema for new installations.
"""

import sqlalchemy as sa
from alembic import op

revision = "780a881b8b94"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "checklist",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("task", sa.String(), nullable=False),
        sa.Column("is_done", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "ci_status",
        sa.Column("test_name", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=True),
        sa.Column("details", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("test_name"),
    )
    op.create_table(
        "license",
        sa.Column("license_key", sa.String(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("issuance_reference", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("license_key"),
        sa.UniqueConstraint("issuance_reference"),
    )
    op.create_table(
        "stats",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("total_requests", sa.Integer(), nullable=False),
        sa.Column("total_bytes_in", sa.Integer(), nullable=False),
        sa.Column("total_bytes_out", sa.Integer(), nullable=False),
        sa.Column("server_started_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "transaction",
        sa.Column("session_id", sa.String(), nullable=False),
        sa.Column("provider_payment_id", sa.String(), nullable=False),
        sa.Column("provider_reference_type", sa.String(length=16), nullable=False),
        sa.Column("expected_price_amount", sa.String(length=32), nullable=False),
        sa.Column("expected_price_currency", sa.String(length=20), nullable=False),
        sa.Column("expected_pay_amount", sa.String(length=32), nullable=True),
        sa.Column("expected_pay_currency", sa.String(length=20), nullable=True),
        sa.Column("customer_country", sa.String(length=100), nullable=False),
        sa.Column("country_evidence", sa.String(length=64), nullable=False),
        sa.Column("geolocation_database", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("processing_started_at", sa.String(length=40), nullable=True),
        sa.Column("finished_at", sa.String(length=40), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("session_id"),
        sa.UniqueConstraint("provider_payment_id"),
    )
    op.create_table(
        "patreon_license_deliveries",
        sa.Column("member_id", sa.String(length=128), nullable=False),
        sa.Column("license_key", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.Column("sent_at", sa.String(length=40), nullable=True),
        sa.Column("lease_expires_at", sa.String(length=40), nullable=True),
        sa.ForeignKeyConstraint(["license_key"], ["license.license_key"]),
        sa.PrimaryKeyConstraint("member_id"),
        sa.UniqueConstraint("license_key"),
    )


def downgrade():
    for table_name in (
        "patreon_license_deliveries",
        "transaction",
        "stats",
        "license",
        "ci_status",
        "checklist",
    ):
        op.drop_table(table_name)
