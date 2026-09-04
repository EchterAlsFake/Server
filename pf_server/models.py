"""Database models for the server's persistent state."""

from .extensions import db


class Stats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    total_requests = db.Column(db.Integer, nullable=False, default=0)
    total_bytes_in = db.Column(db.Integer, nullable=False, default=0)
    total_bytes_out = db.Column(db.Integer, nullable=False, default=0)
    server_started_at = db.Column(db.String, nullable=False)


class CiStatus(db.Model):
    test_name = db.Column(db.String, primary_key=True)
    status = db.Column(db.String, nullable=False)
    updated_at = db.Column(db.String)
    details = db.Column(db.String)


class Transaction(db.Model):
    session_id = db.Column(db.String, primary_key=True)
    provider_payment_id = db.Column(db.String, unique=True, nullable=False)
    provider_reference_type = db.Column(db.String(16), nullable=False)
    expected_price_amount = db.Column(db.String(32), nullable=False)
    expected_price_currency = db.Column(db.String(20), nullable=False)
    expected_pay_amount = db.Column(db.String(32), nullable=True)
    expected_pay_currency = db.Column(db.String(20), nullable=True)
    customer_country = db.Column(db.String(100), nullable=False)
    country_evidence = db.Column(db.String(64), nullable=False)
    geolocation_database = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String, nullable=False, default="pending")
    processing_started_at = db.Column(db.String(40), nullable=True)
    finished_at = db.Column(db.String(40), nullable=True)
    created_at = db.Column(db.String, nullable=False)


class Checklist(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    task = db.Column(db.String, nullable=False)
    is_done = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.String, nullable=False)


class License(db.Model):
    license_key = db.Column(db.String, primary_key=True)
    state = db.Column(db.String, nullable=False, default="valid")
    issuance_reference = db.Column(db.String, unique=True, nullable=False)
    created_at = db.Column(db.String, nullable=False)


class PatreonLicenseDelivery(db.Model):
    """Minimal delivery record used to make Patreon webhook retries idempotent."""

    __tablename__ = "patreon_license_deliveries"

    member_id = db.Column(db.String(128), primary_key=True)
    license_key = db.Column(
        db.String(64),
        db.ForeignKey("license.license_key"),
        unique=True,
        nullable=True,
    )
    status = db.Column(db.String(16), nullable=False, default="pending")
    created_at = db.Column(db.String(40), nullable=False)
    updated_at = db.Column(db.String(40), nullable=False)
    sent_at = db.Column(db.String(40), nullable=True)
    lease_expires_at = db.Column(db.String(40), nullable=True)
