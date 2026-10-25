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
    environment = db.Column(db.String(16), nullable=False, default="production")
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

    renewal_license_id = db.Column(db.String(36), nullable=True)


class Checklist(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    task = db.Column(db.String, nullable=False)
    is_done = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.String, nullable=False)


class OnrampCheckout(db.Model):
    """Checkout consent and delivery outbox; beta preserves historical offer terms."""

    __tablename__ = "onramp_checkouts"

    session_id = db.Column(db.String(64), primary_key=True)
    created_at = db.Column(db.String(40), nullable=False)
    consent_version = db.Column(db.String(32), nullable=False)
    accepted_at = db.Column(db.String(40), nullable=True)
    stage = db.Column(db.String(20), nullable=False, default="acknowledged")
    beta = db.Column(db.Boolean, nullable=False, default=True)
    recipient_encrypted = db.Column(db.Text, nullable=True)
    checkout_encrypted = db.Column(db.Text, nullable=True)
    tracking_encrypted = db.Column(db.Text, nullable=True)
    callback_digest = db.Column(db.String(64), unique=True, nullable=True)
    callback_seen_at = db.Column(db.String(40), nullable=True)
    charge_amount = db.Column(db.String(32), nullable=True)
    charge_currency = db.Column(db.String(8), nullable=False, default="USD")
    payment_state = db.Column(db.String(32), nullable=False, default="waiting")
    delivery_status = db.Column(db.String(16), nullable=False, default="pending")
    lease_token = db.Column(db.String(64), nullable=True)
    lease_expires_at = db.Column(db.String(40), nullable=True)
    sent_at = db.Column(db.String(40), nullable=True)


class License(db.Model):
    license_key = db.Column(db.String, primary_key=True)
    state = db.Column(db.String, nullable=False, default="valid")
    issuance_reference = db.Column(db.String, unique=True, nullable=False)
    created_at = db.Column(db.String, nullable=False)

    keygen_id = db.Column(db.String(36), unique=True, nullable=True)
    signed_key = db.Column(db.Text, nullable=True)


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
    lease_token = db.Column(db.String(64), nullable=True)


class CryptoLicenseDelivery(db.Model):
    """Optional encrypted crypto-delivery outbox, separate from card checkout."""

    __tablename__ = "crypto_license_deliveries"
    session_id = db.Column(db.String(64), primary_key=True)
    recipient_encrypted = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.String(40), nullable=False)
    delivery_status = db.Column(db.String(16), nullable=False, default="pending")
    lease_token = db.Column(db.String(64), nullable=True)
    lease_expires_at = db.Column(db.String(40), nullable=True)
    sent_at = db.Column(db.String(40), nullable=True)


class PaymentProgress(db.Model):
    """Minimal provider observations; never an authority to issue a license."""

    __tablename__ = "payment_progress"
    session_id = db.Column(db.String(64), primary_key=True)
    nowpayments_state = db.Column(db.String(32), nullable=False, default="waiting")
    nowpayments_payment_id = db.Column(db.String(128), nullable=True)
    nowpayments_updated_at = db.Column(db.String(40), nullable=True)
    onramp_state = db.Column(db.String(32), nullable=True)
    onramp_updated_at = db.Column(db.String(40), nullable=True)
    checkout_url = db.Column(db.Text, nullable=True)
    checked_at = db.Column(db.String(40), nullable=True)
    poll_lease_until = db.Column(db.String(40), nullable=True)
    poll_token = db.Column(db.String(64), nullable=True)
    refresh_unavailable = db.Column(db.Boolean, nullable=False, default=False)


class LicenseRenewal(db.Model):
    """A verified provider charge can only ever target one license."""
    reference_hash = db.Column(db.String(64), primary_key=True)
    keygen_id = db.Column(db.String(36), nullable=False)
    completed = db.Column(db.Boolean, nullable=False, default=False)
