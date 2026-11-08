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

    # Separate from the short-lived delivery outbox; never included in licenses.
    customer_email_encrypted = db.Column(db.Text, nullable=True)
    contract_snapshot = db.Column(db.Text, nullable=True)
    confirmation_pdf = db.Column(db.LargeBinary, nullable=True)
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


class PaymentReceipt(db.Model):
    """Minimal authenticated receipt, committed before webhook acknowledgment."""

    __tablename__ = "payment_receipts"
    __table_args__ = (db.Index("ix_payment_receipts_due", "status", "next_attempt_at"),)
    receipt_id = db.Column(db.String(64), primary_key=True)
    payload = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(16), nullable=False, default="pending")
    created_at = db.Column(db.String(40), nullable=False)
    updated_at = db.Column(db.String(40), nullable=False)
    next_attempt_at = db.Column(db.String(40), nullable=False)
    lease_token = db.Column(db.String(64), nullable=True)
    lease_expires_at = db.Column(db.String(40), nullable=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)


class CheckoutRecovery(db.Model):
    """Hashed bearer token; retain an expired tombstone to prevent ID bypass."""

    __tablename__ = "checkout_recovery"
    session_id = db.Column(db.String(64), primary_key=True)
    token_digest = db.Column(db.String(64), unique=True, nullable=True)
    created_at = db.Column(db.String(40), nullable=False)


class CheckoutAgreement(db.Model):
    """Server-side text snapshot accepted before redirecting to a provider."""
    __tablename__ = "checkout_agreements"
    id = db.Column(db.String(64), primary_key=True)
    snapshot = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.String(40), nullable=False)


class WithdrawalRequest(db.Model):
    """Received declarations; independent of purchase matching or legal assessment."""
    __tablename__ = "withdrawal_requests"
    id = db.Column(db.String(64), primary_key=True)
    submission_digest = db.Column(db.String(64), unique=True, nullable=False)
    details_encrypted = db.Column(db.Text, nullable=False)
    receipt_encrypted = db.Column(db.Text, nullable=False)
    received_at = db.Column(db.String(40), nullable=False)
    reviewed_at = db.Column(db.String(40), nullable=True)


class WithdrawalDelivery(db.Model):
    """Separate fenced outboxes for consumer receipt and operator notification."""
    __tablename__ = "withdrawal_deliveries"
    request_id = db.Column(db.String(64), db.ForeignKey("withdrawal_requests.id"), primary_key=True)
    audience = db.Column(db.String(16), primary_key=True)
    status = db.Column(db.String(16), nullable=False, default="pending")
    attempts = db.Column(db.Integer, nullable=False, default=0)
    next_attempt_at = db.Column(db.String(40), nullable=False)
    lease_token = db.Column(db.String(64), nullable=True)
    lease_expires_at = db.Column(db.String(40), nullable=True)
    sent_at = db.Column(db.String(40), nullable=True)


class PatreonShopCustomer(db.Model):
    """Durable email-only activation queue and recovery identity."""
    __tablename__ = 'patreon_shop_customers'
    email_digest = db.Column(db.String(64), primary_key=True)
    recipient_encrypted = db.Column(db.Text, nullable=False)
    pending = db.Column(db.Boolean, nullable=False, default=True)
    requested_at = db.Column(db.Float, nullable=False)
    completed_at = db.Column(db.Float, nullable=True)
    next_attempt_at = db.Column(db.Float, nullable=False, default=0)
    delivery_key = db.Column(db.String, db.ForeignKey('license.license_key'))
    last_key = db.Column(db.String, db.ForeignKey('license.license_key'))
    fallback_key = db.Column(db.String, db.ForeignKey('license.license_key'))
    fallback_created_at = db.Column(db.Float)
    reason = db.Column(db.String(32))


class PatreonShopPurchase(db.Model):
    __tablename__ = 'patreon_shop_purchases'
    order_id = db.Column(db.String(128), primary_key=True)
    email_digest = db.Column(db.String(64), db.ForeignKey('patreon_shop_customers.email_digest'), nullable=False, index=True)
    purchased_at = db.Column(db.Float, nullable=False)
    eligible = db.Column(db.Boolean, nullable=False)
    license_key = db.Column(db.String, db.ForeignKey('license.license_key'), unique=True)
    license_sent_at = db.Column(db.Float)


class PatreonShopHealth(db.Model):
    __tablename__ = 'patreon_shop_health'
    id = db.Column(db.Integer, primary_key=True)
    retry_at = db.Column(db.Float, nullable=False, default=0)
    last_success_at = db.Column(db.Float)
    reason = db.Column(db.String(32))


class PatreonShopLookup(db.Model):
    """Short-lived browser proof, matched only against a verified Shop sale."""
    __tablename__ = 'patreon_shop_lookups'
    id = db.Column(db.String(64), primary_key=True)
    email_digest = db.Column(db.String(64), nullable=False)
    order_digest = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.Float, nullable=False, index=True)
    status = db.Column(db.String(16), nullable=False, default='pending')
    license_key = db.Column(db.String, db.ForeignKey('license.license_key'))
