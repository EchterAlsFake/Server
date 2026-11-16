"""Private tester grants and durable Stripe payment reconciliation."""

from .extensions import db


class StripeGrant(db.Model):
    __tablename__ = "stripe_grants"
    digest = db.Column(db.String(64), primary_key=True)
    configuration = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.String(40), nullable=False)
    order_id = db.Column(db.String(64), nullable=True)


class StripeCheckout(db.Model):
    __tablename__ = "stripe_checkouts"
    session_id = db.Column(
        db.String(64), db.ForeignKey("transaction.session_id"), primary_key=True
    )
    account_id = db.Column(db.String(64), nullable=False)
    payload = db.Column(db.Text, nullable=False)
    idempotency_key = db.Column(db.String(64), nullable=False, unique=True)
    pricing_version = db.Column(db.String(40), nullable=False)
    country_code = db.Column(db.String(2), nullable=False)
    payment_id = db.Column(db.String(128), nullable=True, unique=True)
    payment_intent_id = db.Column(db.String(128), nullable=True, index=True)
    checkout_url = db.Column(db.Text, nullable=True)
    state = db.Column(db.String(32), nullable=False, default="creating")
    first_attempt_at = db.Column(db.String(40), nullable=True)
    checked_at = db.Column(db.String(40), nullable=True)
    next_attempt_at = db.Column(db.String(40), nullable=False, index=True)
    lease_token = db.Column(db.String(64), nullable=True)
    lease_expires_at = db.Column(db.String(40), nullable=True)
    notification_version = db.Column(db.Integer, nullable=False, default=0)
    processed_notification_version = db.Column(db.Integer, nullable=False, default=0)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    last_error = db.Column(db.String(40), nullable=True)
    refunded_amount = db.Column(db.String(32), nullable=False, default="0.00")
    chargeback_amount = db.Column(db.String(32), nullable=False, default="0.00")
