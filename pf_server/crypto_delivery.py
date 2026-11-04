"""Crypto email delivery outbox; no email reaches the payment provider or logs."""

import secrets
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet
from flask import current_app
from sqlalchemy import and_, or_

from .extensions import db
from .licensing import fulfill_transaction_license, send_license_email
from .contracts import confirmation
from .models import CryptoLicenseDelivery, Transaction
from .invoice_service import load_invoice


def cipher():
    key = current_app.config.get(
        "LICENSE_DELIVERY_ENCRYPTION_KEY"
    ) or current_app.config.get("ONRAMP_ENCRYPTION_KEY")
    return Fernet(key.encode("ascii"))


def encrypt_recipient(recipient):
    if not current_app.config.get("LICENSE_SMTP_HOST") or not current_app.config.get(
        "LICENSE_EMAIL_FROM"
    ):
        raise ValueError("Email delivery is not configured")
    return cipher().encrypt(recipient.encode()).decode()


def deliver_crypto_license(session_id):
    """Claim a lease before SMTP; retries reuse the same license and Message-ID."""
    transaction = db.session.get(Transaction, session_id)
    delivery = db.session.get(CryptoLicenseDelivery, session_id)
    if not delivery or not transaction or transaction.status != "finished":
        return "pending"
    if transaction.contract_snapshot and transaction.customer_email_encrypted and delivery.delivery_status != "sent" and (not delivery.recipient_encrypted or delivery.delivery_status == "expired"):
        delivery.recipient_encrypted = transaction.customer_email_encrypted
        delivery.delivery_status = "pending"
        db.session.commit()
    if not delivery.recipient_encrypted or delivery.delivery_status in {
        "sent",
        "expired",
    }:
        return delivery.delivery_status
    timestamp = datetime.now(timezone.utc)
    if not transaction.contract_snapshot and delivery.created_at < (timestamp - timedelta(days=7)).isoformat():
        # Legacy orders retain their original seven-day delivery window.
        if (
            delivery.lease_expires_at
            and delivery.lease_expires_at >= timestamp.isoformat()
        ):
            return "busy"
        delivery.recipient_encrypted = None
        delivery.delivery_status = "expired"
        db.session.commit()
        return "expired"
    token = secrets.token_hex(24)
    claim = db.session.execute(
        db.update(CryptoLicenseDelivery)
        .where(
            CryptoLicenseDelivery.session_id == session_id,
            CryptoLicenseDelivery.recipient_encrypted.is_not(None),
            or_(
                CryptoLicenseDelivery.delivery_status.in_(("pending", "failed")),
                and_(
                    CryptoLicenseDelivery.delivery_status == "sending",
                    CryptoLicenseDelivery.lease_expires_at < timestamp.isoformat(),
                ),
            ),
        )
        .values(
            delivery_status="sending",
            lease_token=token,
            lease_expires_at=(timestamp + timedelta(minutes=10)).isoformat(),
        )
    )
    db.session.commit()
    if claim.rowcount != 1:
        return "busy"
    try:
        delivery = db.session.get(CryptoLicenseDelivery, session_id)
        document = confirmation(transaction)
        license_file = fulfill_transaction_license(transaction)
        invoice = load_invoice(session_id)
        if invoice is None:
            raise ValueError("Paid order invoice is unavailable")
        send_license_email(
            cipher().decrypt(delivery.recipient_encrypted.encode()).decode(),
            license_file,
            invoice=invoice, payment_environment=transaction.environment, confirmation_pdf=document,
        )
    except Exception:
        db.session.rollback()
        db.session.execute(
            db.update(CryptoLicenseDelivery)
            .where(
                CryptoLicenseDelivery.session_id == session_id,
                CryptoLicenseDelivery.lease_token == token,
            )
            .values(delivery_status="failed", lease_token=None, lease_expires_at=None)
        )
        db.session.commit()
        current_app.logger.warning("Crypto license email deferred for retry")
        return "failed"
    db.session.execute(
        db.update(CryptoLicenseDelivery)
        .where(
            CryptoLicenseDelivery.session_id == session_id,
            CryptoLicenseDelivery.lease_token == token,
        )
        .values(
            delivery_status="sent",
            recipient_encrypted=None,
            lease_token=None,
            lease_expires_at=None,
            sent_at=datetime.now(timezone.utc).isoformat(),
        )
    )
    db.session.commit()
    return "sent"


def retry_crypto_deliveries():
    """Purge abandoned/legacy addresses; retry up to 100 confirmed purchases."""
    timestamp = datetime.now(timezone.utc)
    db.session.execute(
        db.update(CryptoLicenseDelivery)
        .where(
            ~CryptoLicenseDelivery.session_id.in_(db.select(Transaction.session_id).where(
                Transaction.status == "finished", Transaction.contract_snapshot.is_not(None))),
            CryptoLicenseDelivery.created_at
            < (timestamp - timedelta(days=7)).isoformat(),
            CryptoLicenseDelivery.recipient_encrypted.is_not(None),
            or_(
                CryptoLicenseDelivery.lease_expires_at.is_(None),
                CryptoLicenseDelivery.lease_expires_at < timestamp.isoformat(),
            ),
        )
        .values(
            recipient_encrypted=None,
            delivery_status="expired",
            lease_token=None,
            lease_expires_at=None,
        )
    )
    db.session.commit()
    ids = (
        db.session.execute(
            db.select(CryptoLicenseDelivery.session_id)
            .join(
                Transaction, Transaction.session_id == CryptoLicenseDelivery.session_id
            )
            .where(
                Transaction.status == "finished",
                CryptoLicenseDelivery.delivery_status != "sent",
                or_(CryptoLicenseDelivery.recipient_encrypted.is_not(None), and_(
                    Transaction.contract_snapshot.is_not(None), Transaction.customer_email_encrypted.is_not(None))),
            )
            .limit(100)
        )
        .scalars()
        .all()
    )
    for session_id in ids:
        deliver_crypto_license(session_id)
    return len(ids)
