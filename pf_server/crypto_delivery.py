"""Optional crypto email delivery; no email reaches the payment provider or logs."""

import secrets
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet
from flask import current_app
from sqlalchemy import and_, or_

from .extensions import db
from .licensing import build_license_file, get_or_create_license, send_license_email
from .models import CryptoLicenseDelivery, Transaction


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
    if not delivery.recipient_encrypted or delivery.delivery_status in {
        "sent",
        "expired",
    }:
        return delivery.delivery_status
    timestamp = datetime.now(timezone.utc)
    if delivery.created_at < (timestamp - timedelta(days=7)).isoformat():
        # A late webhook must not revive an address past the retention window.
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
        license_record = get_or_create_license(transaction.provider_payment_id)
        license_file = build_license_file(
            license_record.license_key,
            license_record.issuance_reference,
            license_record.created_at,
        )
        send_license_email(
            cipher().decrypt(delivery.recipient_encrypted.encode()).decode(),
            license_file,
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
    """Purge unsent addresses after 7 days and retry up to 100 paid orders."""
    timestamp = datetime.now(timezone.utc)
    db.session.execute(
        db.update(CryptoLicenseDelivery)
        .where(
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
                CryptoLicenseDelivery.recipient_encrypted.is_not(None),
                CryptoLicenseDelivery.delivery_status.in_(
                    ("pending", "failed", "sending")
                ),
            )
            .limit(100)
        )
        .scalars()
        .all()
    )
    for session_id in ids:
        deliver_crypto_license(session_id)
    return len(ids)
