"""Durable receipt processing; external I/O never delays an IPN acknowledgment.

Only the signature-verified webhook path may enqueue receipts. Store only parsed
payment fields, not raw provider bodies, signatures, email addresses or tokens.
The existing transaction claim and Keygen issuance ID fence duplicate fulfillment.
"""

import hashlib
import json
import secrets
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from flask import current_app
from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError

from .extensions import db
from .models import OnrampCheckout, PaymentReceipt
from .nowpayments_service import CompletionState, complete_payment
from .webhook_models import NowPaymentsWebhook


def now():
    return datetime.now(timezone.utc)


def enqueue(webhook):
    payload = json.dumps(asdict(webhook), sort_keys=True, separators=(",", ":"), default=str)
    identifier = hashlib.sha256(payload.encode()).hexdigest()
    timestamp = now().isoformat()
    if db.session.get(PaymentReceipt, identifier) is None:
        db.session.add(PaymentReceipt(
            receipt_id=identifier, payload=payload, status="pending",
            created_at=timestamp, updated_at=timestamp, next_attempt_at=timestamp,
        ))
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            if db.session.get(PaymentReceipt, identifier) is None:
                raise
    # An authentic redelivery can expedite a retry, but cannot steal a lease.
    db.session.execute(db.update(PaymentReceipt).where(
        PaymentReceipt.receipt_id == identifier, PaymentReceipt.status == "pending",
    ).values(next_attempt_at=timestamp))
    db.session.commit()
    return identifier


def _webhook(payload):
    fields = json.loads(payload)
    for name in ("price_amount", "pay_amount", "actually_paid"):
        if fields.get(name) is not None:
            fields[name] = Decimal(fields[name])
    return NowPaymentsWebhook(**fields)


def process_receipts(limit=25):
    """Retry durable receipts using an atomic ten-minute lease per receipt."""
    timestamp = now()
    due = or_(
        and_(PaymentReceipt.status == "pending", PaymentReceipt.next_attempt_at <= timestamp.isoformat()),
        and_(PaymentReceipt.status == "processing", PaymentReceipt.lease_expires_at < timestamp.isoformat()),
    )
    identifiers = db.session.execute(db.select(PaymentReceipt.receipt_id).where(due)
        .order_by(PaymentReceipt.created_at).limit(limit)).scalars().all()
    processed = 0
    for identifier in identifiers:
        token = secrets.token_hex(24)
        claim = db.session.execute(db.update(PaymentReceipt).where(
            PaymentReceipt.receipt_id == identifier, due,
        ).values(status="processing", lease_token=token,
            lease_expires_at=(now() + timedelta(minutes=10)).isoformat(),
            attempts=PaymentReceipt.attempts + 1, updated_at=timestamp.isoformat()))
        db.session.commit()
        if claim.rowcount != 1:
            continue
        status = "pending"
        webhook = None
        completed = False
        try:
            receipt = db.session.get(PaymentReceipt, identifier)
            webhook = _webhook(receipt.payload)
            checkout = db.session.get(OnrampCheckout, webhook.order_id)
            # Only a signed, settled partial receipt for a known Onramp order
            # may use its amount tolerance. Ordinary invoices still need finished.
            if webhook.payment_status.casefold() == "partially_paid" and not checkout:
                terminal, status = True, "rejected"
            else:
                result = complete_payment(webhook)
                completed = result.state in {CompletionState.COMPLETED, CompletionState.ALREADY_FINISHED}
                terminal = completed or result.state == CompletionState.REJECTED
                status = "done" if completed else "rejected" if terminal else "pending"
                if result.state == CompletionState.REJECTED:
                    if checkout and result.reason == "insufficient_actual_payment":
                        checkout.payment_state = "partially_paid"
                        db.session.commit()
                    current_app.logger.warning("Payment receipt rejected (reason=%s)", result.reason)
        except Exception:
            db.session.rollback()
            # Exceptions may contain provider bodies or credentials: no traceback.
            current_app.logger.warning("Payment receipt deferred; durable retry remains pending")
        receipt = db.session.get(PaymentReceipt, identifier)
        delay = min(300, 30 * 2 ** min(receipt.attempts - 1, 4))
        db.session.execute(db.update(PaymentReceipt).where(
            PaymentReceipt.receipt_id == identifier, PaymentReceipt.lease_token == token,
        ).values(status=status, updated_at=now().isoformat(), lease_token=None,
            lease_expires_at=None, next_attempt_at=(now() + timedelta(seconds=delay)).isoformat()))
        db.session.commit()
        processed += 1
        if completed:
            # Outbox jobs retry independently if SMTP or this process fails here.
            try:
                from .onramp_service import deliver_license
                from .crypto_delivery import deliver_crypto_license
                deliver_license(webhook.order_id)
                deliver_crypto_license(webhook.order_id)
            except Exception:
                db.session.rollback()
                current_app.logger.warning("License email deferred to delivery retry job")
    # Retain failed/pending work indefinitely; prune acknowledged terminal receipts.
    db.session.execute(db.delete(PaymentReceipt).where(
        PaymentReceipt.status.in_(["done", "rejected"]),
        PaymentReceipt.updated_at < (now() - timedelta(days=30)).isoformat(),
    ))
    db.session.commit()
    return processed
