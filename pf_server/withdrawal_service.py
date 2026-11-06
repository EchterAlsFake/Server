"""Electronic declarations are received before mail delivery or manual assessment."""
import hashlib
import json
import secrets
import unicodedata
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime
from zoneinfo import ZoneInfo

from flask import current_app
from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError

from .crypto_delivery import cipher
from .extensions import db
from .licensing import normalize_recipient_email, send_email_message
from .models import WithdrawalRequest, WithdrawalDelivery

PURPOSE = "withdrawal-declaration-v1"
SUPPORT = "support@echteralsfake.me"
STATEMENT = "I hereby withdraw from the contract or part of the contract identified below."


def now():
    return datetime.now(timezone.utc)


def validate_details(form):
    limits = {"name": 200, "email": 254, "contract": 2000}
    details = {}
    for field, limit in limits.items():
        value = form.get(field, "")
        if not isinstance(value, str):
            raise ValueError("Please complete all fields.")
        value = value.replace("\r\n", "\n").strip()
        if not value or len(value) > limit or any(
            unicodedata.category(char) in {"Cc", "Cs"} and not (field == "contract" and char in "\n\t")
            for char in value
        ):
            raise ValueError("Please check your name, email and contract details.")
        details[field] = value
    recipient = normalize_recipient_email(details["email"])
    if recipient is None:
        raise ValueError("Please enter a valid email address.")
    details["email"] = recipient
    return details


def make_draft(details):
    # PII stays out of signed-but-readable session cookies and URLs. No DB draft.
    payload = dict(purpose=PURPOSE, nonce=secrets.token_urlsafe(24), details=details, statement=STATEMENT)
    return cipher().encrypt(json.dumps(payload, ensure_ascii=False).encode()).decode()


def read_draft(token):
    if not isinstance(token, str) or not 1 <= len(token) <= 16000:
        raise ValueError("Invalid draft")
    payload = json.loads(cipher().decrypt(token.encode()))
    if payload.get("purpose") != PURPOSE or not isinstance(payload.get("nonce"), str):
        raise ValueError("Invalid draft purpose")
    if not isinstance(payload.get("statement"), str) or not isinstance(payload.get("details"), dict):
        raise ValueError("Invalid draft content")
    validate_details(payload["details"])
    return payload


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def find_received(token):
    # An unguessable encrypted draft is the bearer credential, never an order ID.
    return db.session.execute(db.select(WithdrawalRequest).where(
        WithdrawalRequest.submission_digest == digest(token))).scalar_one_or_none()


def receipt_text(reference, payload, received_at):
    details = payload["details"]
    local = received_at.astimezone(ZoneInfo("Europe/Berlin")).isoformat()
    return (
        "Withdrawal receipt\n\n"
        f"Recipient: Johannes Habel, Bahnstr. 21, 06886 Lutherstadt Wittenberg, Germany\n{SUPPORT}\n"
        f"Reference: {reference}\n"
        f"Received (Europe/Berlin): {local}\n"
        f"Received (UTC): {received_at.isoformat()}\n\n"
        f"Declaration:\n{payload['statement']}\n\n"
        f"Name: {details['name']}\n"
        f"Contract or part: {details['contract']}\n"
        f"Receipt email: {details['email']}\n\n"
        "This confirms receipt only. Withdrawal validity and any refund will be assessed separately.\n"
    )


def receive(token, payload, received_at):
    existing = find_received(token)
    if existing:
        return existing
    reference = "WR-" + secrets.token_hex(16)
    encryption = cipher()
    row = WithdrawalRequest(id=reference, submission_digest=digest(token),
        details_encrypted=encryption.encrypt(json.dumps(payload, ensure_ascii=False).encode()).decode(),
        receipt_encrypted=encryption.encrypt(receipt_text(reference, payload, received_at).encode()).decode(),
        received_at=received_at.isoformat())
    try:
        db.session.add(row)
        db.session.flush()
        for audience in ("consumer", "operator"):
            db.session.add(WithdrawalDelivery(request_id=reference, audience=audience,
                next_attempt_at=received_at.isoformat()))
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        existing = find_received(token)
        if existing:
            return existing
        raise
    return row


def decrypt_receipt(row):
    return cipher().decrypt(row.receipt_encrypted.encode()).decode()


def deliver(reference, audience):
    if audience not in {"consumer", "operator"}:
        raise ValueError("Unknown delivery audience")
    timestamp = now()
    token = secrets.token_hex(24)
    claim = db.session.execute(db.update(WithdrawalDelivery).where(
        WithdrawalDelivery.request_id == reference,
        WithdrawalDelivery.audience == audience,
        WithdrawalDelivery.next_attempt_at <= timestamp.isoformat(),
        or_(WithdrawalDelivery.status.in_(("pending", "failed")), and_(
            WithdrawalDelivery.status == "sending",
            WithdrawalDelivery.lease_expires_at < timestamp.isoformat())),
    ).values(status="sending", lease_token=token,
        lease_expires_at=(timestamp + timedelta(minutes=10)).isoformat(),
        attempts=WithdrawalDelivery.attempts + 1))
    db.session.commit()
    if claim.rowcount != 1:
        return "busy"
    try:
        row = db.session.get(WithdrawalRequest, reference)
        content = decrypt_receipt(row)
        payload = json.loads(cipher().decrypt(row.details_encrypted.encode()))
        recipient = payload["details"]["email"] if audience == "consumer" else SUPPORT
        sender = current_app.config.get("LICENSE_EMAIL_FROM")
        if not sender:
            raise RuntimeError("Email sender missing")
        message = EmailMessage()
        message["From"] = sender
        message["To"] = recipient
        message["Reply-To"] = SUPPORT
        message["Subject"] = ("Withdrawal receipt" if audience == "consumer"
                              else "New withdrawal for review")
        message["Date"] = format_datetime(datetime.fromisoformat(row.received_at))
        message["Message-ID"] = f"<withdrawal-{reference}-{audience}@{sender.rpartition('@')[2]}>"
        message.set_content(content)
        message.add_attachment(content.encode(), maintype="text", subtype="plain",
                               filename="withdrawal-receipt.txt", params={"charset": "utf-8"})
        send_email_message(message)
    except Exception:
        db.session.rollback()
        db.session.execute(db.update(WithdrawalDelivery).where(
            WithdrawalDelivery.request_id == reference,
            WithdrawalDelivery.audience == audience,
            WithdrawalDelivery.lease_token == token,
        ).values(status="failed", lease_token=None, lease_expires_at=None,
            next_attempt_at=(now() + timedelta(minutes=1)).isoformat()))
        db.session.commit()
        current_app.logger.warning("Withdrawal receipt delivery deferred; declaration remains received")
        return "failed"
    db.session.execute(db.update(WithdrawalDelivery).where(
        WithdrawalDelivery.request_id == reference,
        WithdrawalDelivery.audience == audience,
        WithdrawalDelivery.lease_token == token,
    ).values(status="sent", lease_token=None, lease_expires_at=None, sent_at=now().isoformat()))
    db.session.commit()
    return "sent"


def deliver_received(reference):
    # Separate transactions: failing to notify the operator must not resend the consumer receipt.
    for audience in ("consumer", "operator"):
        try:
            deliver(reference, audience)
        except Exception:
            db.session.rollback()
            current_app.logger.warning("Withdrawal delivery deferred; retry queue retained")


def retry_deliveries():
    timestamp = now().isoformat()
    ids = db.session.execute(db.select(WithdrawalDelivery.request_id, WithdrawalDelivery.audience).where(
        WithdrawalDelivery.next_attempt_at <= timestamp,
        or_(WithdrawalDelivery.status.in_(("pending", "failed")), and_(
            WithdrawalDelivery.status == "sending", WithdrawalDelivery.lease_expires_at < timestamp)),
    ).order_by(WithdrawalDelivery.next_attempt_at).limit(100)).all()
    for reference, audience in ids:
        try:
            deliver(reference, audience)
        except Exception:
            db.session.rollback()
            current_app.logger.warning("Withdrawal delivery retry deferred")
    return len(ids)
