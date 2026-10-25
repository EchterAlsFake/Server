"""NOWPayments gateway calls, signatures, and transaction completion."""

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from enum import StrEnum

import httpx
from flask import current_app
from sqlalchemy import and_, or_
from sqlalchemy.exc import SQLAlchemyError

from .extensions import db
from .invoice_service import build_invoice, load_invoice, save_invoice
from .models import CryptoLicenseDelivery, OnrampCheckout, PaymentProgress, Transaction
from .webhook_models import NowPaymentsWebhook


class PaymentProviderError(RuntimeError):
    """The payment provider rejected or returned an invalid request."""


class CompletionState(StrEnum):
    COMPLETED = "completed"
    ALREADY_FINISHED = "already_finished"
    BUSY = "busy"
    UNKNOWN = "unknown"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class CompletionResult:
    state: CompletionState
    invoice_number: str | None = None
    reason: str | None = None


def _provider_identifier(value: object, field_name: str) -> str:
    if type(value) is int and value >= 0:
        return str(value)
    if (
        isinstance(value, str)
        and 0 < len(value) <= 128
        and re.fullmatch(r"[A-Za-z0-9._-]+", value)
    ):
        return value
    raise ValueError(f"NOWPayments {field_name} was invalid")


def _new_session() -> tuple[str, str]:
    return "NP-" + secrets.token_urlsafe(16), datetime.now(timezone.utc).isoformat()


def _headers() -> dict[str, str]:
    return {
        "x-api-key": current_app.config["NOWPAYMENTS_API_KEY"],
        "Content-Type": "application/json",
    }


def _store_pending_transaction(
    session_id: str,
    provider_payment_id: str,
    created_at: str,
    *,
    provider_reference_type: str,
    expected_price_amount: str,
    expected_price_currency: str,
    customer_country: str,
    country_evidence: str,
    geolocation_database: str,
    expected_pay_amount: str | None = None,
    expected_pay_currency: str | None = None,
    delivery_recipient_encrypted: str | None = None,
    hosted_url: str | None = None,
) -> None:
    db.session.add(
        Transaction(
            session_id=session_id,
            provider_payment_id=provider_payment_id,
            provider_reference_type=provider_reference_type,
            environment=(
                "sandbox" if current_app.config.get("NOWPAYMENTS_SANDBOX") else "production"
            ),
            expected_price_amount=expected_price_amount,
            expected_price_currency=expected_price_currency,
            customer_country=customer_country,
            country_evidence=country_evidence,
            geolocation_database=geolocation_database,
            expected_pay_amount=expected_pay_amount,
            expected_pay_currency=expected_pay_currency,
            status="pending",
            created_at=created_at,
        )
    )
    from .payment_progress import hosted_checkout_url
    db.session.add(PaymentProgress(session_id=session_id, checkout_url=hosted_checkout_url(hosted_url), nowpayments_payment_id=provider_payment_id if provider_reference_type == "payment" else None))
    if delivery_recipient_encrypted:
        db.session.add(CryptoLicenseDelivery(session_id=session_id, recipient_encrypted=delivery_recipient_encrypted, created_at=created_at))
    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        raise


def create_crypto_invoice(
    customer_country: str,
    country_evidence: str,
    geolocation_database: str,
    *, delivery_recipient_encrypted: str | None = None,
) -> dict[str, str]:
    session_id, created_at = _new_session()
    payload = {
        "price_amount": 19.99,
        "price_currency": "eur",
        "ipn_callback_url": f"{current_app.config['API_DOMAIN']}/nowpayments-ipn",
        "order_id": session_id,
        "order_description": "Porn Fetch License Key",
        "success_url": f"{current_app.config['APP_DOMAIN']}/buy_success?session_id={session_id}",
        "cancel_url": f"{current_app.config['APP_DOMAIN']}/buy_cancel",
    }
    try:
        response = httpx.post(
            f"{current_app.config['NOWPAYMENTS_API_URL']}/invoice",
            json=payload,
            headers=_headers(),
            timeout=10.0,
        )
        response.raise_for_status()
        invoice_data = response.json()
        if not isinstance(invoice_data, dict):
            raise TypeError("NOWPayments invoice response was not an object")
        invoice_id = _provider_identifier(invoice_data.get("id"), "invoice ID")
        from .payment_progress import hosted_checkout_url
        invoice_url = hosted_checkout_url(invoice_data.get("invoice_url"))
        if (
            not isinstance(invoice_url, str)
            or not invoice_url
        ):
            raise ValueError("NOWPayments invoice response was incomplete")
    except (httpx.HTTPError, TypeError, ValueError) as error:
        if not current_app.config.get("NOWPAYMENTS_SANDBOX"):
            raise PaymentProviderError("Failed to create crypto payment") from error
        current_app.logger.info("Falling back to local payment simulation")
        invoice_id = "mock-" + secrets.token_hex(8)
        _store_pending_transaction(
            session_id,
            invoice_id,
            created_at,
            provider_reference_type="invoice",
            expected_price_amount="19.99",
            expected_price_currency="eur",
            customer_country=customer_country,
            country_evidence=country_evidence,
            geolocation_database=geolocation_database,
            delivery_recipient_encrypted=delivery_recipient_encrypted,
        )
        return {
            "session_id": session_id,
            "invoice_url": f"local-sim:{session_id}",
        }

    _store_pending_transaction(
        session_id,
        invoice_id,
        created_at,
        provider_reference_type="invoice",
        expected_price_amount="19.99",
        expected_price_currency="eur",
        customer_country=customer_country,
        country_evidence=country_evidence,
        geolocation_database=geolocation_database,
        delivery_recipient_encrypted=delivery_recipient_encrypted,
        hosted_url=invoice_url,
    )
    return {"session_id": session_id, "invoice_url": invoice_url}


def verify_ipn_signature(payload: object, received_signature: str, secret: str) -> bool:
    if re.fullmatch(r"[0-9A-Fa-f]{128}", received_signature) is None:
        return False
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    calculated_signature = hmac.new(
        secret.encode("utf-8"),
        canonical_payload.encode("utf-8"),
        hashlib.sha512,
    ).hexdigest()
    return hmac.compare_digest(received_signature.lower(), calculated_signature)


def _validate_finished_payment(
    transaction: Transaction, webhook: NowPaymentsWebhook
) -> str | None:
    """Return a privacy-safe rejection reason, or ``None`` when fulfillment is safe."""
    provider_reference = (
        webhook.payment_id
        if transaction.provider_reference_type == "payment"
        else webhook.invoice_id
    )
    if provider_reference != transaction.provider_payment_id:
        return "provider_reference_mismatch"
    if webhook.price_amount is None:
        return "missing_price_amount"
    try:
        expected_price = Decimal(transaction.expected_price_amount)
    except InvalidOperation:
        return "invalid_stored_price"
    if webhook.price_amount != expected_price:
        return "price_amount_mismatch"
    if (
        not webhook.price_currency
        or webhook.price_currency.casefold()
        != transaction.expected_price_currency.casefold()
    ):
        return "price_currency_mismatch"
    if transaction.expected_pay_currency and (
        not webhook.pay_currency
        or webhook.pay_currency.casefold()
        != transaction.expected_pay_currency.casefold()
    ):
        return "pay_currency_mismatch"
    if transaction.expected_pay_amount:
        try:
            expected_paid = Decimal(transaction.expected_pay_amount)
        except InvalidOperation:
            return "invalid_stored_pay_amount"
        if db.session.get(OnrampCheckout, transaction.session_id) is not None:
            expected_paid *= Decimal("0.95")
        if webhook.actually_paid is None or webhook.actually_paid < expected_paid:
            return "insufficient_actual_payment"
    return None


def _claim_payment(session_id: str) -> CompletionState:
    now = datetime.now(timezone.utc)
    stale_before = (now - timedelta(minutes=10)).isoformat()
    result = db.session.execute(
        db.update(Transaction)
        .where(
            Transaction.session_id == session_id,
            or_(
                Transaction.status == "pending",
                and_(
                    Transaction.status == "processing",
                    or_(
                        Transaction.processing_started_at.is_(None),
                        Transaction.processing_started_at < stale_before,
                    ),
                ),
            ),
        )
        .values(status="processing", processing_started_at=now.isoformat())
    )
    db.session.commit()
    if result.rowcount == 1:
        return CompletionState.COMPLETED
    db.session.expire_all()
    transaction = db.session.get(Transaction, session_id)
    if transaction and transaction.status == "finished":
        return CompletionState.ALREADY_FINISHED
    return CompletionState.BUSY


def complete_payment(webhook: NowPaymentsWebhook) -> CompletionResult:
    """Validate, claim, and idempotently complete one known provider payment."""
    transaction = db.session.get(Transaction, webhook.order_id)
    if transaction is None:
        return CompletionResult(CompletionState.UNKNOWN)
    if transaction.status == "finished":
        return CompletionResult(CompletionState.ALREADY_FINISHED)

    rejection_reason = _validate_finished_payment(transaction, webhook)
    if rejection_reason:
        return CompletionResult(CompletionState.REJECTED, reason=rejection_reason)

    claim_state = _claim_payment(webhook.order_id)
    if claim_state != CompletionState.COMPLETED:
        return CompletionResult(claim_state)

    try:
        invoice = load_invoice(webhook.order_id)
        if invoice is None:
            crypto_amount = webhook.actually_paid or webhook.pay_amount or Decimal(0)
            invoice = build_invoice(
                fiat_amount=float(webhook.price_amount or Decimal(0)),
                crypto_amount=float(crypto_amount),
                pay_currency=webhook.pay_currency or "",
                transaction_hash=webhook.payin_hash or webhook.hash or "N/A",
            )
            save_invoice(webhook.order_id, invoice)
        if db.session.get(OnrampCheckout, webhook.order_id) is not None:
            from .licensing import build_license_file, get_or_create_license
            license_record = get_or_create_license(transaction.provider_payment_id)
            build_license_file(license_record.license_key, license_record.issuance_reference, license_record.created_at)
        db.session.execute(
            db.update(Transaction)
            .where(
                Transaction.session_id == webhook.order_id,
                Transaction.status == "processing",
            )
            .values(
                status="finished",
                processing_started_at=None,
                finished_at=datetime.now(timezone.utc).isoformat(),
            )
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        try:
            db.session.execute(
                db.update(Transaction)
                .where(
                    Transaction.session_id == webhook.order_id,
                    Transaction.status == "processing",
                )
                .values(status="pending", processing_started_at=None)
            )
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
        raise
    return CompletionResult(
        CompletionState.COMPLETED,
        invoice_number=str(invoice["Invoice Number"]),
    )
