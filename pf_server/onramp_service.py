"""Banxa-only Onramp checkout and a retryable encrypted license outbox.

Only signed NOWPayments events authorize fulfillment. Onramp callbacks have no
payment authority. Never log provider URLs, responses, addresses or mailboxes.
"""

import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_CEILING
from urllib.parse import urlencode, urljoin, urlsplit

import httpx
from cryptography.fernet import Fernet
from flask import current_app
from sqlalchemy import and_, or_

from .extensions import db
from .country_service import CheckoutCountryDecision
from .licensing import build_license_file, get_or_create_license, send_license_email
from .models import OnrampCheckout, Transaction
from .webhook_models import NowPaymentsWebhook
from .nowpayments_service import (
    PaymentProviderError,
    _headers,
    _provider_identifier,
    _store_pending_transaction,
)

CONSENT_VERSION = "banxa-annual-v1"
API_BASE = "https://api.onramp-pay.com"
CHECKOUT_BASE = "https://checkout.onramp-pay.com/process-payment.php"


def now() -> datetime:
    return datetime.now(timezone.utc)


def available() -> bool:
    config = current_app.config
    return bool(
        config.get("ONRAMP_ENABLED")
        and config.get("ONRAMP_POLYGON_USDC_VERIFIED")
        and not config.get("NOWPAYMENTS_SANDBOX")
        and config.get("NOWPAYMENTS_API_URL") == "https://api.nowpayments.io/v1"
        and config.get("NOWPAYMENTS_API_KEY")
        and config.get("NOWPAYMENTS_IPN_SECRET")
        and config.get("ONRAMP_ENCRYPTION_KEY")
    )


def encrypt(value: str) -> str:
    return (
        Fernet(current_app.config["ONRAMP_ENCRYPTION_KEY"].encode("ascii"))
        .encrypt(value.encode())
        .decode()
    )


def decrypt(value: str) -> str:
    return (
        Fernet(current_app.config["ONRAMP_ENCRYPTION_KEY"].encode("ascii"))
        .decrypt(value.encode())
        .decode()
    )


def positive_decimal(value: object) -> Decimal:
    if isinstance(value, bool):
        raise ValueError("Invalid amount")
    amount = Decimal(str(value))
    if not amount.is_finite() or amount <= 0 or amount > Decimal("1000000"):
        raise ValueError("Invalid amount")
    return amount


def _get_json(client: httpx.Client, url: str, **kwargs) -> dict:
    response = client.get(url, **kwargs)
    for _ in range(3):
        if response.status_code not in {301, 302, 303, 307, 308}:
            break
        target = urljoin(str(response.url), response.headers.get("location", ""))
        parsed = urlsplit(target)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in {"api.onramp-pay.com", "api.paygate.to"}
            or parsed.username
            or parsed.password
            or parsed.port not in {None, 443}
            or parsed.path.rstrip("/") != urlsplit(url).path.rstrip("/")
        ):
            raise ValueError("Unexpected provider redirect")
        response = client.get(target)
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("Invalid provider response")
    return payload


def create_checkout(
    checkout: OnrampCheckout, country: CheckoutCountryDecision, recipient: str
) -> OnrampCheckout:
    """Called only after an atomic claim. Never repeat an ambiguous creation."""
    session_id = checkout.session_id
    checkout.recipient_encrypted = encrypt(recipient)
    checkout.accepted_at = now().isoformat()
    db.session.commit()
    config = current_app.config
    try:
        # Onramp's public API redirects to its underlying PayGate service.
        # Allow only HTTPS redirects to that known API on the same path.
        # Ambiguous timeouts are never retried, especially wallet creation.
        with httpx.Client(
            timeout=15, follow_redirects=False, trust_env=False
        ) as client:
            directory = _get_json(client, API_BASE + "/control/provider-status")
            providers = directory.get("providers")
            if not isinstance(providers, list):
                raise ValueError("Invalid provider directory")
            banxa = next(
                (
                    p
                    for p in providers
                    if isinstance(p, dict) and p.get("id") == "banxa"
                ),
                None,
            )
            if (
                not banxa
                or banxa.get("status") != "active"
                or banxa.get("minimum_currency") != "USD"
            ):
                raise PaymentProviderError("Banxa is currently unavailable")
            minimum = positive_decimal(banxa.get("minimum_amount"))
            response = client.post(
                config["NOWPAYMENTS_API_URL"] + "/payment",
                headers=_headers(),
                json={
                    "price_amount": 19.99,
                    "price_currency": "eur",
                    "pay_currency": "usdcmatic",
                    "is_fixed_rate": False,
                    "is_fee_paid_by_user": False,
                    "order_id": session_id,
                    "order_description": "Porn Fetch annual update license",
                    "ipn_callback_url": config["API_DOMAIN"] + "/nowpayments-ipn",
                },
            )
            response.raise_for_status()
            payment = response.json()
            if not isinstance(payment, dict):
                raise ValueError("Invalid deposit response")
            payment_id = _provider_identifier(payment.get("payment_id"), "payment ID")
            pay_amount = positive_decimal(payment.get("pay_amount"))
            address = payment.get("pay_address")
            if (
                payment.get("pay_currency", "").lower() != "usdcmatic"
                or payment.get("network", "").lower() not in {"matic", "polygon"}
                or positive_decimal(payment.get("price_amount")) != Decimal("19.99")
                or payment.get("price_currency", "").lower() != "eur"
                or payment.get("order_id") != session_id
                or payment.get("payin_extra_id")
                or not isinstance(address, str)
                or re.fullmatch(r"0x[0-9a-fA-F]{40}", address) is None
            ):
                raise ValueError("Incompatible deposit payment")
            _store_pending_transaction(
                session_id,
                payment_id,
                checkout.created_at,
                provider_reference_type="payment",
                expected_price_amount="19.99",
                expected_price_currency="eur",
                expected_pay_amount=str(pay_amount),
                expected_pay_currency="usdcmatic",
                customer_country=country.country_name,
                country_evidence=country.evidence_source,
                geolocation_database=country.database_label,
            )
            estimate = _get_json(
                client,
                config["NOWPAYMENTS_API_URL"] + "/estimate",
                headers=_headers(),
                params={
                    "amount": "1",
                    "currency_from": "usd",
                    "currency_to": "usdcmatic",
                },
            )
            # Gross up a 3% deduction, rather than adding 3% and underfunding.
            # Provider/network costs can still vary; never promise a net quote.
            charge = (
                pay_amount
                / positive_decimal(estimate.get("estimated_amount"))
                / Decimal("0.97")
            ).quantize(Decimal("0.01"), rounding=ROUND_CEILING)
            if charge < minimum:
                raise PaymentProviderError(
                    "This purchase is below Banxa's minimum amount"
                )
            callback_secret = secrets.token_urlsafe(32)
            checkout.callback_digest = hashlib.sha256(
                callback_secret.encode()
            ).hexdigest()
            checkout.charge_amount = str(charge)
            db.session.commit()
            wallet = _get_json(
                client,
                API_BASE + "/control/wallet.php",
                params={
                    "address": address,
                    "callback": config["API_DOMAIN"]
                    + "/onramp-callback?"
                    + urlencode({"reference": callback_secret}),
                },
            )
            encrypted_address = wallet.get("address_in")
            tracking = wallet.get("ipn_token")
            if (
                not isinstance(encrypted_address, str)
                or not 1 <= len(encrypted_address) <= 4096
            ):
                raise ValueError("Missing encrypted wallet reference")
            if not isinstance(tracking, str) or not 1 <= len(tracking) <= 4096:
                raise ValueError("Missing tracking reference")
            # The local delivery address is never prefilled into Banxa. Their
            # verification email is entered independently at hosted checkout.
            checkout.checkout_encrypted = encrypt(
                CHECKOUT_BASE
                + "?"
                + urlencode(
                    {
                        "address": encrypted_address,
                        "amount": str(charge),
                        "provider": "banxa",
                        "currency": "USD",
                    }
                )
            )
            checkout.tracking_encrypted = encrypt(tracking)
            checkout.stage = "ready"
            db.session.commit()
    except Exception as error:
        db.session.rollback()
        checkout = db.session.get(OnrampCheckout, session_id)
        checkout.stage = "failed"
        checkout.recipient_encrypted = None
        db.session.commit()
        if isinstance(error, PaymentProviderError):
            raise
        raise PaymentProviderError(
            "Could not create the Banxa checkout. No payment link has been issued. Please start again."
        ) from None
    return checkout


def record_payment_state(webhook: NowPaymentsWebhook) -> None:
    """Only called for signed events, binding the event to its stored payment."""
    checkout = db.session.get(OnrampCheckout, webhook.order_id)
    transaction = db.session.get(Transaction, webhook.order_id)
    if not checkout or not transaction or transaction.status == "finished":
        return
    if (
        webhook.payment_id != transaction.provider_payment_id
        or webhook.price_amount != Decimal(transaction.expected_price_amount)
        or (webhook.price_currency or "").lower() != transaction.expected_price_currency
        or (webhook.pay_currency or "").lower() != transaction.expected_pay_currency
    ):
        return
    status = (webhook.payment_status or "").lower()
    if status in {
        "waiting",
        "confirming",
        "confirmed",
        "sending",
        "partially_paid",
        "failed",
        "expired",
        "finished",
    }:
        # Once a terminal/problem state is observed, stale waiting events must
        # not hide it. A valid later finished event may still complete payment.
        if status != "finished" and checkout.payment_state in {
            "partially_paid",
            "failed",
            "expired",
        }:
            return
        ranks = {"waiting": 0, "confirming": 1, "confirmed": 2, "sending": 3, "finished": 4}
        if status in ranks and checkout.payment_state in ranks and ranks[status] < ranks[checkout.payment_state]:
            return
        checkout.payment_state = status
        db.session.commit()


def deliver_license(session_id: str) -> str:
    """Fenced, retryable SMTP delivery, independent of browser availability."""
    checkout = db.session.get(OnrampCheckout, session_id)
    transaction = db.session.get(Transaction, session_id)
    if not checkout or not transaction or transaction.status != "finished":
        return "pending"
    if checkout.delivery_status == "sent" or not checkout.recipient_encrypted:
        return checkout.delivery_status
    token = secrets.token_hex(24)
    timestamp = now()
    claimed = db.session.execute(
        db.update(OnrampCheckout)
        .where(
            OnrampCheckout.session_id == session_id,
            OnrampCheckout.recipient_encrypted.is_not(None),
            or_(
                OnrampCheckout.delivery_status.in_(("pending", "failed")),
                and_(
                    OnrampCheckout.delivery_status == "sending",
                    OnrampCheckout.lease_expires_at < timestamp.isoformat(),
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
    if claimed.rowcount != 1:
        return "busy"
    try:
        checkout = db.session.get(OnrampCheckout, session_id)
        license_record = get_or_create_license(transaction.provider_payment_id)
        license_file = build_license_file(
            license_record.license_key,
            license_record.issuance_reference,
            license_record.created_at,
        )
        send_license_email(
            decrypt(checkout.recipient_encrypted), license_file, beta=checkout.beta
        )
    except Exception:
        db.session.rollback()
        db.session.execute(
            db.update(OnrampCheckout)
            .where(
                OnrampCheckout.session_id == session_id,
                OnrampCheckout.lease_token == token,
            )
            .values(delivery_status="failed", lease_token=None, lease_expires_at=None)
        )
        db.session.commit()
        current_app.logger.warning("Onramp license email will be retried")
        return "failed"
    db.session.execute(
        db.update(OnrampCheckout)
        .where(
            OnrampCheckout.session_id == session_id,
            OnrampCheckout.lease_token == token,
        )
        .values(
            delivery_status="sent",
            recipient_encrypted=None,
            lease_token=None,
            lease_expires_at=None,
            sent_at=now().isoformat(),
        )
    )
    db.session.commit()
    return "sent"


def retry_deliveries() -> int:
    """Bounded timer job; purge abandoned PII and retry confirmed purchases."""
    cutoff = (now() - timedelta(days=7)).isoformat()
    db.session.execute(
        db.update(OnrampCheckout)
        .where(
            OnrampCheckout.created_at < cutoff,
            OnrampCheckout.recipient_encrypted.is_not(None),
            OnrampCheckout.delivery_status != "sent",
            or_(
                OnrampCheckout.lease_expires_at.is_(None),
                OnrampCheckout.lease_expires_at < now().isoformat(),
            ),
        )
        .values(delivery_status="expired")
    )
    db.session.execute(
        db.update(OnrampCheckout)
        .where(
            OnrampCheckout.created_at < cutoff,
            or_(
                OnrampCheckout.lease_expires_at.is_(None),
                OnrampCheckout.lease_expires_at < now().isoformat(),
            ),
        )
        .values(
            recipient_encrypted=None,
            checkout_encrypted=None,
            tracking_encrypted=None,
            callback_digest=None,
        )
    )
    db.session.commit()
    ids = (
        db.session.execute(
            db.select(OnrampCheckout.session_id)
            .join(
                Transaction,
                Transaction.session_id == OnrampCheckout.session_id,
            )
            .where(
                Transaction.status == "finished",
                OnrampCheckout.recipient_encrypted.is_not(None),
                OnrampCheckout.delivery_status != "sent",
            )
            .limit(100)
        )
        .scalars()
        .all()
    )
    for session_id in ids:
        deliver_license(session_id)
    return len(ids)
