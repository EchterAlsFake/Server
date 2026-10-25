"""Read-only provider progress, bound to known orders and cached across browsers.

Only the existing signed NOWPayments IPN fulfillment path can approve payment.
Neither unsigned callbacks nor any API observation changes Transaction.status.
"""

import re
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from urllib.parse import urlsplit

import httpx
from flask import current_app
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

from .extensions import db
from .models import OnrampCheckout, PaymentProgress, Transaction
from .webhook_models import NowPaymentsWebhook

PHASES = {"waiting": 0, "confirming": 1, "confirmed": 2, "sending": 3, "finished": 4}
PROBLEMS = {"partially_paid", "failed", "expired", "refunded", "wrong_asset_confirmed"}


def now():
    return datetime.now(timezone.utc)


def hosted_checkout_url(value):
    if not isinstance(value, str) or len(value) > 4096:
        return None
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme == "https"
            and parsed.hostname
            in {"nowpayments.io", "sandbox.nowpayments.io", "pay.nowpayments.io"}
            and not parsed.username
            and not parsed.password
            and parsed.port in {None, 443}
        ):
            return value
    except ValueError:
        pass
    return None


def progress_record(transaction):
    record = db.session.get(PaymentProgress, transaction.session_id)
    if record:
        return record
    checkout = db.session.get(OnrampCheckout, transaction.session_id)
    state = (
        checkout.payment_state
        if checkout and checkout.payment_state in PHASES.keys() | PROBLEMS
        else "waiting"
    )
    record = PaymentProgress(
        session_id=transaction.session_id,
        nowpayments_state=state,
        nowpayments_payment_id=transaction.provider_payment_id
        if transaction.provider_reference_type == "payment"
        else None,
    )
    db.session.add(record)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        record = db.session.get(PaymentProgress, transaction.session_id)
    return record


def record_nowpayments(webhook):
    """Bind every observation to the same order, provider reference, price and asset."""
    transaction = db.session.get(Transaction, webhook.order_id)
    state = (webhook.payment_status or "").lower()
    if (
        not transaction
        or transaction.status == "finished"
        or webhook.parent_payment_id
        or state not in PHASES.keys() | PROBLEMS
        or not webhook.payment_id
    ):
        return False
    reference = (
        webhook.invoice_id
        if transaction.provider_reference_type == "invoice"
        else webhook.payment_id
    )
    if (
        reference != transaction.provider_payment_id
        or webhook.price_amount != Decimal(transaction.expected_price_amount)
        or (webhook.price_currency or "").lower()
        != transaction.expected_price_currency.lower()
        or (
            transaction.expected_pay_currency
            and (webhook.pay_currency or "").lower()
            != transaction.expected_pay_currency.lower()
        )
    ):
        return False
    record = progress_record(transaction)
    # Different child/repeated deposits cannot replace the payment being tracked.
    predecessors = (
        list(PHASES)
        if state in PROBLEMS
        else [key for key, rank in PHASES.items() if rank <= PHASES[state]]
    )
    if state == "finished":
        predecessors += list(PROBLEMS)
    result = db.session.execute(
        db.update(PaymentProgress)
        .where(
            PaymentProgress.session_id == transaction.session_id,
            PaymentProgress.nowpayments_state.in_(predecessors),
            or_(
                PaymentProgress.nowpayments_payment_id.is_(None),
                PaymentProgress.nowpayments_payment_id == webhook.payment_id,
            ),
        )
        .values(
            nowpayments_state=state,
            nowpayments_payment_id=webhook.payment_id,
            nowpayments_updated_at=now().isoformat(),
        )
    )
    db.session.commit()
    return result.rowcount == 1


def _api_observation(payload):
    # Some provider API amounts are strings; the signed webhook parser stays strict.
    value = dict(payload)
    for field in ("price_amount", "pay_amount", "actually_paid"):
        if isinstance(value.get(field), str):
            amount = Decimal(value[field])
            if not amount.is_finite() or not 0 <= amount <= 1000000:
                raise ValueError("Invalid provider amount")
            value[field] = float(amount)
    return NowPaymentsWebhook.from_mapping(value)


def refresh_providers(transaction):
    """At most once per minute per order, with a shared DB lease and finite timeouts."""
    record = progress_record(transaction)
    if transaction.status == "finished" or transaction.provider_payment_id.startswith(
        "mock-"
    ):
        return record
    checkout = db.session.get(OnrampCheckout, transaction.session_id)
    query_now = bool(
        record.nowpayments_payment_id and current_app.config.get("NOWPAYMENTS_API_KEY")
    )
    query_onramp = bool(
        checkout
        and checkout.tracking_encrypted
        and current_app.config.get("ONRAMP_ENCRYPTION_KEY")
    )
    if not query_now and not query_onramp:
        return record
    timestamp = now()
    token = secrets.token_hex(24)
    claim = db.session.execute(
        db.update(PaymentProgress)
        .where(
            PaymentProgress.session_id == transaction.session_id,
            or_(
                PaymentProgress.checked_at.is_(None),
                PaymentProgress.checked_at
                < (timestamp - timedelta(seconds=60)).isoformat(),
            ),
            or_(
                PaymentProgress.poll_lease_until.is_(None),
                PaymentProgress.poll_lease_until < timestamp.isoformat(),
            ),
        )
        .values(
            poll_lease_until=(timestamp + timedelta(seconds=60)).isoformat(),
            poll_token=token,
        )
    )
    db.session.commit()
    if claim.rowcount != 1:
        return record
    unavailable = False
    try:
        with httpx.Client(timeout=4.0, follow_redirects=False) as client:
            if query_now:
                try:
                    payment_id = record.nowpayments_payment_id
                    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", payment_id):
                        raise ValueError("Invalid payment ID")
                    response = client.get(
                        f"{current_app.config['NOWPAYMENTS_API_URL']}/payment/{payment_id}",
                        headers={
                            "x-api-key": current_app.config["NOWPAYMENTS_API_KEY"]
                        },
                    )
                    response.raise_for_status()
                    observation = _api_observation(response.json())
                    if (
                        observation.order_id != transaction.session_id
                        or observation.payment_id != payment_id
                    ):
                        raise ValueError("Provider order mismatch")
                    record_nowpayments(observation)
                except httpx.HTTPError, ValueError, TypeError, ArithmeticError:
                    unavailable = True
            if query_onramp:
                try:
                    from .onramp_service import API_BASE, _get_json, decrypt

                    payload = _get_json(
                        client,
                        API_BASE + "/control/payment-status.php",
                        params={"ipn_token": decrypt(checkout.tracking_encrypted)},
                    )
                    if not isinstance(payload.get("status"), str):
                        raise ValueError("Missing provider status")
                    # The documented response only distinguishes paid from waiting.
                    # A payout transaction is evidence of forwarding, not license settlement.
                    if payload["status"].lower() == "paid":
                        amount = Decimal(str(payload.get("value_coin", "0")))
                        if (
                            not amount.is_finite()
                            or amount <= 0
                            or payload.get("coin") not in {None, "polygon_usdc"}
                        ):
                            raise ValueError("Invalid provider receipt")
                        state = (
                            "forwarded"
                            if isinstance(payload.get("txid_out"), str)
                            and re.fullmatch(r"0x[0-9a-fA-F]{64}", payload["txid_out"])
                            else "received"
                        )
                        allowed = (
                            (None, "received", "forwarded")
                            if state == "forwarded"
                            else (None, "received")
                        )
                        db.session.execute(
                            db.update(PaymentProgress)
                            .where(
                                PaymentProgress.session_id == transaction.session_id,
                                or_(
                                    PaymentProgress.onramp_state.is_(None),
                                    PaymentProgress.onramp_state.in_(
                                        [item for item in allowed if item]
                                    ),
                                ),
                            )
                            .values(
                                onramp_state=state, onramp_updated_at=now().isoformat()
                            )
                        )
                        db.session.commit()
                except Exception:
                    # Provider errors may include secret query parameters. Never log them.
                    db.session.rollback()
                    unavailable = True
    finally:
        db.session.execute(
            db.update(PaymentProgress)
            .where(
                PaymentProgress.session_id == transaction.session_id,
                PaymentProgress.poll_token == token,
            )
            .values(
                checked_at=now().isoformat(),
                poll_lease_until=None,
                poll_token=None,
                refresh_unavailable=unavailable,
            )
        )
        db.session.commit()
    return db.session.get(PaymentProgress, transaction.session_id)


def public_progress(transaction, checkout=None):
    record = db.session.get(PaymentProgress, transaction.session_id)
    state = record.nowpayments_state if record else "waiting"
    if checkout and checkout.payment_state in PROBLEMS:
        state = checkout.payment_state
    card = checkout is not None
    steps = (
        [
            ("provider", "Complete Banxa checkout"),
            ("onramp", "Onramp Pay receives crypto"),
            ("forwarding", "Crypto forwarded to NOWPayments"),
            ("blockchain", "Blockchain confirmations"),
            ("settlement", "NOWPayments settlement"),
            ("license", "License and invoice ready"),
        ]
        if card
        else [
            ("payment", "Send cryptocurrency"),
            ("blockchain", "Blockchain confirmations"),
            ("settlement", "NOWPayments settlement"),
            ("license", "License and invoice ready"),
        ]
    )
    index = 0
    title = "Waiting for Banxa checkout" if card else "Waiting for your crypto payment"
    message = (
        "Complete the provider checkout in the other tab. Updates appear here as funds move through the route."
        if card
        else "Open NOWPayments and follow the payment instructions. I’ll update this page when your transaction is detected."
    )
    if card and record and record.onramp_state == "received":
        index = 1
        title, message = (
            "Onramp Pay received crypto",
            "Onramp Pay reports receipt of crypto. Waiting for forwarding to NOWPayments.",
        )
    if card and record and record.onramp_state == "forwarded":
        index = 2
        title, message = (
            "Crypto forwarded to NOWPayments",
            "Onramp Pay reports the outgoing transfer. Waiting for NOWPayments to detect the payment on the blockchain.",
        )
    if state == "confirming":
        index = 3 if card else 1
        title, message = (
            "Payment detected. Waiting for blockchain confirmations.",
            "NOWPayments detected the crypto transfer. The blockchain is confirming it.",
        )
    if state in {"confirmed", "sending"}:
        index = 4 if card else 2
        title = "Blockchain confirmed. Completing settlement."
        message = "NOWPayments is settling the payment. Your license will be issued after the final receipt is verified."
    if state == "finished" or transaction.status == "processing":
        index = len(steps) - 1
        title, message = (
            "Payment reported complete. Preparing your license.",
            "Waiting for the verified final receipt and license generation. No further payment is needed.",
        )
    problem = state if state in PROBLEMS else None
    if problem:
        title = {
            "partially_paid": "Payment amount needs review",
            "failed": "Payment failed",
            "expired": "Payment window expired",
            "refunded": "Provider reports a refund",
            "wrong_asset_confirmed": "Payment asset needs review",
        }[problem]
        message = "A license has not been issued. If you sent money, contact support with your session ID. Do not pay again while the transfer is being reviewed."
    finished = transaction.status == "finished"
    if finished:
        index = len(steps)
        problem = None
        title, message = (
            "Your license and invoice are ready",
            "Payment verified. Save your license and invoice safely.",
        )
    return dict(
        title=title,
        message=message,
        stage="finished"
        if finished
        else problem or steps[min(index, len(steps) - 1)][0],
        steps=[
            dict(
                id=key,
                label=label,
                state="done" if i < index else "current" if i == index else "upcoming",
            )
            for i, (key, label) in enumerate(steps)
        ],
        updated_at=max(
            filter(
                None,
                (
                    record.checked_at,
                    record.nowpayments_updated_at,
                    record.onramp_updated_at,
                ),
            ),
            default=None,
        )
        if record
        else None,
        refresh_unavailable=bool(record and record.refresh_unavailable),
        provider_state=state,
        poll_after_ms=15000 if problem else 5000,
    )
