"""Test-only Mollie adapter. Only authenticated payment reads permit fulfillment."""

import base64
import hashlib
import hmac
import json
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from urllib.parse import urlsplit

import httpx
from flask import abort, current_app, session
from sqlalchemy import or_

from .extensions import db
from .models import Transaction, CheckoutRecovery, CryptoLicenseDelivery
from .mollie_models import MollieCheckout, MollieGrant

API = "https://api.mollie.com/v2"
PAYMENT_ID = re.compile(r"tr_[A-Za-z0-9]{1,120}")
TEST_NOTICE = "No money is charged. A successful test issues a real lifetime license."


def now():
    return datetime.now(timezone.utc)


def new_environment():
    return "production" if live_enabled() else "sandbox"


def configured(environment="sandbox"):
    config = current_app.config
    key = api_key(environment)
    return bool(
        key.startswith("live_" if environment == "production" else "test_")
        and re.fullmatch(r"pfl_[A-Za-z0-9]+", config.get("MOLLIE_PROFILE_ID", ""))
    )


def api_key(environment):
    if environment not in {"sandbox", "production"}:
        raise ValueError("Unknown payment environment")
    return current_app.config.get(
        "MOLLIE_LIVE_API_KEY" if environment == "production" else "MOLLIE_TEST_API_KEY",
        "",
    )


def live_enabled():
    """Mollie is retired; old credentials must never reopen checkout."""
    return False


def enabled():
    return False


def public_access():
    """A live browser gets a single-order nonce; no password is needed to buy."""
    token = session.get("mollie_grant", "")
    row = db.session.get(MollieGrant, digest(token)) if token else None
    if (
        row
        and row.expires_at > now().isoformat()
        and row.configuration == configuration()
    ):
        return row
    token = secrets.token_urlsafe(32)
    row = MollieGrant(
        digest=digest(token),
        configuration=configuration(),
        expires_at=(now() + timedelta(minutes=15)).isoformat(),
    )
    db.session.add(row)
    db.session.commit()
    session["mollie_grant"] = token
    return row


def configuration():
    config = current_app.config
    material = "\0".join(
        config.get(name, "")
        for name in (
            "MOLLIE_TEST_PASSWORD_HASH",
            "MOLLIE_TEST_API_KEY",
            "MOLLIE_LIVE_API_KEY",
            "MOLLIE_PROFILE_ID",
        )
    )
    return hashlib.sha256((material + str(live_enabled())).encode()).hexdigest()


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def grant():
    token = session.get("mollie_grant", "")
    row = (
        db.session.get(MollieGrant, digest(token))
        if isinstance(token, str) and token
        else None
    )
    if not row:
        abort(403, description="Unlock tester access first.")
    if row.order_id:
        from .checkout_recovery import resolve_session_id

        remember_recovery(row.order_id)
        resolve_session_id(row.order_id)
    elif row.expires_at <= now().isoformat() or not hmac.compare_digest(
        row.configuration, configuration()
    ):
        abort(403, description="Tester access expired. Enter the password again.")
    return row


def quote(country):
    """Future regional discounts belong here; browser prices are never accepted."""
    from .offer import PREMIUM_PRICE_TEXT

    return dict(
        amount=PREMIUM_PRICE_TEXT,
        currency="EUR",
        country=country,
        version="lifetime-eur-v1",
    )


def snapshot(country, accepted_at):
    from .contracts import terms_snapshot, dumps

    data = terms_snapshot()
    data.update(
        version=data["version"] + "-mollie-v2",
        payment_method="mollie",
        country=country,
        accepted_at=accepted_at,
        terms_accepted=True,
        age_confirmed=True,
        immediate_supply_consent=True,
        withdrawal_acknowledged=True,
        refund_method_accepted=False,
        refund_en="",
        refund_terms="",
        test_acknowledged=new_environment() == "sandbox",
        test_notice=TEST_NOTICE if new_environment() == "sandbox" else "",
    )
    return dumps(data)


def offer_digest():
    # Includes all accepted text and the price so a stale form cannot accept a changed offer.
    data = dict(terms=json.loads(snapshot(None, None)), quote=quote(None))
    return digest(json.dumps(data, sort_keys=True))


def remember_recovery(identifier):
    # Reconstruct the same bearer token after a lost response or concurrent request.
    # Requires the browser's original random grant secret and the server secret.
    material = session["mollie_grant"] + "\0" + identifier
    key = str(current_app.config["SECRET_KEY"]).encode()
    token = (
        base64.urlsafe_b64encode(
            hmac.new(key, material.encode(), hashlib.sha256).digest()[:16]
        )
        .decode()
        .rstrip("=")
    )
    cached = dict(session.get("checkout_recovery", {}))
    cached[identifier] = token
    session["checkout_recovery"] = dict(list(cached.items())[-8:])
    return token


def reserve(access, country, country_code, recipient):
    """Consume the grant and persist the complete order/recovery identity atomically."""
    from .crypto_delivery import encrypt_recipient
    from .checkout_recovery import _digest

    timestamp = now().isoformat()
    price = quote(country_code)
    identifier = "ML-" + secrets.token_urlsafe(16)
    encrypted = encrypt_recipient(recipient)
    claim = db.session.execute(
        db.update(MollieGrant)
        .where(
            MollieGrant.digest == access.digest,
            MollieGrant.order_id.is_(None),
            MollieGrant.configuration == configuration(),
            MollieGrant.expires_at > timestamp,
        )
        .values(order_id=identifier)
    )
    if claim.rowcount != 1:
        db.session.rollback()
        return grant().order_id
    db.session.add(
        Transaction(
            session_id=identifier,
            provider="mollie",
            provider_payment_id="mollie-pending-" + identifier,
            provider_reference_type="payment",
            environment=new_environment(),
            expected_price_amount=price["amount"],
            expected_price_currency=price["currency"],
            customer_country=country.country_name,
            country_evidence=country.evidence_source,
            geolocation_database=country.database_label,
            status="pending",
            created_at=timestamp,
            customer_email_encrypted=encrypted,
            contract_snapshot=snapshot(country_code, timestamp),
        )
    )
    db.session.add(
        MollieCheckout(
            session_id=identifier,
            profile_id=current_app.config["MOLLIE_PROFILE_ID"],
            payload=json.dumps(
                dict(
                    amount=dict(currency=price["currency"], value=price["amount"]),
                    description="Porn Fetch lifetime Premium license"
                    + (" (sandbox test)" if new_environment() == "sandbox" else ""),
                    redirectUrl=current_app.config["APP_DOMAIN"]
                    + "/buy_success?session_id="
                    + identifier,
                    webhookUrl=current_app.config["API_DOMAIN"] + "/mollie/webhook",
                    metadata=dict(order_id=identifier),
                    sequenceType="oneoff",
                )
            ),
            idempotency_key=str(uuid.uuid4()),
            pricing_version=price["version"],
            country_code=country_code,
            next_attempt_at=timestamp,
        )
    )
    token = remember_recovery(identifier)
    db.session.add(
        CheckoutRecovery(
            session_id=identifier, token_digest=_digest(token), created_at=timestamp
        )
    )
    db.session.add(
        CryptoLicenseDelivery(
            session_id=identifier, recipient_encrypted=encrypted, created_at=timestamp
        )
    )
    db.session.commit()
    return identifier


def checkout_url(value):
    if not isinstance(value, str) or len(value) > 4096:
        return None
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme == "https"
            and parsed.hostname == "www.mollie.com"
            and parsed.path.startswith("/checkout/")
            and not parsed.username
            and not parsed.password
            and parsed.port in (None, 443)
        ):
            return value
    except ValueError:
        pass
    return None


def request_api(method, path, *, environment="sandbox", **kwargs):
    if not configured(environment):
        raise ValueError("Mollie test credentials unavailable")
    # A profile-specific test key selects mode; never send a conflicting testmode field.
    response = httpx.request(
        method,
        API + path,
        headers={
            "Authorization": "Bearer " + api_key(environment),
            **kwargs.pop("headers", {}),
        },
        timeout=10,
        follow_redirects=False,
        **kwargs,
    )
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError("Invalid payment response")
    return data


def verify(payment, row, transaction):
    metadata = payment.get("metadata")
    amount = payment.get("amount")
    if (
        not isinstance(metadata, dict)
        or not isinstance(amount, dict)
        or payment.get("mode")
        != ("live" if transaction.environment == "production" else "test")
        or payment.get("profileId") != row.profile_id
        or row.profile_id != current_app.config.get("MOLLIE_PROFILE_ID")
        or metadata.get("order_id") != row.session_id
        or not PAYMENT_ID.fullmatch(str(payment.get("id", "")))
        or (row.payment_id and payment["id"] != row.payment_id)
        or amount.get("currency") != transaction.expected_price_currency
        or Decimal(str(amount.get("value")))
        != Decimal(transaction.expected_price_amount)
    ):
        raise ValueError("Payment verification failed")
    for name in ("amountRefunded", "amountChargedBack"):
        value = payment.get(name) or dict(
            currency=transaction.expected_price_currency, value="0.00"
        )
        if (
            not isinstance(value, dict)
            or value.get("currency") != transaction.expected_price_currency
            or not Decimal(str(value.get("value"))).is_finite()
            or Decimal(str(value["value"])) < 0
        ):
            raise ValueError("Invalid reversal amount")
    if payment.get("status") not in {
        "open",
        "pending",
        "authorized",
        "paid",
        "canceled",
        "expired",
        "failed",
    }:
        raise ValueError("Unknown payment status")


def process_order(identifier, *, force=False):
    """One leased processor handles creation, authenticated verification and issuance."""
    from .licensing import fulfill_transaction_license
    from .invoice_service import build_invoice, load_invoice, save_invoice

    timestamp = now()
    lease = secrets.token_hex(24)
    query = db.update(MollieCheckout).where(
        MollieCheckout.session_id == identifier,
        or_(
            MollieCheckout.lease_expires_at.is_(None),
            MollieCheckout.lease_expires_at < timestamp.isoformat(),
        ),
    )
    if not force:
        query = query.where(MollieCheckout.next_attempt_at <= timestamp.isoformat())
    claimed = db.session.execute(
        query.values(
            lease_token=lease,
            lease_expires_at=(timestamp + timedelta(minutes=10)).isoformat(),
            attempts=MollieCheckout.attempts + 1,
        )
    )
    db.session.commit()
    if claimed.rowcount != 1:
        return False
    try:
        row = db.session.get(MollieCheckout, identifier)
        transaction = db.session.get(Transaction, identifier)
        notification_version = row.notification_version
        if (
            not transaction
            or transaction.provider != "mollie"
            or transaction.environment not in {"sandbox", "production"}
        ):
            raise ValueError("Invalid transaction")
        if not row.payment_id:
            # Retirement also blocks creation of payments reserved before removal.
            row.state, row.last_error = "review", "provider_retired"
            db.session.commit()
            return False
        # Creation responses are never sufficient authority for license issuance.
        payment = request_api(
            "GET", "/payments/" + row.payment_id, environment=transaction.environment
        )
        verify(payment, row, transaction)
        if transaction.provider_payment_id != payment["id"]:
            raise ValueError("Payment binding mismatch")
        row.state, row.last_error = payment["status"], None
        row.processed_notification_version = notification_version
        row.refunded_amount = (payment.get("amountRefunded") or {}).get("value", "0.00")
        row.chargeback_amount = (payment.get("amountChargedBack") or {}).get(
            "value", "0.00"
        )
        row.checked_at = now().isoformat()
        db.session.commit()
        reversed_payment = (
            Decimal(row.refunded_amount) > 0 or Decimal(row.chargeback_amount) > 0
        )
        if (
            row.state == "paid"
            and not reversed_payment
            and transaction.status != "finished"
        ):
            # Real Keygen lifetime policy, with test provenance metadata only.
            fulfill_transaction_license(transaction)
            if load_invoice(identifier) is None:
                invoice = build_invoice(
                    fiat_amount=float(transaction.expected_price_amount),
                    crypto_amount=0,
                    pay_currency="EUR",
                    transaction_hash=row.payment_id,
                    environment=transaction.environment,
                )
                invoice.update(
                    {
                        "Provider": "mollie",
                        "Invoice Number": (
                            "TEST-ML-"
                            if transaction.environment == "sandbox"
                            else "INV-ML-"
                        )
                        + digest(identifier)[:16].upper(),
                        "Invoice Date": transaction.created_at,
                        "Delivery Date": row.checked_at,
                        "Payment Reference": row.payment_id,
                        "Test Amount": transaction.expected_price_amount + " EUR",
                    }
                )
                save_invoice(identifier, invoice)
            finished = db.session.execute(
                db.update(Transaction)
                .where(
                    Transaction.session_id == identifier,
                    Transaction.status == "pending",
                    db.select(MollieCheckout.session_id)
                    .where(
                        MollieCheckout.session_id == identifier,
                        MollieCheckout.lease_token == lease,
                        MollieCheckout.lease_expires_at > now().isoformat(),
                    )
                    .exists(),
                )
                .values(status="finished", finished_at=now().isoformat())
            )
            db.session.commit()
            if finished.rowcount:
                from .crypto_delivery import deliver_crypto_license

                deliver_crypto_license(identifier)
        return True
    except Exception as error:
        db.session.rollback()
        # Do not log provider bodies, credential-bearing requests or customer data.
        code = (
            "verification_failed"
            if isinstance(error, (ValueError, TypeError, KeyError, ArithmeticError))
            else "provider_or_delivery_unavailable"
        )
        db.session.execute(
            db.update(MollieCheckout)
            .where(
                MollieCheckout.session_id == identifier,
                MollieCheckout.lease_token == lease,
            )
            .values(last_error=code)
        )
        db.session.commit()
        current_app.logger.warning("Mollie processing deferred (reason=%s)", code)
        return False
    finally:
        db.session.execute(
            db.update(MollieCheckout)
            .where(
                MollieCheckout.session_id == identifier,
                MollieCheckout.lease_token == lease,
            )
            .values(
                lease_token=None,
                lease_expires_at=None,
                next_attempt_at=(now() + timedelta(minutes=1)).isoformat(),
            )
        )
        db.session.commit()


def process_pending(limit=100):
    """Called every minute, including when new tester access has been disabled."""
    if not configured() and not configured("production"):
        return 0
    timestamp = now().isoformat()
    ids = (
        db.session.execute(
            db.select(MollieCheckout.session_id)
            .join(Transaction)
            .where(
                MollieCheckout.next_attempt_at <= timestamp,
                or_(
                    Transaction.status != "finished",
                    MollieCheckout.state.in_(["open", "pending", "authorized"]),
                ),
                Transaction.created_at > (now() - timedelta(days=7)).isoformat(),
                or_(
                    MollieCheckout.lease_expires_at.is_(None),
                    MollieCheckout.lease_expires_at < timestamp,
                ),
            )
            .order_by(MollieCheckout.next_attempt_at)
            .limit(limit)
        )
        .scalars()
        .all()
    )
    for identifier in ids:
        process_order(identifier)
    # Finished orders can still receive reversal notifications.
    notified = (
        db.session.execute(
            db.select(MollieCheckout.session_id)
            .join(Transaction)
            .where(
                Transaction.status == "finished",
                MollieCheckout.next_attempt_at <= timestamp,
                or_(
                    MollieCheckout.notification_version
                    > MollieCheckout.processed_notification_version,
                    MollieCheckout.last_error.is_not(None),
                ),
            )
            .limit(limit)
        )
        .scalars()
        .all()
    )
    for identifier in notified:
        process_order(identifier)
    from .crypto_delivery import deliver_crypto_license

    deliveries = (
        db.session.execute(
            db.select(CryptoLicenseDelivery.session_id)
            .join(
                Transaction, Transaction.session_id == CryptoLicenseDelivery.session_id
            )
            .where(
                Transaction.provider == "mollie",
                Transaction.status == "finished",
                CryptoLicenseDelivery.delivery_status.in_(
                    ["pending", "failed", "sending"]
                ),
            )
            .limit(limit)
        )
        .scalars()
        .all()
    )
    for identifier in deliveries:
        deliver_crypto_license(identifier)
    db.session.execute(
        db.delete(MollieGrant).where(
            MollieGrant.expires_at < (now() - timedelta(days=7)).isoformat()
        )
    )
    db.session.commit()
    return len(ids) + len(notified)


def progress(transaction, *, license_pending=False):
    row = db.session.get(MollieCheckout, transaction.session_id)
    state = row.state
    finished = transaction.status == "finished" and not license_pending
    problem = state in {"failed", "expired", "canceled", "review"}
    title = (
        "Your lifetime license is ready."
        if finished
        else (
            "Preparing your lifetime license…"
            if state == "paid"
            else "Test checkout needs attention"
            if problem
            else "Complete your checkout"
        )
    )
    message = (
        TEST_NOTICE
        if transaction.environment == "sandbox"
        else "Your license and receipt will appear here after payment is verified."
    )
    if problem:
        message = (
            "This attempt needs manual reconciliation. Contact support; do not start another payment."
            if state == "review"
            else "This payment is "
            + state
            + ". Return to payment methods to start again."
        )
    return dict(
        title=title,
        message=message,
        activity="attention" if problem else "complete" if finished else "active",
        stage="finished"
        if finished
        else "license"
        if state == "paid"
        else state
        if problem
        else "payment",
        provider_state=state,
        updated_at=row.checked_at,
        refresh_unavailable=bool(row.last_error),
        poll_after_ms=5000,
        steps=[
            dict(
                id=key,
                label=label,
                state="done"
                if finished or (state == "paid" and i == 0)
                else "current"
                if i == (1 if state == "paid" else 0)
                else "upcoming",
            )
            for i, (key, label) in enumerate(
                [
                    ("payment", "Payment"),
                    ("license", "Prepare lifetime license"),
                    ("ready", "Download and email"),
                ]
            )
        ],
    )
