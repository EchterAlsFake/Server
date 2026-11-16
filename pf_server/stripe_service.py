"""Stripe Checkout adapter. Only authenticated payment reads permit fulfillment."""

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
from .stripe_models import StripeCheckout, StripeGrant

API = "https://api.stripe.com/v1"
PAYMENT_ID = re.compile(r"cs_(?:test_|live_)?[A-Za-z0-9]{1,200}")
TEST_NOTICE = "No money is charged. A successful test issues a real lifetime license."
MANAGED_RECEIPT = "stripe_managed_receipt"
SOFTWARE_TAX_CODE = "txcd_10202000"


def now():
    return datetime.now(timezone.utc)


def new_environment():
    return "production" if live_enabled() else "sandbox"


def configured(environment="sandbox"):
    key = api_key(environment)
    prefixes = (
        ("rk_live_", "sk_live_")
        if environment == "production"
        else ("rk_test_", "sk_test_")
    )
    return bool(
        key.startswith(prefixes)
        and re.fullmatch(r"acct_[A-Za-z0-9]+", account_id(environment))
    )


def account_id(environment):
    if environment not in {"sandbox", "production"}:
        raise ValueError("Unknown payment environment")
    config = current_app.config
    name = (
        "STRIPE_LIVE_ACCOUNT_ID"
        if environment == "production"
        else "STRIPE_TEST_ACCOUNT_ID"
    )
    return config.get(name, "") or config.get("STRIPE_ACCOUNT_ID", "")


def api_key(environment):
    if environment not in {"sandbox", "production"}:
        raise ValueError("Unknown payment environment")
    return current_app.config.get(
        "STRIPE_LIVE_API_KEY" if environment == "production" else "STRIPE_TEST_API_KEY",
        "",
    )


def live_enabled():
    return bool(
        current_app.config.get("STRIPE_LIVE_ENABLED")
        and configured("production")
        and current_app.config.get("STRIPE_LIVE_WEBHOOK_SECRET", "").startswith(
            "whsec_"
        )
    )


def enabled():
    return live_enabled() or bool(
        current_app.config.get("STRIPE_TEST_ENABLED")
        and configured()
        and current_app.config.get("STRIPE_TEST_WEBHOOK_SECRET", "").startswith(
            "whsec_"
        )
        and current_app.config.get("STRIPE_TEST_PASSWORD_HASH", "").startswith(
            ("scrypt:", "pbkdf2:")
        )
    )


def public_access():
    """A live browser gets a single-order nonce; no password is needed to buy."""
    token = session.get("stripe_grant", "")
    row = db.session.get(StripeGrant, digest(token)) if token else None
    if (
        row
        and row.expires_at > now().isoformat()
        and row.configuration == configuration()
    ):
        return row
    token = secrets.token_urlsafe(32)
    row = StripeGrant(
        digest=digest(token),
        configuration=configuration(),
        expires_at=(now() + timedelta(minutes=15)).isoformat(),
    )
    db.session.add(row)
    db.session.commit()
    session["stripe_grant"] = token
    return row


def configuration():
    config = current_app.config
    material = "\0".join(
        config.get(name, "")
        for name in (
            "STRIPE_TEST_PASSWORD_HASH",
            "STRIPE_TEST_API_KEY",
            "STRIPE_LIVE_API_KEY",
            "STRIPE_ACCOUNT_ID",
            "STRIPE_TEST_ACCOUNT_ID",
            "STRIPE_LIVE_ACCOUNT_ID",
        )
    )
    return hashlib.sha256((material + str(live_enabled())).encode()).hexdigest()


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def grant():
    token = session.get("stripe_grant", "")
    row = (
        db.session.get(StripeGrant, digest(token))
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
        version="lifetime-eur-managed-v1",
    )


def snapshot(country, accepted_at):
    from .contracts import terms_snapshot, dumps

    data = terms_snapshot(managed_payments=True)
    data.update(
        version=data["version"] + "-stripe-managed-v1",
        payment_method="stripe",
        managed_payments=True,
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
    material = session["stripe_grant"] + "\0" + identifier
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
    identifier = "ST-" + secrets.token_urlsafe(16)
    encrypted = encrypt_recipient(recipient)
    claim = db.session.execute(
        db.update(StripeGrant)
        .where(
            StripeGrant.digest == access.digest,
            StripeGrant.order_id.is_(None),
            StripeGrant.configuration == configuration(),
            StripeGrant.expires_at > timestamp,
        )
        .values(order_id=identifier)
    )
    if claim.rowcount != 1:
        db.session.rollback()
        return grant().order_id
    db.session.add(
        Transaction(
            session_id=identifier,
            provider="stripe",
            provider_payment_id="stripe-pending-" + identifier,
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
        StripeCheckout(
            session_id=identifier,
            account_id=account_id(new_environment()),
            payload=json.dumps(
                dict(
                    mode="payment",
                    managed_payments=dict(enabled=True),
                    line_items=[
                        dict(
                            price_data=dict(
                                currency="eur",
                                unit_amount=int(Decimal(price["amount"]) * 100),
                                tax_behavior="inclusive",
                                product_data=dict(
                                    name="Porn Fetch lifetime Premium license",
                                    tax_code=SOFTWARE_TAX_CODE,
                                ),
                            ),
                            quantity=1,
                        )
                    ],
                    success_url=current_app.config["APP_DOMAIN"]
                    + "/buy_success?session_id="
                    + identifier,
                    cancel_url=current_app.config["APP_DOMAIN"]
                    + "/buy_success?session_id="
                    + identifier,
                    client_reference_id=identifier,
                    metadata=dict(order_id=identifier),
                    payment_intent_data=dict(metadata=dict(order_id=identifier)),
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
            and parsed.hostname == "checkout.stripe.com"
            and parsed.path.startswith("/c/pay/")
            and not parsed.username
            and not parsed.password
            and parsed.port in (None, 443)
        ):
            return value
    except ValueError:
        pass
    return None


def _form_fields(value, prefix=""):
    result = {}
    if isinstance(value, dict):
        for key, item in value.items():
            result.update(_form_fields(item, f"{prefix}[{key}]" if prefix else key))
    elif isinstance(value, list):
        for key, item in enumerate(value):
            result.update(_form_fields(item, f"{prefix}[{key}]"))
    else:
        result[prefix] = str(value).lower() if isinstance(value, bool) else str(value)
    return result


def managed_checkout(row):
    return json.loads(row.payload).get("managed_payments", {}).get("enabled") is True


def receipt_url(value):
    """Only redirect buyers to receipt URLs returned by authenticated Stripe reads."""
    if not isinstance(value, str) or len(value) > 4096:
        return None
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme == "https"
            and parsed.hostname
            in {
                "invoice.stripe.com",
                "pay.stripe.com",
                "billing.stripe.com",
                "app.link.com",
                "pay.link.com",
            }
            and not parsed.username
            and not parsed.password
            and parsed.port in (None, 443)
        ):
            return value
    except ValueError:
        pass
    return None


def managed_receipt(payment, row, transaction):
    """Persist provider document references, without issuing a second tax invoice."""
    invoice = payment.get("invoice")
    invoice = invoice if isinstance(invoice, dict) else {}
    intent = payment.get("payment_intent")
    intent = intent if isinstance(intent, dict) else {}
    charge = intent.get("latest_charge")
    charge = charge if isinstance(charge, dict) else {}
    return {
        "Document Type": MANAGED_RECEIPT,
        "Provider": "stripe",
        "Environment": transaction.environment,
        "Invoice Number": invoice.get("number") or row.payment_id,
        "Stripe Invoice ID": invoice.get("id"),
        "Stripe Invoice URL": receipt_url(invoice.get("hosted_invoice_url")),
        "Stripe Invoice PDF": receipt_url(invoice.get("invoice_pdf")),
        "Stripe Receipt URL": receipt_url(charge.get("receipt_url")),
        "Payment Reference": row.payment_id,
    }


def managed_document_url(document):
    return next(
        (
            url
            for key in (
                "Stripe Invoice PDF",
                "Stripe Invoice URL",
                "Stripe Receipt URL",
            )
            if (url := receipt_url(document.get(key)))
        ),
        None,
    )


def request_api(method, path, *, environment="sandbox", **kwargs):
    if not configured(environment):
        raise ValueError("Stripe credentials unavailable")
    headers = {
        "Authorization": "Bearer " + api_key(environment),
        "Stripe-Version": "2026-10-28.endive",
        **kwargs.pop("headers", {}),
    }
    if "json" in kwargs:
        kwargs["data"] = _form_fields(kwargs.pop("json"))
    response = httpx.request(
        method,
        API + path,
        headers=headers,
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
    expected = int(Decimal(transaction.expected_price_amount) * 100)
    if (
        payment.get("object") != "checkout.session"
        or payment.get("livemode") is not (transaction.environment == "production")
        or payment.get("mode") != "payment"
        or (
            managed_checkout(row)
            and payment.get("managed_payments", {}).get("enabled") is not True
        )
        or row.account_id != account_id(transaction.environment)
        or payment.get("metadata", {}).get("order_id") != row.session_id
        or payment.get("client_reference_id") != row.session_id
        or not PAYMENT_ID.fullmatch(str(payment.get("id", "")))
        or (row.payment_id and payment["id"] != row.payment_id)
        or payment.get("currency") != transaction.expected_price_currency.lower()
        or type(payment.get("amount_total")) is not int
        or payment["amount_total"] != expected
        or payment.get("status") not in {"open", "complete", "expired"}
        or payment.get("payment_status")
        not in {"paid", "unpaid", "no_payment_required"}
    ):
        raise ValueError("Payment verification failed")


def expected_amount(transaction):
    return int(Decimal(transaction.expected_price_amount) * 100)


def payment_state(payment):
    if payment["status"] == "complete" and payment["payment_status"] == "paid":
        return "paid"
    return (
        "expired"
        if payment["status"] == "expired"
        else "pending"
        if payment["status"] == "complete"
        else "open"
    )


def process_order(identifier, *, force=False):
    """One leased processor handles creation, authenticated verification and issuance."""
    from .licensing import fulfill_transaction_license
    from .invoice_service import build_invoice, load_invoice, save_invoice

    timestamp = now()
    lease = secrets.token_hex(24)
    query = db.update(StripeCheckout).where(
        StripeCheckout.session_id == identifier,
        or_(
            StripeCheckout.lease_expires_at.is_(None),
            StripeCheckout.lease_expires_at < timestamp.isoformat(),
        ),
    )
    if not force:
        query = query.where(StripeCheckout.next_attempt_at <= timestamp.isoformat())
    claimed = db.session.execute(
        query.values(
            lease_token=lease,
            lease_expires_at=(timestamp + timedelta(minutes=10)).isoformat(),
            attempts=StripeCheckout.attempts + 1,
        )
    )
    db.session.commit()
    if claimed.rowcount != 1:
        return False
    try:
        row = db.session.get(StripeCheckout, identifier)
        transaction = db.session.get(Transaction, identifier)
        notification_version = row.notification_version
        if (
            not transaction
            or transaction.provider != "stripe"
            or transaction.environment not in {"sandbox", "production"}
        ):
            raise ValueError("Invalid transaction")
        if not row.payment_id:
            if not row.first_attempt_at:
                row.first_attempt_at = timestamp.isoformat()
                db.session.commit()
            if now() - datetime.fromisoformat(row.first_attempt_at) >= timedelta(
                minutes=55
            ):
                row.state, row.last_error = "review", "creation_reconciliation_required"
                db.session.commit()
                return False
            account = request_api(
                "GET", "/account", environment=transaction.environment
            )
            if account.get("id") != row.account_id:
                raise ValueError("Stripe account mismatch")
            payment = request_api(
                "POST",
                "/checkout/sessions",
                json=json.loads(row.payload),
                headers={"Idempotency-Key": row.idempotency_key},
                environment=transaction.environment,
            )
            verify(payment, row, transaction)
            url = checkout_url(payment.get("url"))
            if not url:
                raise ValueError("Invalid checkout URL")
            row.payment_id, row.checkout_url = payment["id"], url
            transaction.provider_payment_id = payment["id"]
            db.session.commit()
        # The return URL and webhook payload never authorize fulfillment.
        payment = request_api(
            "GET",
            "/checkout/sessions/" + row.payment_id,
            environment=transaction.environment,
            params={"expand[]": ["payment_intent.latest_charge", "invoice"]},
        )
        verify(payment, row, transaction)
        if transaction.provider_payment_id != payment["id"]:
            raise ValueError("Payment binding mismatch")
        intent = payment.get("payment_intent")
        row.payment_intent_id = intent.get("id") if isinstance(intent, dict) else intent
        row.state, row.last_error = payment_state(payment), None
        row.processed_notification_version = notification_version
        if row.state == "paid":
            intent = payment.get("payment_intent")
            charge = intent.get("latest_charge") if isinstance(intent, dict) else None
            if (
                not isinstance(charge, dict)
                or intent.get("status") != "succeeded"
                or charge.get("paid") is not True
                or charge.get("amount") != expected_amount(transaction)
                or charge.get("currency") != transaction.expected_price_currency.lower()
            ):
                raise ValueError("Payment charge verification failed")
            row.refunded_amount = str(Decimal(charge.get("amount_refunded", 0)) / 100)
            row.chargeback_amount = (
                transaction.expected_price_amount if charge.get("disputed") else "0.00"
            )
        row.checked_at = now().isoformat()
        db.session.commit()
        reversed_payment = (
            Decimal(row.refunded_amount) > 0 or Decimal(row.chargeback_amount) > 0
        )
        if row.state == "paid" and managed_checkout(row):
            save_invoice(identifier, managed_receipt(payment, row, transaction))
        if (
            row.state == "paid"
            and not reversed_payment
            and transaction.status != "finished"
        ):
            # Real Keygen lifetime policy, with test provenance metadata only.
            fulfill_transaction_license(transaction)
            if not managed_checkout(row) and load_invoice(identifier) is None:
                invoice = build_invoice(
                    fiat_amount=float(transaction.expected_price_amount),
                    crypto_amount=0,
                    pay_currency="EUR",
                    transaction_hash=row.payment_id,
                    environment=transaction.environment,
                )
                invoice.update(
                    {
                        "Provider": "stripe",
                        "Invoice Number": (
                            "TEST-ST-"
                            if transaction.environment == "sandbox"
                            else "INV-ST-"
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
                    db.select(StripeCheckout.session_id)
                    .where(
                        StripeCheckout.session_id == identifier,
                        StripeCheckout.lease_token == lease,
                        StripeCheckout.lease_expires_at > now().isoformat(),
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
            db.update(StripeCheckout)
            .where(
                StripeCheckout.session_id == identifier,
                StripeCheckout.lease_token == lease,
            )
            .values(last_error=code)
        )
        db.session.commit()
        current_app.logger.warning("Stripe processing deferred (reason=%s)", code)
        return False
    finally:
        db.session.execute(
            db.update(StripeCheckout)
            .where(
                StripeCheckout.session_id == identifier,
                StripeCheckout.lease_token == lease,
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
            db.select(StripeCheckout.session_id)
            .join(Transaction)
            .where(
                StripeCheckout.next_attempt_at <= timestamp,
                or_(
                    Transaction.status != "finished",
                    StripeCheckout.state.in_(["open", "pending", "authorized"]),
                ),
                Transaction.created_at > (now() - timedelta(days=7)).isoformat(),
                or_(
                    StripeCheckout.lease_expires_at.is_(None),
                    StripeCheckout.lease_expires_at < timestamp,
                ),
            )
            .order_by(StripeCheckout.next_attempt_at)
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
            db.select(StripeCheckout.session_id)
            .join(Transaction)
            .where(
                Transaction.status == "finished",
                StripeCheckout.next_attempt_at <= timestamp,
                or_(
                    StripeCheckout.notification_version
                    > StripeCheckout.processed_notification_version,
                    StripeCheckout.last_error.is_not(None),
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
                Transaction.provider == "stripe",
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
        db.delete(StripeGrant).where(
            StripeGrant.expires_at < (now() - timedelta(days=7)).isoformat()
        )
    )
    db.session.commit()
    return len(ids) + len(notified)


def progress(transaction, *, license_pending=False):
    row = db.session.get(StripeCheckout, transaction.session_id)
    state = row.state
    finished = transaction.status == "finished" and not license_pending
    problem = state in {"failed", "expired", "canceled", "review"}
    title = (
        "Your lifetime license is ready."
        if finished
        else (
            "Preparing your lifetime license…"
            if state == "paid"
            else "Checkout needs attention"
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
