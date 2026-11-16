"""Password-gated sandbox routes; all payment authority stays on the server."""

import secrets
from datetime import timedelta

from flask import (
    Blueprint,
    abort,
    current_app,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash
from werkzeug.exceptions import Forbidden

from .extensions import csrf, db, limiter, browser_limit_key
from .stripe_models import StripeCheckout, StripeGrant
from . import stripe_service as stripe

stripe_bp = Blueprint("stripe", __name__)


def require_enabled():
    if not stripe.enabled():
        abort(404)


def require_sandbox():
    if not stripe.test_enabled():
        abort(404)
    g.stripe_sandbox_checkout = True


@stripe_bp.get("/stripe/test")
def review():
    require_sandbox()
    try:
        access = stripe.grant()
    except Forbidden:
        return render_template("stripe_unlock.html")
    if access.order_id:
        return redirect(
            url_for("payments.buy_success", session_id=access.order_id), code=303
        )
    return checkout_page(test_mode=True)


def checkout_page(*, test_mode=False):
    from .countries import COUNTRY_OPTIONS
    from .contracts import IMMEDIATE_EN

    return render_template(
        "stripe_checkout.html",
        managed_payments=True,
        countries=COUNTRY_OPTIONS,
        immediate_consent=IMMEDIATE_EN,
        stripe_offer_digest=stripe.offer_digest(),
        test_mode=test_mode,
        test_notice=stripe.TEST_NOTICE,
        test_quote=stripe.quote(None),
    )


@stripe_bp.post("/stripe/unlock")
@limiter.limit("5 per minute", key_func=browser_limit_key)
@limiter.limit(
    "5 per minute",
    key_func=lambda: request.environ.get("PF_MOLLIE_LIMIT_KEY", "unknown-address"),
)
def unlock():
    require_sandbox()
    password = request.form.get("password", "")
    try:
        valid = len(password) <= 1024 and check_password_hash(
            current_app.config["STRIPE_TEST_PASSWORD_HASH"], password
        )
    except ValueError, TypeError:
        valid = False
    if not valid:
        return render_template(
            "stripe_unlock.html", error="Incorrect tester password."
        ), 403
    token = secrets.token_urlsafe(32)
    db.session.add(
        StripeGrant(
            digest=stripe.digest(token),
            configuration=stripe.configuration(),
            expires_at=(stripe.now() + timedelta(minutes=15)).isoformat(),
        )
    )
    db.session.commit()
    session[stripe.grant_session_key()] = token
    return redirect(url_for("stripe.review"), code=303)


@stripe_bp.post("/stripe/lock")
def lock():
    g.stripe_sandbox_checkout = True
    token = session.pop(stripe.grant_session_key(), "")
    if isinstance(token, str) and token:
        db.session.execute(
            db.delete(StripeGrant).where(StripeGrant.digest == stripe.digest(token))
        )
        db.session.commit()
    return redirect(url_for("pages.porn_fetch"), code=303)


@stripe_bp.post("/stripe/test/checkout")
def create_test_checkout():
    require_sandbox()
    return create_checkout()


@stripe_bp.post("/stripe/checkout")
@limiter.limit("20 per hour", key_func=browser_limit_key)
def create_checkout():
    require_enabled()
    access = stripe.grant()
    identifier = access.order_id
    if not identifier:
        from .payment_routes import validate_checkout_country
        from .licensing import normalize_recipient_email
        from .tor_checkout import checkout_network_status

        if checkout_network_status() != "clear":
            return jsonify(
                error="Use a direct connection; network verification is required."
            ), 403
        if request.form.get("offer_digest") != stripe.offer_digest():
            return jsonify(
                error="The offer has changed. Reload and review the checkout again."
            ), 409
        required = ["age_terms_accepted", "withdrawal_accepted"]
        if stripe.new_environment() == "sandbox":
            required.append("test_acknowledged")
        if any(request.form.get(name) != "yes" for name in required):
            return jsonify(
                error="Accept the required confirmations before continuing."
            ), 400
        # The existing country validator accepts dictionaries, not Flask MultiDict.
        country, error = validate_checkout_country(dict(request.form))
        if error:
            return error
        recipient = normalize_recipient_email(request.form.get("email"))
        if not recipient:
            return jsonify(error="Enter a valid license delivery email."), 400
        try:
            identifier = stripe.reserve(
                access, country, request.form["country"], recipient
            )
        except ValueError, TypeError, AttributeError:
            db.session.rollback()
            return jsonify(
                error="Email delivery is not configured. Please try again later."
            ), 503
    stripe.process_order(identifier)
    # Show the private recovery page first so the link can be saved before leaving.
    target = url_for("payments.buy_success", session_id=identifier)
    if request.headers.get("Accept") == "application/json":
        return jsonify(next=target)
    return redirect(target, code=303)


@stripe_bp.get("/stripe/launch")
def launch():

    from .checkout_recovery import resolve_session_id

    identifier = resolve_session_id()
    row = db.session.get(StripeCheckout, identifier)
    if (
        not row
        or not row.payment_id
        or row.state not in {"open", "pending", "authorized"}
    ):
        abort(
            409,
            description="This checkout is unavailable. Check your order status.",
        )
    target = stripe.checkout_url(row.checkout_url)
    if not target:
        abort(503)
    return redirect(target, code=303)


@stripe_bp.post("/stripe/webhook")
@csrf.exempt
@limiter.limit("20 per second")
def webhook():
    from .payment_routes import require_api_subdomain

    require_api_subdomain()
    import hashlib
    import hmac
    import json
    import time

    raw = request.get_data()
    if len(raw) > 1024 * 1024:
        abort(413)
    try:
        parts = request.headers.get("Stripe-Signature", "").split(",")
        timestamp = next(p[2:] for p in parts if p.startswith("t="))
        if abs(time.time() - int(timestamp)) > 300:
            raise ValueError("Expired signature")
        signed = timestamp.encode() + b"." + raw
        secrets_to_check = [
            current_app.config.get(name, "")
            for name in ("STRIPE_TEST_WEBHOOK_SECRET", "STRIPE_LIVE_WEBHOOK_SECRET")
        ]
        matched = [
            i
            for i, secret in enumerate(secrets_to_check)
            if secret.startswith("whsec_")
            and any(
                hmac.compare_digest(
                    p[3:], hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
                )
                for p in parts
                if p.startswith("v1=")
            )
        ]
        if not matched:
            raise ValueError("Invalid signature")
        event = json.loads(raw)
        if (
            type(event.get("livemode")) is not bool
            or int(event["livemode"]) not in matched
        ):
            raise ValueError("Wrong webhook environment")
        session_event = event.get("type") in {
            "checkout.session.completed",
            "checkout.session.async_payment_succeeded",
            "checkout.session.async_payment_failed",
            "checkout.session.expired",
        }
        reversal_event = event.get("type") in {
            "charge.refunded",
            "charge.dispute.created",
            "charge.dispute.closed",
        }
        if not session_event and not reversal_event:
            return "", 200
        obj = event["data"]["object"]
        payment_id = obj["id"] if session_event else obj["payment_intent"]
        if not isinstance(payment_id, str) or (
            session_event and not stripe.PAYMENT_ID.fullmatch(payment_id)
        ):
            raise ValueError("Invalid payment reference")
    except ValueError, TypeError, KeyError, StopIteration, AttributeError:
        return "", 400
    try:
        # A signed event only queues a server-side authenticated read.
        db.session.execute(
            db.update(StripeCheckout)
            .where(
                (StripeCheckout.payment_id == payment_id)
                if session_event
                else (StripeCheckout.payment_intent_id == payment_id)
            )
            .values(
                next_attempt_at=stripe.now().isoformat(),
                notification_version=StripeCheckout.notification_version + 1,
            )
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        return "", 503
    return "", 200
