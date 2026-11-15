"""Password-gated sandbox routes; all payment authority stays on the server."""

import secrets
from datetime import timedelta

from flask import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash

from .extensions import csrf, db, limiter, browser_limit_key
from .mollie_models import MollieCheckout, MollieGrant
from . import mollie_service as mollie

mollie_bp = Blueprint("mollie", __name__)


def require_enabled():
    if not mollie.enabled():
        abort(404)


@mollie_bp.get("/mollie/test")
def review():
    require_enabled()
    access = mollie.grant()
    if access.order_id:
        return redirect(
            url_for("payments.buy_success", session_id=access.order_id), code=303
        )
    return checkout_page(test_mode=not mollie.live_enabled())


def checkout_page(*, test_mode=False):
    from .countries import COUNTRY_OPTIONS
    from .contracts import IMMEDIATE_EN

    return render_template(
        "premium_checkout.html",
        countries=COUNTRY_OPTIONS,
        immediate_consent=IMMEDIATE_EN,
        mollie_offer_digest=mollie.offer_digest(),
        test_mode=test_mode,
        test_notice=mollie.TEST_NOTICE,
        test_quote=mollie.quote(None),
    )


@mollie_bp.post("/mollie/unlock")
@limiter.limit("5 per minute", key_func=browser_limit_key)
@limiter.limit(
    "5 per minute",
    key_func=lambda: request.environ.get("PF_MOLLIE_LIMIT_KEY", "unknown-address"),
)
def unlock():
    require_enabled()
    password = request.form.get("password", "")
    try:
        valid = len(password) <= 1024 and check_password_hash(
            current_app.config["MOLLIE_TEST_PASSWORD_HASH"], password
        )
    except ValueError, TypeError:
        valid = False
    if not valid:
        return render_template(
            "mollie_unlock.html", error="Incorrect tester password."
        ), 403
    token = secrets.token_urlsafe(32)
    db.session.add(
        MollieGrant(
            digest=mollie.digest(token),
            configuration=mollie.configuration(),
            expires_at=(mollie.now() + timedelta(minutes=15)).isoformat(),
        )
    )
    db.session.commit()
    session["mollie_grant"] = token
    return redirect(url_for("mollie.review"), code=303)


@mollie_bp.post("/mollie/lock")
def lock():
    token = session.pop("mollie_grant", "")
    if isinstance(token, str) and token:
        db.session.execute(
            db.delete(MollieGrant).where(MollieGrant.digest == mollie.digest(token))
        )
        db.session.commit()
    return redirect(url_for("pages.porn_fetch"), code=303)


@mollie_bp.post("/mollie/checkout")
@limiter.limit("20 per hour", key_func=browser_limit_key)
def create_checkout():
    require_enabled()
    access = mollie.grant()
    identifier = access.order_id
    if not identifier:
        from .payment_routes import validate_checkout_country
        from .licensing import normalize_recipient_email
        from .tor_checkout import checkout_network_status

        if checkout_network_status() != "clear":
            return jsonify(
                error="Use a direct connection; network verification is required."
            ), 403
        if request.form.get("offer_digest") != mollie.offer_digest():
            return jsonify(
                error="The offer has changed. Reload and review the checkout again."
            ), 409
        required = ["age_terms_accepted", "withdrawal_accepted"]
        if not mollie.live_enabled():
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
            identifier = mollie.reserve(
                access, country, request.form["country"], recipient
            )
        except ValueError, TypeError, AttributeError:
            db.session.rollback()
            return jsonify(
                error="Email delivery is not configured. Please try again later."
            ), 503
    mollie.process_order(identifier)
    # Show the private recovery page first so the link can be saved before leaving.
    target = url_for("payments.buy_success", session_id=identifier)
    if request.headers.get("Accept") == "application/json":
        return jsonify(next=target)
    return redirect(target, code=303)


@mollie_bp.get("/mollie/launch")
def launch():
    from .checkout_recovery import resolve_session_id

    identifier = resolve_session_id()
    row = db.session.get(MollieCheckout, identifier)
    if (
        not row
        or not row.payment_id
        or row.state not in {"open", "pending", "authorized"}
    ):
        abort(
            409,
            description="This checkout is unavailable. Check your order status.",
        )
    target = mollie.checkout_url(row.checkout_url)
    if not target:
        abort(503)
    return redirect(target, code=303)


@mollie_bp.post("/mollie/webhook")
@csrf.exempt
@limiter.limit("20 per second")
def webhook():
    from .payment_routes import require_api_subdomain

    require_api_subdomain()
    payment_id = request.form.get("id", "")
    if not mollie.PAYMENT_ID.fullmatch(payment_id):
        return "", 200
    try:
        # No API request for attacker-supplied unknown IDs. The queued ID is only a hint.
        db.session.execute(
            db.update(MollieCheckout)
            .where(MollieCheckout.payment_id == payment_id)
            .values(
                next_attempt_at=mollie.now().isoformat(),
                notification_version=MollieCheckout.notification_version + 1,
            )
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        return "", 503
    return "", 200
