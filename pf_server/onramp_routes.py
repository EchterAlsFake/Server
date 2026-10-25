"""Browser consent and Banxa annual-license checkout endpoints."""

import hashlib
import secrets
from datetime import datetime

from flask import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    render_template,
    request,
    session,
)
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy.exc import SQLAlchemyError

from .countries import COUNTRY_OPTIONS
from .extensions import csrf, db, limiter
from .licensing import normalize_recipient_email
from .models import OnrampCheckout
from .nowpayments_service import PaymentProviderError
from . import onramp_service as service
from .payment_routes import require_api_subdomain, validate_checkout_country

onramp_bp = Blueprint("onramp", __name__)


def serializer():
    return URLSafeTimedSerializer(current_app.secret_key, salt="onramp-consent-v1")


def browser_limit_key():
    """Keep the per-browser limit independent of stripped IP addresses."""
    browser = session.setdefault("onramp_browser", secrets.token_urlsafe(32))
    return hashlib.sha256(browser.encode()).hexdigest()


@onramp_bp.get("/buy_card")
def buy_card():
    return render_template(
        "buy_card.html", countries=COUNTRY_OPTIONS, enabled=service.available()
    )


@onramp_bp.post("/onramp-acknowledgment")
@limiter.limit("20 per hour", key_func=browser_limit_key)
def acknowledgment():
    if not service.available():
        return jsonify(
            error="Test preview: external payment-link creation is not configured. No payment has been created."
        ), 503
    browser = session.setdefault("onramp_browser", secrets.token_urlsafe(32))
    checkout = OnrampCheckout(
        session_id="OR-" + secrets.token_urlsafe(24),
        created_at=service.now().isoformat(),
        consent_version=service.CONSENT_VERSION,
        beta=False,
    )
    db.session.add(checkout)
    db.session.commit()
    token = serializer().dumps({"id": checkout.session_id, "browser": browser})
    return jsonify(acknowledgment_token=token, wait_seconds=5)


@onramp_bp.post("/create-onramp-payment")
@limiter.limit("20 per hour", key_func=browser_limit_key)
def create_payment():
    if not service.available():
        return jsonify(
            error="Test preview: external payment-link creation is not configured. No payment has been created."
        ), 503
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or any(
        data.get(field) is not True
        for field in (
            "age_confirmed",
            "terms_accepted",
            "withdrawal_accepted",
            "annual_terms_acknowledged",
            "kyc_acknowledged",
        )
    ):
        return jsonify(
            error="Please accept all purchase, annual-license and KYC confirmations."
        ), 400
    recipient = (
        normalize_recipient_email(data.get("delivery_email"))
        if isinstance(data.get("delivery_email"), str)
        else None
    )
    if recipient is None:
        return jsonify(error="Enter a valid license delivery email."), 400
    country, error = validate_checkout_country(data)
    if error:
        return error
    try:
        consent = serializer().loads(data.get("acknowledgment_token", ""), max_age=1200)
        if (
            not session.get("onramp_browser")
            or consent.get("browser") != session["onramp_browser"]
        ):
            raise BadSignature("Browser mismatch")
        checkout = db.session.get(OnrampCheckout, consent["id"])
        if not checkout or checkout.consent_version != service.CONSENT_VERSION:
            raise BadSignature("Missing consent")
    except BadSignature, KeyError, TypeError, AttributeError:
        return jsonify(
            error="Reopen the disclosure and read it before continuing."
        ), 400
    elapsed = (
        service.now() - datetime.fromisoformat(checkout.created_at)
    ).total_seconds()
    if elapsed < 5:
        return jsonify(
            error="Read the disclosure for at least five seconds before continuing."
        ), 409
    if checkout.stage != "ready":
        claim = db.session.execute(
            db.update(OnrampCheckout)
            .where(
                OnrampCheckout.session_id == checkout.session_id,
                OnrampCheckout.stage == "acknowledged",
            )
            .values(stage="creating")
        )
        db.session.commit()
        if claim.rowcount != 1:
            return jsonify(
                error="This checkout is already being created or could not be completed. Reopen the disclosure to start a new checkout."
            ), 409
        try:
            checkout = service.create_checkout(checkout, country, recipient)
        except PaymentProviderError as error:
            db.session.rollback()
            current_app.logger.warning("Onramp checkout creation failed")
            return jsonify(error=str(error)), 503
        except SQLAlchemyError:
            db.session.rollback()
            current_app.logger.warning("Onramp checkout creation failed")
            return jsonify(
                error="Could not create the Banxa checkout. No payment link has been issued. Reopen the disclosure to try again."
            ), 503
    return jsonify(
        session_id=checkout.session_id,
        checkout_url=service.decrypt(checkout.checkout_encrypted),
        status_url="/buy_success?session_id=" + checkout.session_id,
        charge_amount=checkout.charge_amount,
        charge_currency=checkout.charge_currency,
        beta=checkout.beta,
        payment_method="banxa",
    )


@onramp_bp.get("/onramp-callback")
@csrf.exempt
@limiter.limit("20 per second")
def callback():
    require_api_subdomain()
    reference = request.args.get("reference", "")
    if not 20 <= len(reference) <= 128:
        abort(404)
    digest = hashlib.sha256(reference.encode()).hexdigest()
    db.session.execute(
        db.update(OnrampCheckout)
        .where(
            OnrampCheckout.callback_digest == digest,
        )
        .values(callback_seen_at=service.now().isoformat())
    )
    db.session.commit()
    # Deliberately ignore every payment field. This callback is unsigned.
    return "ok", 200, {"Content-Type": "text/plain"}
