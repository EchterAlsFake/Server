"""License purchase, invoice, and payment webhook routes."""

import hmac
import json
import re
from datetime import datetime, timezone
from io import BytesIO

from flask import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    render_template,
    request,
    send_file,
)
from sqlalchemy.exc import SQLAlchemyError

from .config import DEFAULT_RATE_LIMIT
from .countries import COUNTRY_OPTIONS
from .country_service import CheckoutCountryDecision, checkout_country_decision
from .extensions import csrf, db, limiter
from .http import normalized_hostname
from .invoice_service import (
    build_simulated_invoice,
    invoice_download_name,
    load_invoice,
    render_invoice_pdf,
    save_invoice,
)
from .licensing import (
    build_license_file,
    get_or_create_license,
    normalize_recipient_email,
)
from .logging_config import safe_log_reference
from .models import License, Transaction
from .nowpayments_service import (
    CompletionState,
    PaymentProviderError,
    complete_payment,
    create_crypto_invoice,
    verify_ipn_signature,
)
from .nowpayments_service import (
    create_fiat_payment as create_fiat_payment_with_provider,
)
from .patreon_service import (
    calculate_patreon_signature,
    deliver_patreon_license,
    extract_patreon_email,
    patreon_member_is_paid_and_entitled,
)
from .webhook_models import NowPaymentsWebhook, PatreonWebhook

payments_bp = Blueprint("payments", __name__)
WEBHOOK_RATE_LIMIT = "20 per second"


def require_api_subdomain() -> None:
    if normalized_hostname(request.host) != current_app.config["API_PUBLIC_HOST"]:
        abort(404)


def validate_checkout_country(
    data: object,
) -> tuple[CheckoutCountryDecision | None, object | None]:
    declared_country = data.get("country") if isinstance(data, dict) else None
    decision = checkout_country_decision(declared_country, request.environ)
    if decision.status == "verified":
        return decision, None
    if decision.status == "invalid_declaration":
        return None, (jsonify({"error": "Please select a valid country."}), 400)
    if decision.status == "mismatch":
        current_app.logger.warning("Checkout country evidence does not match")
        return None, (
            jsonify(
                {
                    "error": (
                        "Your selected country does not match the local location "
                        "check. Disable any VPN and try again."
                    )
                }
            ),
            409,
        )
    if decision.status == "restricted":
        current_app.logger.warning(
            "Checkout blocked by geographic policy (reason=%s)", decision.reason
        )
        return None, (
            jsonify({"error": "Checkout is unavailable in this location."}),
            451,
        )
    current_app.logger.error(
        "Local checkout country verification is unavailable (reason=%s)",
        decision.reason,
    )
    return None, (
        jsonify({"error": "Country verification is temporarily unavailable."}),
        503,
    )


@payments_bp.route("/buy_license", methods=["GET"])
def buy_license():
    return render_template("buy_license.html", countries=COUNTRY_OPTIONS)


@payments_bp.route("/buy_success", methods=["GET"])
def buy_success():
    return render_template(
        "buy_success.html", session_id=request.args.get("session_id")
    )


@payments_bp.route("/buy_cancel", methods=["GET"])
def buy_cancel():
    return render_template("buy_cancel.html")


@payments_bp.route("/download_license", methods=["GET"])
@limiter.limit(DEFAULT_RATE_LIMIT)
def download_license():
    session_id = request.args.get("session_id", "")
    if not session_id:
        return jsonify({"error": "Missing session_id"}), 400

    transaction = db.session.get(Transaction, session_id)
    if transaction is None or transaction.status != "finished":
        return jsonify({"error": "Payment not approved or session not found"}), 402

    issuance_reference = transaction.provider_payment_id
    license_record = get_or_create_license(issuance_reference)
    license_file = build_license_file(
        license_record.license_key,
        issuance_reference,
        license_record.created_at,
    )
    return send_file(
        BytesIO(license_file),
        as_attachment=True,
        download_name="porn_fetch.license",
        mimetype="application/json",
    )


@payments_bp.route("/check_license", methods=["POST"])
@limiter.limit(DEFAULT_RATE_LIMIT)
def check_license():
    data = request.get_json(silent=True)
    license_key = data.get("license_key") if isinstance(data, dict) else None
    if (
        not isinstance(license_key, str)
        or not license_key.strip()
        or len(license_key) > 128
    ):
        return jsonify({"error": "Missing license_key in JSON payload"}), 400

    license_record = db.session.get(License, license_key.strip())
    if license_record is None:
        return jsonify({"error": "License not found", "state": "invalid"}), 404
    return jsonify({"state": license_record.state}), 200


@payments_bp.route("/check-payment-status", methods=["GET"])
@limiter.limit(DEFAULT_RATE_LIMIT)
def check_payment_status():
    session_id = request.args.get("session_id", "")
    if not session_id:
        return jsonify({"error": "Missing session_id"}), 400

    transaction = db.session.get(Transaction, session_id)
    if transaction is None:
        return jsonify({"status": "unknown"}), 404
    if transaction.status != "finished":
        return jsonify({"status": "pending"}), 200

    try:
        invoice = load_invoice(session_id)
    except ValueError:
        current_app.logger.warning(
            "Stored invoice is unreadable (reference=%s)",
            safe_log_reference(session_id),
            exc_info=True,
        )
        invoice = None
    invoice_number = invoice.get("Invoice Number", "N/A") if invoice else "N/A"
    return jsonify({"status": "finished", "invoice_num": invoice_number}), 200


@payments_bp.route("/download_invoice", methods=["GET"])
@limiter.limit(DEFAULT_RATE_LIMIT)
def download_invoice():
    session_id = request.args.get("session_id", "")
    if not session_id:
        return jsonify({"error": "Missing session_id"}), 400

    transaction = db.session.get(Transaction, session_id)
    if transaction is None or transaction.status != "finished":
        return jsonify({"error": "Payment not approved or session not found"}), 402
    try:
        invoice = load_invoice(session_id)
    except ValueError:
        current_app.logger.error(
            "Stored invoice is unreadable (reference=%s)",
            safe_log_reference(session_id),
            exc_info=True,
        )
        return jsonify({"error": "Invoice data is unavailable"}), 503
    if invoice is None:
        return jsonify({"error": "Invoice not found for this session"}), 404

    return send_file(
        BytesIO(render_invoice_pdf(invoice)),
        as_attachment=True,
        download_name=invoice_download_name(invoice),
        mimetype="application/pdf",
    )


@payments_bp.route("/simulate-payment-success", methods=["POST"])
@limiter.limit(DEFAULT_RATE_LIMIT)
def simulate_payment_success():
    if not current_app.config.get("NOWPAYMENTS_SANDBOX"):
        abort(404)

    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id") if isinstance(data, dict) else None
    if not isinstance(session_id, str) or not session_id:
        return jsonify({"error": "Missing session_id"}), 400
    transaction = db.session.get(Transaction, session_id)
    if transaction is None:
        return jsonify({"error": "Session not found"}), 404

    try:
        save_invoice(session_id, build_simulated_invoice())
        transaction.status = "finished"
        transaction.finished_at = datetime.now(timezone.utc).isoformat()
        db.session.commit()
    except (OSError, ValueError, SQLAlchemyError):
        db.session.rollback()
        current_app.logger.exception("Local payment simulation failed")
        return jsonify({"error": "Payment simulation failed"}), 500
    return jsonify({"status": "ok", "message": "Payment simulation successful."}), 200


@payments_bp.route("/create-fiat-payment", methods=["POST"])
@limiter.limit(DEFAULT_RATE_LIMIT)
def create_fiat_payment():
    if not current_app.config.get("NOWPAYMENTS_API_KEY"):
        return jsonify({"error": "NOWPayments API key not configured on server."}), 500
    data = request.get_json(silent=True)
    country, country_error = validate_checkout_country(data)
    if country_error:
        return country_error
    assert country is not None
    email = normalize_recipient_email(
        data.get("email") if isinstance(data, dict) else None
    )
    if email is None:
        return jsonify({"error": "A valid email address is required"}), 400
    try:
        result = create_fiat_payment_with_provider(
            email,
            country.country_name,
            country.evidence_source,
            country.database_label,
        )
    except (PaymentProviderError, SQLAlchemyError):
        current_app.logger.exception("NOWPayments fiat payment creation failed")
        return jsonify({"error": "Failed to create fiat payment"}), 500
    return jsonify(result), 200


@payments_bp.route("/create-crypto-payment", methods=["POST"])
@limiter.limit(DEFAULT_RATE_LIMIT)
def create_crypto_payment():
    if not current_app.config.get("NOWPAYMENTS_API_KEY"):
        return jsonify({"error": "NOWPayments API key not configured on server."}), 500
    data = request.get_json(silent=True)
    country, country_error = validate_checkout_country(data)
    if country_error:
        return country_error
    assert country is not None
    try:
        result = create_crypto_invoice(
            country.country_name,
            country.evidence_source,
            country.database_label,
        )
    except (PaymentProviderError, SQLAlchemyError):
        current_app.logger.exception("NOWPayments invoice creation failed")
        return jsonify({"error": "Failed to generate crypto payment"}), 500
    return jsonify(result), 200


@payments_bp.route("/nowpayments-ipn", methods=["POST"])
@csrf.exempt
@limiter.limit(WEBHOOK_RATE_LIMIT)
def nowpayments_ipn():
    require_api_subdomain()
    received_signature = request.headers.get("x-nowpayments-sig", "")
    signing_secret = current_app.config.get("NOWPAYMENTS_IPN_SECRET")
    if not signing_secret:
        current_app.logger.error("NOWPayments IPN secret is not configured")
        response = jsonify({"error": "secret_not_configured"})
        response.headers["Retry-After"] = "30"
        return response, 503
    if not received_signature:
        current_app.logger.warning("NOWPayments webhook signature is missing")
        return "Missing signature", 401

    try:
        raw_payload = json.loads(request.get_data())
    except (json.JSONDecodeError, UnicodeDecodeError):
        current_app.logger.warning("NOWPayments webhook JSON is invalid")
        return "Invalid JSON", 400
    if not verify_ipn_signature(raw_payload, received_signature, signing_secret):
        current_app.logger.warning("NOWPayments webhook signature is invalid")
        return "Invalid signature verification", 403
    try:
        webhook = NowPaymentsWebhook.from_mapping(raw_payload)
    except (ValueError, TypeError):
        current_app.logger.warning("NOWPayments webhook schema validation failed")
        return jsonify({"error": "Invalid payload schema"}), 400

    payment_status = webhook.payment_status or ""
    reference = safe_log_reference(webhook.order_id)
    if webhook.parent_payment_id is not None:
        current_app.logger.warning(
            "Ignored NOWPayments repeated/wrong-asset deposit (reference=%s)",
            reference,
        )
        return "Ignored repeated deposit", 200

    if payment_status.casefold() == "finished":
        try:
            result = complete_payment(webhook)
        except Exception:
            db.session.rollback()
            current_app.logger.exception(
                "NOWPayments fulfillment failed (reference=%s)", reference
            )
            response = jsonify({"error": "fulfillment_failed"})
            response.headers["Retry-After"] = "30"
            return response, 503
        if result.state in {CompletionState.UNKNOWN, CompletionState.BUSY}:
            current_app.logger.warning(
                "NOWPayments fulfillment is temporarily unavailable "
                "(reference=%s, state=%s)",
                reference,
                result.state,
            )
            response = jsonify({"error": result.state})
            response.headers["Retry-After"] = "30"
            return response, 503
        if result.state == CompletionState.REJECTED:
            current_app.logger.warning(
                "Rejected NOWPayments fulfillment (reference=%s, reason=%s)",
                reference,
                result.reason,
            )
            return "Ignored invalid payment", 200
        if result.state == CompletionState.COMPLETED:
            current_app.logger.info(
                "NOWPayments fulfillment completed (reference=%s, invoice=%s)",
                reference,
                safe_log_reference(result.invoice_number),
            )
    return "OK", 200


@payments_bp.route("/patreon-webhook", methods=["POST"])
@csrf.exempt
@limiter.limit(WEBHOOK_RATE_LIMIT)
def patreon_webhook():
    require_api_subdomain()
    received_signature = request.headers.get("X-Patreon-Signature", "").strip()
    signing_secret = current_app.config.get("PATREON_SECRET")
    if not signing_secret:
        current_app.logger.error("Patreon webhook secret is not configured")
        return jsonify({"error": "secret_not_configured"}), 503
    if re.fullmatch(r"[0-9A-Fa-f]{32}", received_signature) is None:
        current_app.logger.warning("Patreon webhook signature is missing or malformed")
        return jsonify({"error": "invalid_signature"}), 403

    request_body = request.get_data(cache=False)
    calculated_signature = calculate_patreon_signature(signing_secret, request_body)
    if not hmac.compare_digest(received_signature.lower(), calculated_signature):
        current_app.logger.warning("Patreon webhook signature is invalid")
        return jsonify({"error": "invalid_signature"}), 403

    event_type = request.headers.get("X-Patreon-Event", "").strip()
    if event_type not in {
        "members:create",
        "members:pledge:create",
        "members:pledge:update",
        "members:update",
    }:
        return jsonify({"status": "ignored_event"}), 200
    try:
        payload = PatreonWebhook.from_mapping(json.loads(request_body))
    except (json.JSONDecodeError, ValueError, TypeError):
        current_app.logger.warning("Patreon webhook schema validation failed")
        return jsonify({"error": "invalid_payload"}), 400
    if not patreon_member_is_paid_and_entitled(payload.data):
        return jsonify({"status": "not_eligible"}), 200

    recipient = extract_patreon_email(payload)
    if recipient is None:
        current_app.logger.warning(
            "Eligible Patreon member has no deliverable email address"
        )
        return jsonify({"status": "email_unavailable"}), 200
    try:
        delivery_status = deliver_patreon_license(payload.data.id, recipient)
    except Exception:
        current_app.logger.exception(
            "Patreon license delivery failed (member=%s)",
            safe_log_reference(payload.data.id),
        )
        return jsonify({"error": "delivery_failed"}), 503
    if delivery_status == "busy":
        response = jsonify({"error": "delivery_in_progress"})
        response.headers["Retry-After"] = "30"
        return response, 503
    return jsonify({"status": "ok"}), 200
