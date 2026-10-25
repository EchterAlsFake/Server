"""License purchase, invoice, and payment webhook routes."""

import hashlib
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

from .checkout_recovery import issue as issue_recovery, resolve_session_id, view_context
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
    fulfill_transaction_license,
    get_or_create_license,
    normalize_recipient_email,
)
from .logging_config import safe_log_reference
from .models import CryptoLicenseDelivery, License, LicenseRenewal, OnrampCheckout, PaymentProgress, Transaction
from .payment_progress import hosted_checkout_url, public_progress, record_nowpayments, refresh_providers
from .crypto_delivery import deliver_crypto_license, encrypt_recipient
from .keygen_service import KeygenUnavailable, renewal_target
from .nowpayments_service import (
    PaymentProviderError,
    create_crypto_invoice,
    verify_ipn_signature,
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


def webhook_replay_rate_limit_key() -> str:
    """Isolate replay limits by signature without retaining an IP address."""
    signature = (
        request.headers.get("X-Patreon-Signature")
        or request.headers.get("x-nowpayments-sig")
        or "missing"
    )
    material = f"{request.path}\0{signature.strip().lower()}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


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
    session_id = resolve_session_id()
    checkout = db.session.get(OnrampCheckout, session_id)
    transaction = db.session.get(Transaction, checkout.session_id) if checkout else None
    payment_url = None
    progress = db.session.get(PaymentProgress, checkout.session_id) if checkout else None
    if (checkout and transaction and transaction.status == "pending"
        and checkout.payment_state == "waiting" and checkout.stage == "ready"
        and checkout.checkout_encrypted
        and (not progress or (not progress.onramp_state and progress.nowpayments_state == "waiting"))):
        from .onramp_service import decrypt
        payment_url = decrypt(checkout.checkout_encrypted)
    if not checkout:
        transaction = db.session.get(Transaction, session_id)
        progress = db.session.get(PaymentProgress, transaction.session_id) if transaction else None
        if transaction and transaction.status == "pending" and progress and progress.nowpayments_state == "waiting":
            payment_url = hosted_checkout_url(progress.checkout_url)
    return render_template(
        "buy_success.html", session_id=session_id, **view_context(session_id), beta=bool(checkout and checkout.beta), is_card_checkout=bool(checkout),
        payment_url=payment_url, charge_amount=checkout.charge_amount if checkout else None,
    )


@payments_bp.get("/download-recovery")
@limiter.limit("30 per minute")
def download_recovery():
    session_id = resolve_session_id()
    if not session_id or db.session.get(Transaction, session_id) is None:
        abort(404)
    context = view_context(session_id)
    content = (
        "Porn Fetch private payment recovery link\n\n" + context["recovery_url"]
        + "\n\nAnyone with this link can access your license and invoice. Keep it private.\n"
        + "For new orders: valid while payment is pending (up to seven days), then for six hours after your license is ready.\n"
        + "Save the license and invoice before access expires. Your license itself does not expire with this link.\n"
        + "Support: support@echteralsfake.me. Keep your payment transaction hash or invoice reference.\n"
    )
    return send_file(BytesIO(content.encode()), as_attachment=True,
        download_name="porn-fetch-recovery.txt", mimetype="text/plain")


@payments_bp.route("/buy_cancel", methods=["GET"])
def buy_cancel():
    return render_template("buy_cancel.html")


@payments_bp.route("/download_license", methods=["GET"])
@limiter.limit(DEFAULT_RATE_LIMIT)
def download_license():
    session_id = resolve_session_id()
    if not session_id:
        return jsonify({"error": "Missing session_id"}), 400

    transaction = db.session.get(Transaction, session_id)
    if transaction is None or transaction.status != "finished":
        return jsonify({"error": "Payment not approved or session not found"}), 402

    issuance_reference = transaction.provider_payment_id
    try:
        license_file = fulfill_transaction_license(transaction)
    except KeygenUnavailable:
        db.session.rollback()
        return jsonify({"error": "License delivery is temporarily unavailable. Please retry."}), 503, {"Retry-After": "30"}
    return send_file(
        BytesIO(license_file),
        as_attachment=True,
        download_name="porn_fetch.license",
        mimetype="application/json",
    )


@payments_bp.route("/check_license", methods=["POST"])
@limiter.limit(DEFAULT_RATE_LIMIT)
def check_license():
    return jsonify({"error": "Use the Keygen licensing client", "state": "unsupported"}), 410


@payments_bp.route("/check-payment-status", methods=["GET"])
@limiter.limit(DEFAULT_RATE_LIMIT)
def check_payment_status():
    session_id = resolve_session_id()
    if not session_id:
        return jsonify({"error": "Missing session_id"}), 400

    transaction = db.session.get(Transaction, session_id)
    if transaction is None:
        return jsonify({"status": "unknown"}), 404
    checkout = db.session.get(OnrampCheckout, session_id)
    if transaction.status != "finished":
        refresh_providers(transaction)
        progress = public_progress(transaction, checkout)
        status = progress["provider_state"] if progress["provider_state"] in {"partially_paid", "failed", "expired", "refunded", "wrong_asset_confirmed"} else "pending"
        result = {"status": status, "progress": progress, "recovery_expires_at": view_context(session_id)["recovery_expires_at"]}
        if checkout:
            result.update(payment_state=progress["provider_state"], payment_method="banxa", beta=checkout.beta)
        return jsonify(result), 200

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
    result = {"status": "finished", "invoice_num": invoice_number, "recovery_expires_at": view_context(session_id)["recovery_expires_at"]}
    checkout = db.session.get(OnrampCheckout, session_id)
    if checkout:
        license_record = License.query.filter_by(issuance_reference=transaction.provider_payment_id).first()
        result.update(payment_method="banxa", beta=checkout.beta, license_key=license_record.signed_key if license_record else None, delivery_status=checkout.delivery_status)
    if not checkout:
        try:
            license_record = get_or_create_license(transaction.provider_payment_id)
            build_license_file(license_record.license_key, license_record.issuance_reference, license_record.created_at)
            result["license_key"] = license_record.signed_key
        except KeygenUnavailable:
            db.session.rollback()
            return jsonify(error="Payment confirmed. License issuance is temporarily unavailable; please retry."), 503
    delivery = db.session.get(CryptoLicenseDelivery, session_id)
    if delivery:
        result["delivery_status"] = delivery.delivery_status
    result["progress"] = public_progress(transaction, checkout)
    return jsonify(result), 200


@payments_bp.route("/download_invoice", methods=["GET"])
@limiter.limit(DEFAULT_RATE_LIMIT)
def download_invoice():
    session_id = resolve_session_id()
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
    if (not current_app.config.get("NOWPAYMENTS_SANDBOX")
        or not current_app.config.get("NOWPAYMENTS_LOCAL_SIMULATION_ENABLED")):
        abort(404)

    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id") if isinstance(data, dict) else None
    if not isinstance(session_id, str) or not session_id:
        return jsonify({"error": "Missing session_id"}), 400
    session_id = resolve_session_id(session_id)
    transaction = db.session.get(Transaction, session_id)
    if transaction is None:
        return jsonify({"error": "Session not found"}), 404
    if db.session.get(OnrampCheckout, session_id) is not None:
        return jsonify({"error": "Real-money beta purchases cannot be simulated."}), 400

    try:
        save_invoice(session_id, build_simulated_invoice())
        transaction.status = "finished"
        transaction.finished_at = datetime.now(timezone.utc).isoformat()
        db.session.commit()
    except (OSError, ValueError, SQLAlchemyError):
        db.session.rollback()
        current_app.logger.exception("Local payment simulation failed")
        return jsonify({"error": "Payment simulation failed"}), 500
    try:
        deliver_crypto_license(session_id)
    except Exception:
        db.session.rollback()
        current_app.logger.warning("Crypto license email deferred for retry")
    return jsonify({"status": "ok", "message": "Payment simulation successful."}), 200


@payments_bp.route("/create-crypto-payment", methods=["POST"])
@limiter.limit(DEFAULT_RATE_LIMIT)
def create_crypto_payment():
    if not current_app.config.get("NOWPAYMENTS_API_KEY"):
        return jsonify({"error": "NOWPayments API key not configured on server."}), 500
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or data.get("terms_accepted") is not True:
        return jsonify({"error": "Please accept the Terms of Service."}), 400
    if (
        current_app.config.get("NOWPAYMENTS_SANDBOX")
        and data.get("test_acknowledged") is not True
    ):
        return jsonify({
            "error": "Please acknowledge that this is a test site and no real purchase is made."
        }), 400
    country, country_error = validate_checkout_country(data)
    if country_error:
        return country_error
    assert country is not None
    if any(data.get(field) is not True for field in ("age_confirmed", "withdrawal_accepted")):
        return jsonify(error="Please confirm your age and consent to immediate digital delivery."), 400
    raw_email = data.get("delivery_email", "")
    if not isinstance(raw_email, str):
        return jsonify(error="Enter a valid license delivery email."), 400
    recipient = normalize_recipient_email(raw_email.strip()) if raw_email.strip() else None
    if raw_email.strip() and recipient is None:
        return jsonify(error="Enter a valid license delivery email."), 400
    if not recipient and data.get("no_email_acknowledged") is not True:
        return jsonify(error="Acknowledge that you will save your license and invoice without email delivery."), 400
    encrypted_recipient = None
    if recipient:
        try:
            encrypted_recipient = encrypt_recipient(recipient)
        except (ValueError, TypeError, AttributeError):
            return jsonify(error="Email delivery is not configured yet. Try again later, or leave the email blank and save your license after checkout."), 503
    try:
        target = renewal_target(data['renewal_license_key']) if data.get('renewal_license_key') else None
        result = create_crypto_invoice(
            country.country_name,
            country.evidence_source,
            country.database_label,
            delivery_recipient_encrypted=encrypted_recipient,
            **({"renewal_license_id": target} if target else {}),
        )
    except ValueError:
        return jsonify({'error': 'Renewal requires an activated commercial license.'}), 400
    except KeygenUnavailable:
        return jsonify({'error': 'Licensing is temporarily unavailable.'}), 503
    except (PaymentProviderError, SQLAlchemyError):
        current_app.logger.exception("NOWPayments invoice creation failed")
        return jsonify({"error": "Failed to generate crypto payment"}), 500
    token = issue_recovery(result["session_id"])
    result["status_url"] = "/buy_success?token=" + token
    result["recovery_url"] = current_app.config["APP_DOMAIN"] + result["status_url"]
    return jsonify(result), 200


@payments_bp.route("/nowpayments-ipn", methods=["POST"])
@csrf.exempt
@limiter.limit(WEBHOOK_RATE_LIMIT, key_func=webhook_replay_rate_limit_key)
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

    from .onramp_service import record_payment_state
    record_payment_state(webhook)
    record_nowpayments(webhook)

    if payment_status.casefold() in {"finished", "partially_paid"}:
        from .payment_receipts import enqueue
        try:
            enqueue(webhook)
        except SQLAlchemyError:
            db.session.rollback()
            current_app.logger.error("Could not persist authenticated payment receipt")
            response = jsonify({"error": "receipt_storage_unavailable"})
            response.headers["Retry-After"] = "30"
            return response, 503
    return "OK", 200


@payments_bp.route("/patreon-webhook", methods=["POST"])
@csrf.exempt
@limiter.limit(WEBHOOK_RATE_LIMIT, key_func=webhook_replay_rate_limit_key)
def patreon_webhook():
    require_api_subdomain()
    if not current_app.config.get('PATREON_PAYMENTS_ENABLED'):
        return jsonify({'error': 'patreon_payments_disabled'}), 503
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
