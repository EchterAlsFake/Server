"""License purchase, invoice, and payment webhook routes."""

import hashlib
import json
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
from .extensions import csrf, db, limiter, browser_limit_key
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
from .models import CryptoLicenseDelivery, OnrampCheckout, PaymentProgress, Transaction
from .payment_progress import hosted_checkout_url, public_progress, record_nowpayments, refresh_providers
from .crypto_delivery import deliver_crypto_license, encrypt_recipient
from .keygen_service import KeygenUnavailable
from .nowpayments_service import (
    PaymentProviderError,
    create_crypto_invoice,
    verify_ipn_signature,
)
from .webhook_models import NowPaymentsWebhook

payments_bp = Blueprint("payments", __name__)
WEBHOOK_RATE_LIMIT = "20 per second"


def webhook_replay_rate_limit_key() -> str:
    """Isolate replay limits by signature without retaining an IP address."""
    signature = (
        request.headers.get("x-nowpayments-sig")
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
    from .checkout_consent import current_consent
    consent = current_consent()
    return render_template("buy_license.html", countries=COUNTRY_OPTIONS,
                           checkout_consent=consent if consent and consent.get("payment_method") == "crypto" else None)


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
    from .tor_checkout import checkout_network_status
    if checkout_network_status() != 'clear':
        payment_url = None
    return render_template(
        "buy_success.html", session_id=session_id, **view_context(session_id), beta=bool(checkout and checkout.beta), is_card_checkout=bool(checkout),
        has_contract=bool(transaction and transaction.contract_snapshot), payment_url=payment_url, charge_amount=checkout.charge_amount if checkout else None,
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

    try:
        license_file = fulfill_transaction_license(transaction)
    except KeygenUnavailable:
        db.session.rollback()
        return jsonify({"error": "License delivery is temporarily unavailable. Please retry."}), 503, {"Retry-After": "30"}
    return send_file(
        BytesIO(license_file),
        as_attachment=True,
        download_name="porn_fetch.license",
        mimetype="application/octet-stream",
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
        result.update(payment_method="banxa", beta=checkout.beta, delivery_status=checkout.delivery_status)
    try:
        license_record = get_or_create_license(transaction.provider_payment_id)
        build_license_file(license_record.license_key, license_record.issuance_reference, license_record.created_at)
        result["license_key"] = license_record.signed_key
    except KeygenUnavailable:
        db.session.rollback()
        from .payment_progress import record_fulfillment
        record_fulfillment(transaction, 'retry')
        return jsonify(status='pending', progress=public_progress(transaction, checkout, license_pending=True),
                       recovery_expires_at=result['recovery_expires_at']), 200
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
@limiter.limit("20 per hour", key_func=browser_limit_key)
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
    if "renewal_license_key" in data or "renewal_license_id" in data:
        return jsonify(error="Lifetime Premium does not require renewal. Start a new lifetime purchase."), 400
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
    if recipient is None:
        return jsonify(error="Enter a valid email for license delivery and your purchase reference."), 400
    try:
        encrypted_recipient = encrypt_recipient(recipient)
    except (ValueError, TypeError, AttributeError):
        return jsonify(error="Email delivery is not configured yet. Please try again later."), 503
    from .contracts import checkout_snapshot
    contract_snapshot = checkout_snapshot("crypto", data.get("country"))
    try:
        result = create_crypto_invoice(
            country.country_name,
            country.evidence_source,
            country.database_label,
            delivery_recipient_encrypted=encrypted_recipient,
            contract_snapshot=contract_snapshot,
        )
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




@payments_bp.get("/download_contract")
@limiter.limit(DEFAULT_RATE_LIMIT)
def download_contract():
    from .contracts import confirmation
    session_id = resolve_session_id()
    transaction = db.session.get(Transaction, session_id) if session_id else None
    if transaction is None or transaction.status != "finished":
        abort(404)
    document = confirmation(transaction)
    if document is None:
        abort(404)
    return send_file(BytesIO(document), as_attachment=True,
        download_name="confirmation.pdf", mimetype="application/pdf")
