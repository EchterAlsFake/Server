"""Marketing pages, bilingual documents and session-based age confirmation."""

import time
from collections.abc import Mapping
from urllib.parse import parse_qs, urlsplit

from flask import (
    Blueprint, abort, current_app, jsonify, make_response, redirect, render_template,
    request, session, url_for,
)

from .extensions import limiter, browser_limit_key
from .checkout_consent import CONSENT_VERSION, FIELDS, current_consent, current_selection, required_fields
from .countries import COUNTRY_OPTIONS
from .http import normalized_hostname
from .product_catalog import WEBSITES
from .guide_content import GUIDES, guide_path
from .download_pages import render_download_page

pages_bp = Blueprint("pages", __name__)
AGE_GATED_PATHS = {"/porn_fetch", "/donation", "/buy_license", "/buy_card", "/buy_success", "/buy_cancel", "/payment-preview/patreon", "/payment-preview/card", "/payment-preview/banxa"}


@pages_bp.app_context_processor
def public_page_context():
    from .onion import is_onion
    from .contracts import IMMEDIATE_EN, REFUND_EN, offer_digest
    from .offer import PREMIUM_PRICE_TEXT
    return {"premium_price": PREMIUM_PRICE_TEXT, "immediate_en": IMMEDIATE_EN, "refund_en": REFUND_EN, "offer_digest": offer_digest, "age_required": not is_onion() and request.path in AGE_GATED_PATHS and not session.get("adult_confirmed"), "checkout_consent": current_consent(), "checkout_selection": current_selection()}


@pages_bp.after_app_request
def private_age_state(response):
    if normalized_hostname(request.host).startswith("docs."):
        return response
    if request.path in AGE_GATED_PATHS or request.path in {"/leave", "/checkout/start", "/checkout/crypto-confirm"}:
        if "no-store" not in response.headers.get("Cache-Control", ""):
            response.headers["Cache-Control"] = "private, no-store"
    return response


@pages_bp.route("/", methods=["GET", "POST"])
def landing_page():
    error = None
    if request.method == "POST":
        if request.form.get("adult_confirmed") == "yes":
            session["adult_confirmed"] = True
            if request.accept_mimetypes.best == "application/json":
                return jsonify({"confirmed": True})
            target = request.form.get("next", "/")
            try:
                parsed = urlsplit(target)
            except ValueError:
                parsed = urlsplit("/")
                target = "/"
            if parsed.scheme or parsed.netloc or parsed.path not in AGE_GATED_PATHS | {"/", "/download", "/about", "/help", "/releases"} or target.startswith("//"):
                target = "/"
            return redirect(target, code=303)
        error = "Confirm that you are at least 18 years old to continue."
        if request.accept_mimetypes.best == "application/json":
            return jsonify({"error": error}), 400
    return make_response(render_template(
        "index.html", websites=WEBSITES,
        guide_links={guide["name"]: guide_path(key) for key, guide in GUIDES.items()},
        featured_guides=dict(list(GUIDES.items())[:5]), age_error=error,
    ), 400 if error else 200)


@pages_bp.route("/leave", methods=["GET"])
def leave():
    session.pop("adult_confirmed", None)
    response = make_response(render_template("leave.html"))
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    return response


@pages_bp.route("/download", methods=["GET"])
def download():
    return render_download_page()


@pages_bp.route("/about", methods=["GET"])
def about():
    return render_template("about.html")


@pages_bp.route("/access", methods=["GET"])
def site_access():
    response = redirect(url_for("pages.landing_page"), code=302)
    response.headers["Cache-Control"] = "private, no-store"
    return response


@pages_bp.route("/impress", methods=["GET"])
def impress():
    return render_template("impress.html")


@pages_bp.route("/transparency", methods=["GET"])
def transparency():
    return redirect("https://docs.echteralsfake.me/transparency/", code=301)


@pages_bp.route("/refund_policy", methods=["GET"])
def refund_policy():
    return render_template("refund_policy.html")


@pages_bp.route("/terms", methods=["GET"])
def terms():
    return render_template("terms.html")


@pages_bp.route("/porn_fetch", methods=["GET"])
def porn_fetch():
    return render_template("porn_fetch.html", countries=COUNTRY_OPTIONS, preferred_method=request.args.get("method"))


@pages_bp.post("/checkout/start")
def checkout_start():
    data = request.get_json(silent=True) if request.is_json else request.form
    data = data if isinstance(data, Mapping) else {}
    # One explicit checkbox covers both declarations; never prefill either alone.
    if data.get("age_terms_accepted") is True or data.get("age_terms_accepted") == "yes":
        data = dict(data, age_confirmed=True, terms_accepted=True)
    method = data.get("payment_method")
    if isinstance(method, str) and method in {"crypto", "card"}:
        from .tor_checkout import block_crypto_checkout
        blocked = block_crypto_checkout()
        if blocked is not None:
            return blocked
    if method == "patreon" and not current_app.config["NOWPAYMENTS_SANDBOX"] and not current_app.config["PATREON_SHOP_ENABLED"]:
        return jsonify(error="Patreon purchases are not available yet."), 503
    country = data.get("country")
    def accepted(field):
        return data.get(field) == "yes" or data.get(field) is True

    shared_fields = tuple(field for field in required_fields(method) if field != "withdrawal_accepted")
    if not isinstance(method, str) or method not in {"crypto", "patreon", "card"} or not all(accepted(field) for field in shared_fields):
        error = "Choose your payment method and accept all required confirmations."
        if request.is_json:
            return jsonify(error=error), 400
        return render_template("porn_fetch.html", countries=COUNTRY_OPTIONS, checkout_error=error), 400
    pending_crypto = method == "crypto" and country is None and not accepted("withdrawal_accepted")
    if method != "patreon" and not pending_crypto and (not isinstance(country, str) or country not in dict(COUNTRY_OPTIONS) or not accepted("withdrawal_accepted")):
        return jsonify(error="Select your country and consent to immediate digital supply on the crypto checkout."), 400
    from .contracts import offer_digest, record_agreement
    from datetime import datetime, timezone
    if data.get("offer_digest") != offer_digest():
        return jsonify(error="The offer has changed. Reload the checkout information and confirm it again."), 409
    session.pop("checkout_selection", None)
    session.pop("checkout_consent", None)
    if pending_crypto:
        session["checkout_selection"] = dict(version=CONSENT_VERSION, accepted_at=time.time(), payment_method="crypto", offer_digest=data["offer_digest"], **{field: accepted(field) for field in shared_fields})
        target = url_for("payments.buy_license")
        if request.is_json:
            return jsonify(next=target, method=method)
        return redirect(target, code=303)
    if method == "patreon":
        country = None  # No tax-country declaration collected for Patreon Shop.
    agreement_id = record_agreement(method, country, datetime.now(timezone.utc).isoformat())
    session["checkout_consent"] = dict(agreement_id=agreement_id, offer_digest=data["offer_digest"], version=CONSENT_VERSION, accepted_at=time.time(), country=country, payment_method=method, **{field: accepted(field) for field in FIELDS})
    target = url_for("payments.buy_license") if method == "crypto" else url_for("pages.payment_preview", method=method)
    if request.is_json:
        return jsonify(next=target, method=method, live=not current_app.config['NOWPAYMENTS_SANDBOX'])
    return redirect(target, code=303)


@pages_bp.post("/checkout/crypto-confirm")
def confirm_crypto_checkout():
    """Complete direct-purchase consent after the shared payment-method page."""
    selection = current_selection() or current_consent()
    if not selection or selection.get("payment_method") != "crypto":
        return jsonify(error="Start with the payment methods and confirmations again."), 409
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("country"), str) or data.get("country") not in dict(COUNTRY_OPTIONS) or data.get("withdrawal_accepted") is not True:
        return jsonify(error="Select your country and consent to immediate digital supply."), 400
    from .contracts import offer_digest, record_agreement
    if selection.get("offer_digest") != offer_digest() or data.get("offer_digest") != selection.get("offer_digest"):
        return jsonify(error="The offer has changed. Start checkout again and review the confirmations."), 409
    from datetime import datetime, timezone
    country = data["country"]
    agreement_id = record_agreement("crypto", country, datetime.now(timezone.utc).isoformat())
    session["checkout_consent"] = dict(selection, agreement_id=agreement_id, country=country, withdrawal_accepted=True)
    session.pop("checkout_selection", None)
    return jsonify(confirmed=True)


@pages_bp.get("/checkout/agreement")
def download_checkout_agreement():
    from .contracts import agreement_receipt
    from .extensions import db
    from .models import CheckoutAgreement
    consent = current_consent()
    if not consent:
        abort(404)
    agreement = db.session.get(CheckoutAgreement, consent.get("agreement_id"))
    if agreement is None:
        abort(404)
    response = make_response(agreement_receipt(agreement))
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = 'attachment; filename="checkout-agreement.pdf"'
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    return response


@pages_bp.route("/donation", methods=["GET"])
def donation():
    return render_template("donation.html")


@pages_bp.route("/datenschutz", methods=["GET"])
def datenschutz():
    return redirect(url_for("pages.privacy_policy", _anchor="de"), code=302)


@pages_bp.route("/privacy_policy", methods=["GET"])
def privacy_policy():
    return render_template("privacy_policy.html")


@pages_bp.route("/legal-statement", methods=["GET"])
def legal_compliance():
    return render_template("legal-statement.html")


@pages_bp.route("/payment-preview/<method>", methods=["GET", "POST"])
def payment_preview(method):
    """Require explicit no-payment acknowledgment; never creates a provider order."""
    if method not in {"patreon", "card", "banxa"}:
        abort(404)
    if method == "patreon":
        consent = current_consent()
        if not consent or consent.get("payment_method") != "patreon":
            return redirect(url_for("pages.porn_fetch", method="patreon"), code=303)
        from .contracts import checkout_snapshot
        checkout_snapshot("patreon", consent["country"])
    provider = "Patreon" if method == "patreon" else "Onramp Pay / Banxa"
    session_id = request.values.get("session_id", "")
    target = (
        current_app.config["PATREON_SHOP_PRODUCT_URL"]
        if method == "patreon" else url_for("onramp.buy_card")
    )
    if method == "patreon" and not current_app.config["NOWPAYMENTS_SANDBOX"]:
        if not current_app.config["PATREON_SHOP_ENABLED"]:
            abort(503)
        response = make_response(render_template("patreon_checkout.html", target=target))
        response.headers["Cache-Control"] = "private, no-store"
        return response
    if method == "banxa":
        from .checkout_recovery import resolve_session_id
        session_id = resolve_session_id()
        from .extensions import db
        from .models import OnrampCheckout, PaymentProgress, Transaction
        from .onramp_service import decrypt
        checkout = db.session.get(OnrampCheckout, session_id)
        transaction = db.session.get(Transaction, session_id)
        progress = db.session.get(PaymentProgress, session_id)
        if (not checkout or not transaction or transaction.status != "pending"
            or checkout.stage != "ready" or checkout.payment_state != "waiting"
            or not checkout.checkout_encrypted
            or (progress and (progress.onramp_state or progress.nowpayments_state != "waiting"))):
            abort(404)
        target = decrypt(checkout.checkout_encrypted)
        parsed = urlsplit(target)
        if (parsed.scheme != "https" or parsed.hostname != "checkout.onramp-pay.com"
            or parsed.username or parsed.password or parsed.port not in {None, 443}
            or parsed.path != "/process-payment.php"
            or parse_qs(parsed.query).get("provider") != ["banxa"]):
            abort(404)
    error = None
    if request.method == "POST":
        if request.form.get("confirm_no_payment") == "yes":
            if method == 'patreon':
                return render_template("payment_preview_launch.html", target=current_app.config["PATREON_SHOP_PRODUCT_URL"], provider=provider)
            if method == "card":
                return redirect(target, code=303)
            # A cross-origin HTTP redirect after POST is blocked by form-action
            # 'self' in some browsers. Keep form submissions same-origin and
            # navigate from a local launch page without weakening the CSP.
            return render_template("payment_preview_launch.html", target=target, provider=provider)
        error = "Confirm that you will not send money or make a purchase while testing."
    response = make_response(render_template(
        "payment_preview.html", provider=provider, method=method,
        session_id=session_id, recovery_token=request.values.get("token"), error=error,
    ), 400 if error else 200)
    response.headers["Cache-Control"] = "private, no-store"
    return response


@pages_bp.route('/activate', methods=['GET', 'POST'])
@limiter.limit('5 per minute;20 per hour', methods=['POST'], key_func=browser_limit_key)
@limiter.limit('60 per minute', methods=['POST'])
def activate():
    from flask import current_app
    from .licensing import normalize_recipient_email
    from .patreon_shop import enqueue, enqueue_lookup, normalize_order_id, digest_email
    from .patreon_worker import wake
    from .extensions import db
    from sqlalchemy.exc import SQLAlchemyError
    if not current_app.config.get('PATREON_SHOP_ENABLED'):
        abort(404)
    status, error, accepted = 200, None, False
    if request.method == 'POST':
        email = normalize_recipient_email(request.form.get('email'))
        action = request.form.get('action', 'email')
        order_id = normalize_order_id(request.form.get('order_id'))
        if not email:
            status, error = 400, 'Please enter a valid email address.'
        elif action not in {'email', 'lookup'} or (action == 'lookup' and order_id is None):
            status, error = 400, 'Enter the order ID from your Patreon purchase receipt.'
        else:
            try:
                if action == 'lookup':
                    session['patreon_lookup'] = enqueue_lookup(email, order_id)
                    wake()
                    return redirect(url_for('pages.activate'), code=303)
                else:
                    enqueue(email)
                    import time
                    session['patreon_delivery'] = {'digest': digest_email(email), 'created_at': time.time()}
                    wake()
                    accepted = True
                    status = 202
            except SQLAlchemyError:
                db.session.rollback()
                status, error = 503, 'Your request could not be saved. Please try again shortly.'
    delivery = patreon_delivery_result()
    response = make_response(render_template('activate.html', error=error, accepted=accepted or bool(delivery),
                                            lookup=patreon_lookup_result(include_progress=True), delivery=delivery), status)
    response.headers['Cache-Control'] = 'private, no-store'
    response.headers['X-Robots-Tag'] = 'noindex, nofollow'
    return response


def patreon_lookup_result(*, include_progress=False):
    from .patreon_shop import browser_lookup
    from .extensions import db
    from .models import License
    lookup = browser_lookup(session.get('patreon_lookup'))
    if lookup is None:
        return None
    result = {'status': lookup.status}
    if lookup.status == 'ready':
        record = db.session.get(License, lookup.license_key)
        if record and record.signed_key:
            result['license_key'] = record.signed_key
        else:
            result['status'] = 'pending'
    if include_progress:
        from .purchase_activity import patreon_progress
        result['progress'] = patreon_progress(lookup)
    return result


def patreon_delivery_result():
    import time
    from .extensions import db
    from .models import PatreonShopCustomer
    from .patreon_shop import LOOKUP_LIFETIME
    from .purchase_activity import patreon_progress
    proof = session.get('patreon_delivery')
    if not isinstance(proof, dict) or not 0 <= time.time() - proof.get('created_at', 0) < LOOKUP_LIFETIME:
        return None
    row = db.session.get(PatreonShopCustomer, proof.get('digest'))
    if row is None:
        return None
    return {'status': 'pending' if row.pending else 'complete', 'progress': patreon_progress(row, email_only=True)}


@pages_bp.get('/activate/status')
@limiter.limit('180 per minute', key_func=browser_limit_key)
def patreon_license_status():
    if not current_app.config.get('PATREON_SHOP_ENABLED'):
        abort(404)
    if request.args.get('action') == 'email':
        return jsonify(patreon_delivery_result() or {'status': 'expired'})
    return jsonify(patreon_lookup_result(include_progress=request.args.get('progress') == '1') or {'status': 'expired'})


@pages_bp.post('/activate/download')
@limiter.limit('20 per minute', key_func=browser_limit_key)
def download_patreon_license():
    import json
    from io import BytesIO
    from flask import send_file
    if not current_app.config.get('PATREON_SHOP_ENABLED'):
        abort(404)
    result = patreon_lookup_result()
    if not result or not result.get('license_key'):
        abort(404)
    content = json.dumps({'schema': 2, 'product': 'porn-fetch', 'license_key': result['license_key']}, indent=2) + '\n'
    return send_file(BytesIO(content.encode()), as_attachment=True,
        download_name='porn_fetch.license', mimetype='application/octet-stream')
