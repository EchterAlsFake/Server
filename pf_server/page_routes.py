"""Marketing pages, bilingual documents and session-based age confirmation."""

import time
from collections.abc import Mapping
from urllib.parse import parse_qs, urlsplit

from flask import (
    Blueprint, abort, jsonify, make_response, redirect, render_template,
    request, session, url_for,
)

from .checkout_consent import CONSENT_VERSION, FIELDS, current_consent
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
    return {"age_required": not is_onion() and request.path in AGE_GATED_PATHS and not session.get("adult_confirmed"), "checkout_consent": current_consent()}


@pages_bp.after_app_request
def private_age_state(response):
    if normalized_hostname(request.host).startswith("docs."):
        return response
    if request.path in AGE_GATED_PATHS or request.path in {"/leave", "/checkout/start"}:
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
    return redirect("/docs/transparency/", code=301)


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
    country = data.get("country")
    def accepted(field):
        return data.get(field) == "yes" or data.get(field) is True

    if not isinstance(method, str) or not isinstance(country, str) or method not in {"crypto", "patreon", "card"} or country not in dict(COUNTRY_OPTIONS) or not all(accepted(field) for field in FIELDS):
        error = "Choose your payment method and country, then accept all required confirmations."
        if request.is_json:
            return jsonify(error=error), 400
        return render_template("porn_fetch.html", countries=COUNTRY_OPTIONS, checkout_error=error), 400
    session["checkout_consent"] = dict(version=CONSENT_VERSION, accepted_at=time.time(), country=country, payment_method=method, **{field: True for field in FIELDS})
    target = url_for("payments.buy_license") if method == "crypto" else url_for("pages.payment_preview", method=method)
    if request.is_json:
        return jsonify(next=target, method=method)
    return redirect(target, code=303)


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
    provider = "Patreon" if method == "patreon" else "Onramp Pay / Banxa"
    session_id = request.values.get("session_id", "")
    target = (
        "https://www.patreon.com/profile/creators?u=214243387&vanity=profile"
        if method == "patreon" else url_for("onramp.buy_card")
    )
    if method == "banxa":
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
            if method == "card":
                return redirect(target, code=303)
            # A cross-origin HTTP redirect after POST is blocked by form-action
            # 'self' in some browsers. Keep form submissions same-origin and
            # navigate from a local launch page without weakening the CSP.
            return render_template("payment_preview_launch.html", target=target, provider=provider)
        error = "Confirm that you will not send money or start a paid membership while testing."
    response = make_response(render_template(
        "payment_preview.html", provider=provider, method=method,
        session_id=session_id, error=error,
    ), 400 if error else 200)
    response.headers["Cache-Control"] = "private, no-store"
    return response
