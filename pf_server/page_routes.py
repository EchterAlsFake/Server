"""Public HTML pages and the neutral landing-page access gate."""

import hashlib
import hmac

from flask import (
    Blueprint,
    current_app,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .extensions import limiter

pages_bp = Blueprint("pages", __name__)


def check_site_auth() -> bool:
    auth_secret = current_app.config.get("CHECKLIST_AUTH")
    saved_marker = session.get("site_auth")
    if not auth_secret or not isinstance(saved_marker, str):
        return False
    return hmac.compare_digest(saved_marker, _site_auth_marker(auth_secret))


def _site_auth_marker(auth_secret: str) -> str:
    signing_key = str(current_app.config["SECRET_KEY"]).encode("utf-8")
    return hmac.new(
        signing_key,
        b"site-auth\x00" + auth_secret.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _safe_local_redirect(value, default="/"):
    if (
        isinstance(value, str)
        and value.startswith("/")
        and not value.startswith("//")
        and "\\" not in value
        and not any(character in value for character in ("\r", "\n", "\x00"))
    ):
        return value
    return default


def _render_site_access(*, unavailable, next_url, error=None, status=200):
    response = make_response(
        render_template(
            "site_access.html",
            unavailable=unavailable,
            next_url=next_url,
            error=error,
        ),
        status,
    )
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    return response


@pages_bp.route("/", methods=["GET"])
def landing_page():
    if not check_site_auth():
        response = redirect(url_for("pages.site_access", next="/"))
    else:
        response = make_response(render_template("index.html"))
        response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    response.headers["Cache-Control"] = "private, no-store"
    return response


@pages_bp.route("/access", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def site_access():
    auth_secret = current_app.config.get("CHECKLIST_AUTH")
    next_url = _safe_local_redirect(
        request.form.get("next") if request.method == "POST" else request.args.get("next"),
        default="/",
    )
    if not auth_secret:
        return _render_site_access(unavailable=True, next_url=next_url, status=503)

    if request.method == "POST":
        provided = request.form.get("password", "")
        if hmac.compare_digest(provided.encode("utf-8"), auth_secret.encode("utf-8")):
            session["site_auth"] = _site_auth_marker(auth_secret)
            response = redirect(next_url)
            response.headers["Cache-Control"] = "private, no-store"
            return response
        return _render_site_access(
            error="Das Passwort ist nicht korrekt.",
            unavailable=False,
            next_url=next_url,
            status=401,
        )

    if check_site_auth():
        return redirect(next_url)
    return _render_site_access(unavailable=False, next_url=next_url)


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
    return render_template("porn_fetch.html")


@pages_bp.route("/donation", methods=["GET"])
def donation():
    return render_template("donation.html")


@pages_bp.route("/datenschutz", methods=["GET"])
def datenschutz():
    return render_template("privacy_policy_de.html")


@pages_bp.route("/privacy_policy", methods=["GET"])
def privacy_policy():
    return render_template("privacy_policy_en.html")


@pages_bp.route("/legal-statement", methods=["GET"])
def legal_compliance():
    return render_template("legal-statement.html")
