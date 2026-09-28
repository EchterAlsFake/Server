"""Block commercial-site visits referred by the school substitution-plan site."""

import hashlib
import hmac
import secrets
from urllib.parse import urlsplit

from flask import current_app, make_response, render_template, request

from .http import normalized_hostname

COOKIE_NAME = "__Host-vplan-block"
COOKIE_AGE_SECONDS = 400 * 24 * 60 * 60
VPLAN_HOST = "vplan.echteralsfake.me"


def _from_vplan(referer: str | None) -> bool:
    if not referer or len(referer) > 2048:
        return False
    try:
        parsed = urlsplit(referer)
        return (
            parsed.scheme.lower() == "https"
            and parsed.hostname == VPLAN_HOST
            and parsed.username is None
            and parsed.password is None
            and parsed.port in (None, 443)
        )
    except ValueError:
        return False


def _valid_marker(value: str | None, key: bytes) -> bool:
    if not value or len(value) > 128 or "." not in value:
        return False
    identifier, signature = value.split(".", 1)
    if len(identifier) != 32 or len(signature) != 64:
        return False
    expected = hmac.new(key, identifier.encode("ascii", "ignore"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)


def block_vplan_referrals():
    """Use an app-lifetime signing key and a host-only browser marker."""
    origin = current_app.config["APP_DOMAIN"]
    if normalized_hostname(request.host) != urlsplit(origin).hostname:
        return None
    if request.path == "/docs" or request.path.startswith("/docs/"):
        return None
    if request.path == "/dashboard" or request.path.startswith("/dashboard/"):
        return None

    key = current_app.extensions["vplan_referral_key"]
    marker = request.cookies.get(COOKIE_NAME)
    from_vplan = _from_vplan(request.headers.get("Referer"))
    if not from_vplan and not _valid_marker(marker, key):
        return None

    response = make_response(render_template("vplan_blocked.html"), 403)
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    response.headers["Referrer-Policy"] = "no-referrer"
    if from_vplan and not _valid_marker(marker, key):
        identifier = secrets.token_hex(16)
        signature = hmac.new(key, identifier.encode("ascii"), hashlib.sha256).hexdigest()
        marker = f"{identifier}.{signature}"
    response.set_cookie(
        COOKIE_NAME,
        marker,
        max_age=COOKIE_AGE_SECONDS,
        secure=True,
        httponly=True,
        samesite="Lax",
        path="/",
    )
    return response
