"""Read-only onion presentation; purchase and publisher protocols stay on HTTPS."""

from urllib.parse import urlsplit

from flask import abort, current_app, render_template, request
from flask.sessions import SecureCookieSessionInterface
from .website_locale import language, path_in_language, source_path

DEFAULT_ONION_ORIGIN = "http://pornfetchc5ct7s7uiervf4ziymmus5gy33gyqc6vkdtqyr5pbxrxmid.onion"
PURCHASE_PATHS = {"/porn_fetch", "/buy_license", "/buy_card", "/buy_paywarp", "/donation"}


def is_onion():
    return request.host.split(":", 1)[0].lower() == urlsplit(current_app.config["ONION_ORIGIN"]).hostname


def before_onion_request():
    if not is_onion():
        return None
    if request.method not in {"GET", "HEAD"}:
        abort(404)
    if request.path in PURCHASE_PATHS:
        return render_template("onion_checkout.html")
    allowed = {"/", "/about", "/help", "/impress", "/privacy_policy", "/terms", "/refund_policy",
               "/legal-statement", "/transparency", "/download", "/releases", "/guides", "/robots.txt", "/sitemap.xml"}
    path = source_path()
    if path not in allowed and not path.startswith(("/static/", "/docs/", "/guides/", "/download/", "/downloads/", "/releases/", "/repo/android/")):
        abort(404)
    return None


def onion_headers(response):
    path = source_path()
    if is_onion():
        response.headers["X-Robots-Tag"] = "noindex, follow"
        response.headers.pop("Strict-Transport-Security", None)
    elif request.is_secure and request.method in {"GET", "HEAD"} and path not in PURCHASE_PATHS and (
        path in {"/", "/about", "/help", "/download", "/releases", "/guides"}
        or path.startswith(("/download/", "/releases/", "/guides/", "/docs/"))
    ):
        response.headers["Onion-Location"] = current_app.config["ONION_ORIGIN"] + path_in_language(path, language())
    return response


def init_onion(app):
    # Register ahead of session-bearing view handlers and aggregate counting.
    app.before_request(before_onion_request)
    app.after_request(onion_headers)
    app.context_processor(lambda: {"is_onion": is_onion()})
    app.session_interface = OnionSessionInterface()


class OnionSessionInterface(SecureCookieSessionInterface):
    """The authenticated onion origin uses HTTP inside Tor, rather than HTTPS."""

    def get_cookie_secure(self, app):
        return False if is_onion() else super().get_cookie_secure(app)
