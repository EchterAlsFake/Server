"""URL-based language selection for the public product website."""

import json
import re
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from babel import Locale
from flask import current_app, g, has_app_context, render_template, request
from markupsafe import Markup, escape
from werkzeug.exceptions import HTTPException, MethodNotAllowed, NotFound
from werkzeug.routing import RequestRedirect

from .http import normalized_hostname

LANGUAGES = {"en": "English", "de": "Deutsch", "es": "Español", "hi": "हिन्दी", "zh-hans": "简体中文"}
LANGUAGE_TAGS = {"zh-hans": "zh-Hans"}
CATALOG_DIR = Path(__file__).resolve().parents[1] / "i18n" / "website"
# Reuse the GET views so localized pages share release and guide data with English.
LOCALIZED_ROUTES = {
    "/": "pages.landing_page",
    "/download": "pages.download",
    "/download/<platform>": "downloads.platform_download",
    "/about": "pages.about",
    "/help": "downloads.help_page",
    "/guides": "guides.index",
    "/guides/download-<provider>-videos": "guides.provider_guide",
    "/releases": "downloads.release_history",
    "/releases/<version>": "downloads.release_notes",
    "/impress": "pages.impress",
    "/privacy_policy": "pages.privacy_policy",
    "/terms": "pages.terms",
    "/refund_policy": "pages.refund_policy",
    "/legal-statement": "pages.legal_compliance",
}

BROWSER_ROUTES = {
    "/porn_fetch", "/checkout/start", "/checkout/crypto-confirm", "/checkout/agreement",
    "/buy_license", "/buy_card", "/buy_paywarp", "/buy_success", "/buy_cancel",
    "/activate", "/activate/status", "/activate/download", "/donation", "/leave",
    "/confirm-age", "/check-payment-status", "/create-crypto-payment",
    "/create-paywarp-payment", "/create-onramp-payment", "/onramp-acknowledgment",
    "/onramp-callback", "/simulate-payment-success", "/download-recovery",
    "/download_license", "/download_invoice", "/download_contract",
    "/mollie/test", "/mollie/unlock", "/mollie/lock", "/mollie/checkout", "/mollie/launch",
    "/withdrawal", "/withdrawal/preview", "/withdrawal/edit", "/withdrawal/confirm",
    "/withdrawal/receipt", "/transparency", "/stats", "/checklist", "/checklist/login",
}
BROWSER_PATHS = re.compile(
    r"^/(?:payment-preview/(?:patreon|card|banxa)|docs(?:/.*)?|"
    r"checklist/api/(?:tasks|add|(?:toggle|remove)/[0-9]+)|static/notices/[a-z-]+\.txt)$"
)
ERROR_MESSAGES = {
    400: "Check your details and try again.",
    403: "You do not have access to this page.",
    404: "Page not found.",
    405: "This action is unavailable here.",
    409: "The request could not be completed. Reload and try again.",
    410: "This link is no longer available.",
    500: "Something went wrong. Please try again.",
    503: "This service is temporarily unavailable. Please try again later.",
}


def browser_path(path):
    return path in BROWSER_ROUTES or BROWSER_PATHS.fullmatch(path) is not None


def split_language(path):
    prefix, _, suffix = path[1:].partition("/")
    if prefix in LANGUAGES and prefix != "en":
        return prefix, "/" + suffix
    return "en", path


class WebsiteLocaleMiddleware:
    """Strip browser locale prefixes before routing and the checkout guards."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        locale, path = split_language(environ.get("PATH_INFO", ""))
        if locale != "en" and (browser_path(path) or environ.get("HTTP_HOST", "").lower().startswith("docs.")):
            environ["pf.website_language"] = locale
            environ["PATH_INFO"] = path
        return self.wsgi_app(environ, start_response)


@lru_cache
def catalog_for(language):
    if language == "en":
        return {}
    return json.loads((CATALOG_DIR / f"{language}.json").read_text(encoding="utf-8"))


def language():
    return g.get("website_language", "en") if has_app_context() else "en"


@contextmanager
def use_language(locale):
    previous = language()
    g.website_language = locale
    try:
        yield
    finally:
        g.website_language = previous


def language_tag(locale):
    return LANGUAGE_TAGS.get(locale, locale)


def country_label(code):
    from .countries import COUNTRIES

    if language() == "en":
        return COUNTRIES.get(code, code)
    locale = Locale.parse(language_tag(language()), sep="-")
    return locale.territories.get(code, COUNTRIES.get(code, code))


def artifact_platform(platform):
    names = {"macos": "macOS", "ios": "iOS", "any": translate("All platforms")}
    return names.get(platform, platform.capitalize())


def artifact_kind(kind):
    names = {
        "gui": "Desktop app", "cli": "CLI", "installer": "Installer",
        "apk": "APK", "ipa": "IPA", "source": "Source code", "notices": "Legal notices",
    }
    return translate(names.get(kind, kind))


def source_path():
    return g.get("website_source_path", request.path)


def translate(message, **values):
    translation = catalog_for(language()).get(message, message)
    return translation % values if values else translation


@lru_cache
def browser_message_keys():
    return json.loads((CATALOG_DIR.parent / "browser_messages.json").read_text(encoding="utf-8"))


def browser_messages():
    catalog = catalog_for(language())
    return {key: catalog[key] for key in browser_message_keys() if key in catalog}


def commercial_host():
    return normalized_hostname(request.host) == urlsplit(current_app.config["APP_DOMAIN"]).hostname


def path_in_language(path, locale):
    return path if locale == "en" else f"/{locale}{path}"


def has_localized_route(path, locale):
    if browser_path(path):
        return True
    try:
        _, values = current_app.url_map.bind("").match(path_in_language(path, locale))
    except (NotFound, MethodNotAllowed, RequestRedirect):
        return False
    return values.get("website_locale") == locale


def published_languages(path, *, release=None):
    locales = [code for code in LANGUAGES if code == "en" or has_localized_route(path, code)]
    if path.startswith("/releases/"):
        if not release:
            return ["en"]
        translations = {code for code, notes in release.get("notes_i18n", {}).items() if notes.strip()}
        if release["notes"].strip() or translations:
            return [code for code in locales if code == "en" or code in translations]
    return locales


def site_path(path):
    """Return the published equivalent of a product link, if one exists."""
    locale = language()
    if locale == "en":
        return path
    parts = urlsplit(path)
    if parts.scheme or parts.netloc or not parts.path.startswith("/"):
        return path
    if not has_localized_route(parts.path, locale):
        return path
    if parts.path.startswith("/releases/"):
        from .download_pages import request_catalog

        release = next((item for item in request_catalog()["releases"] if item["version"] == parts.path.rsplit("/", 1)[-1]), None)
        if locale not in published_languages(parts.path, release=release):
            return path
    return parts._replace(path=path_in_language(parts.path, locale)).geturl()


def browser_language_urls():
    if not browser_path(source_path()) or request.method not in {"GET", "HEAD"}:
        return {}
    query = request.query_string.decode("ascii", errors="replace")
    return {code: path_in_language(source_path(), code) + ("?" + query if query else "") for code in LANGUAGES}


def site_link(path):
    """Render attributes for a product link, including the language of a fallback."""
    target = site_path(path)
    attrs = Markup('href="{}"').format(target)
    if language() != "en" and target == path and not path.startswith(("/static/", "/downloads/")):
        attrs += Markup(' hreflang="en" data-language-fallback title="{}"').format(translate("Page in English"))
    return attrs


def init_website_locale(app):
    app.wsgi_app = WebsiteLocaleMiddleware(app.wsgi_app)
    app.jinja_env.add_extension("jinja2.ext.i18n")
    # Jinja handles interpolation and escaping for {% trans %} and gettext calls.
    app.jinja_env.install_gettext_callables(
        lambda message: escape(translate(message)),
        lambda singular, plural, number: escape(translate(singular if number == 1 else plural)),
        newstyle=True,
    )
    app.jinja_env.globals.update(
        site_path=site_path, site_link=site_link, site_text=translate,
        language_tag=language_tag, browser_messages=browser_messages, country_label=country_label,
        artifact_platform=artifact_platform, artifact_kind=artifact_kind,
    )

    @app.url_value_preprocessor
    def select_language(endpoint, values):
        if values and (locale := values.pop("website_locale", None)):
            g.website_language = locale
            g.website_source_path = request.path.removeprefix(f"/{locale}")
        elif locale := request.environ.get("pf.website_language"):
            g.website_language = locale
        elif endpoint is None:
            g.website_language = split_language(request.path)[0]

    @app.after_request
    def localize_redirect(response):
        if response.status_code in {301, 302, 303, 307, 308} and response.location:
            response.location = site_path(response.location)
        return response

    @app.errorhandler(HTTPException)
    def website_error(error):
        response = error.get_response()
        if language() == "en":
            return response
        message = (translate(error.description) if error.description != type(error).description
                   else translate(ERROR_MESSAGES.get(error.code, ERROR_MESSAGES[500])))
        if request.is_json or request.accept_mimetypes.best == "application/json":
            response.set_data(current_app.json.dumps({"error": message}))
            response.mimetype = "application/json"
        else:
            response.set_data(render_template("website_error.html", message=message, code=error.code))
        return response

    for locale in LANGUAGES:
        if locale == "en":
            continue
        catalog_for(locale)
        for path, endpoint in LOCALIZED_ROUTES.items():
            localized_endpoint = f"localized_website_{locale}_{endpoint.replace('.', '_')}"
            app.add_url_rule(
                path_in_language(path, locale), localized_endpoint, app.view_functions[endpoint],
                defaults={"website_locale": locale}, methods=["GET"],
            )

    @app.context_processor
    def language_context():
        return {
            "website_language": language(), "website_source_path": source_path(),
            "website_language_names": LANGUAGES, "browser_language_urls": browser_language_urls(),
        }
