"""URL-based language selection for the public product website."""

import json
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from flask import current_app, g, request
from markupsafe import Markup, escape
from werkzeug.exceptions import MethodNotAllowed, NotFound
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


@lru_cache
def catalog_for(language):
    if language == "en":
        return {}
    return json.loads((CATALOG_DIR / f"{language}.json").read_text(encoding="utf-8"))


def language():
    return g.get("website_language", "en")


def language_tag(locale):
    return LANGUAGE_TAGS.get(locale, locale)


def source_path():
    return g.get("website_source_path", request.path)


def translate(message, **values):
    translation = catalog_for(language()).get(message, message)
    return translation % values if values else translation


def commercial_host():
    return normalized_hostname(request.host) == urlsplit(current_app.config["APP_DOMAIN"]).hostname


def path_in_language(path, locale):
    return path if locale == "en" else f"/{locale}{path}"


def has_localized_route(path, locale):
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


def site_link(path):
    """Render attributes for a product link, including the language of a fallback."""
    target = site_path(path)
    attrs = Markup('href="{}"').format(target)
    if language() != "en" and target == path and not path.startswith(("/static/", "/downloads/")):
        attrs += Markup(' hreflang="en" data-language-fallback title="{}"').format(translate("Page in English"))
    return attrs


def init_website_locale(app):
    app.jinja_env.add_extension("jinja2.ext.i18n")
    # Jinja handles interpolation and escaping for {% trans %} and gettext calls.
    app.jinja_env.install_gettext_callables(
        lambda message: escape(translate(message)),
        lambda singular, plural, number: escape(translate(singular if number == 1 else plural)),
        newstyle=True,
    )
    app.jinja_env.globals.update(site_path=site_path, site_link=site_link, site_text=translate, language_tag=language_tag)

    @app.url_value_preprocessor
    def select_language(endpoint, values):
        if values and (locale := values.pop("website_locale", None)):
            g.website_language = locale
            g.website_source_path = request.path.removeprefix(f"/{locale}")

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
        return {"website_language": language(), "website_source_path": source_path(), "website_language_names": LANGUAGES}
