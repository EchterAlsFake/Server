"""Public product metadata and crawl discovery; private flows stay unindexed."""

from urllib.parse import urlsplit
from xml.sax.saxutils import escape

from flask import Blueprint, Response, abort, current_app, g, redirect, request

from .guide_content import GUIDES, GUIDE_DATE, GUIDE_PUBLISHED, guide_for_path, guide_path
from .http import normalized_hostname
from .website_locale import commercial_host, language, language_tag, path_in_language, published_languages, source_path, translate

seo_bp = Blueprint("seo", __name__)
PUBLIC_PAGES = {
    "/": (
        "Porn Fetch — Video Downloader for PornHub & More",
        "Porn Fetch saves videos from PornHub, XHamster, XVideos and other supported sites. Get the app for Android, iPhone, Windows, macOS or Linux.",
    ),
    "/download": (
        "Download Porn Fetch for Android, iPhone & Desktop",
        "Get Porn Fetch for Android, iPhone, Windows, macOS or Linux, or choose the CLI. Find setup instructions, system requirements and SHA-256 checksums.",
    ),
    "/about": (
        "About Porn Fetch — Independent Software by Johannes Habel",
        "Meet Johannes Habel, the developer of Porn Fetch. Find the app’s source code and learn how Premium purchases support its development.",
    ),
    "/help": (
        "Porn Fetch Help — Installation & License Activation",
        "Fix a Porn Fetch installation, verify a download or activate Premium. Find platform setup guides and the support details to include with your request.",
    ),
    "/releases": (
        "Porn Fetch Releases — Changelog & Previous Downloads",
        "Compare stable and beta Porn Fetch releases. Read what changed in each version and find its original download files and SHA-256 checksums.",
    ),
    "/guides": (
        "Video Download Guides for Supported Sites — Porn Fetch",
        "Find your site and follow illustrated Porn Fetch download steps for Android, iPhone, desktop or CLI. Check supported links and troubleshoot errors.",
    ),
    "/impress": (
        "Legal Disclosure — Porn Fetch",
        "Find the operator, postal address and contact information for Porn Fetch, the software project maintained by Johannes Habel in Germany.",
    ),
    "/privacy_policy": (
        "Privacy Policy — Porn Fetch",
        "Learn how Porn Fetch handles cookies, aggregate statistics, purchase records and support requests, and how to exercise your data protection rights.",
    ),
    "/terms": (
        "Terms of Service — Porn Fetch",
        "Read the Porn Fetch license terms for purchases, Premium activation, software updates and the rights that come with a license.",
    ),
    "/refund_policy": (
        "Refund Policy — Porn Fetch",
        "Find out how to request a refund or report a missing or defective Porn Fetch license. See what order information to include when you contact support.",
    ),
    "/legal-statement": (
        "Legal Statement & Responsible Use — Porn Fetch",
        "Learn how Porn Fetch describes third-party site compatibility, independent status and the rules for saving content you are authorized to download.",
    ),
}


def page_metadata():
    if hasattr(g, "page_meta"):
        return g.page_meta
    path = source_path()
    title_description = PUBLIC_PAGES.get(path)
    if title_description:
        title_description = tuple(translate(text) for text in title_description)
    release = None
    guide = guide_for_path(path)
    if guide:
        description = translate(guide["description"]) if "description" in guide else translate(
            "Porn Fetch guide for %(provider)s on Android, iPhone and desktop. %(summary)s",
            provider=guide["name"], summary=translate(guide["summary"]),
        )
        title_description = (
            translate("How to Download %(provider)s Videos — Porn Fetch", provider=guide["name"]),
            description,
        )
    if path.startswith("/download/"):
        from .download_pages import PLATFORMS

        platform = PLATFORMS.get(path.removeprefix("/download/"))
        if platform:
            title_description = tuple(translate(platform[field]) for field in ("title", "description"))
    elif path.startswith("/releases/"):
        from .download_pages import request_catalog

        version = path.removeprefix("/releases/")
        release = next((item for item in request_catalog()["releases"] if item["version"] == version), None)
        if release and language() in published_languages(path, release=release):
            title_description = (
                translate("Porn Fetch %(version)s — Release Notes & Downloads", version=version),
                translate("%(channel)s release of Porn Fetch %(version)s, published %(date)s. See release notes, original packages and SHA-256 checksums.",
                          channel=translate(release["channel"].capitalize()), version=version, date=release["published_at"][:10]),
            )
    if not title_description:
        return None
    origin = current_app.config["APP_DOMAIN"]
    locale = language()
    canonical_path = path_in_language(path, locale)
    locales = published_languages(path, release=release)
    language_urls = {code: path_in_language(path, code) for code in locales}
    title, description = title_description
    graph = [
        {
            "@type": "WebSite",
            "@id": origin + "/#website",
            "url": origin + "/",
            "name": "Porn Fetch",
            "publisher": {"@id": origin + "/#maintainer"},
        },
        {
            "@type": "Person",
            "@id": origin + "/#maintainer",
            "name": "Johannes Habel",
            "url": origin + "/about",
        },
    ]
    breadcrumbs = []
    if path == "/":
        graph.append(
            {
                "@type": "SoftwareApplication",
                "@id": origin + "/#software",
                "name": "Porn Fetch",
                "url": origin + canonical_path,
                "downloadUrl": origin + path_in_language("/download", locale),
                "applicationCategory": "MultimediaApplication",
                "operatingSystem": [
                    "Windows",
                    "Linux",
                    "macOS",
                    "Android",
                    "iOS 15.0 or later · native GUI",
                ],
                "publisher": {"@id": origin + "/#maintainer"},
                "description": description,
                "inLanguage": language_tag(locale),
            }
        )
    else:
        crumbs = [(translate("Home"), "/")]
        if guide:
            crumbs.append((translate("Guides"), "/guides"))
        if path.startswith("/download/"):
            crumbs.append((translate("Downloads"), "/download"))
        if path.startswith("/releases/"):
            crumbs.append((translate("Releases"), "/releases"))
        crumbs.append((title.split(" — ")[0], path))
        crumbs = [(name, path_in_language(location, locale)) for name, location in crumbs]
        breadcrumbs = [{"name": name, "url": location} for name, location in crumbs]
        graph.append(
            {
                "@type": "BreadcrumbList",
                "itemListElement": [
                    {
                        "@type": "ListItem",
                        "position": index,
                        "name": name,
                        "item": origin + location,
                    }
                    for index, (name, location) in enumerate(crumbs, 1)
                ],
            }
        )
    if guide:
        graph.append({
            "@type": "Article",
            "@id": origin + canonical_path + "#article",
            "headline": title.split(" — ")[0],
            "description": description,
            "mainEntityOfPage": origin + canonical_path,
            "inLanguage": language_tag(locale),
            "datePublished": guide.get("published", GUIDE_PUBLISHED),
            "image": origin + "/static/media/web/guide-ios-ready-3.9.1-720.webp",
            "dateModified": guide.get("updated", guide.get("published", GUIDE_DATE)),
            "author": {"@id": origin + "/#maintainer"},
            "publisher": {"@id": origin + "/#maintainer"},
        })
    g.page_meta = {
        "title": title,
        "description": description,
        "canonical": origin + canonical_path,
        "language_urls": language_urls if len(language_urls) > 1 else {},
        "alternates": {
            language_tag(code): origin + url for code, url in {**language_urls, "x-default": path}.items()
        } if len(language_urls) > 1 and commercial_host() and current_app.config["SEO_INDEXING_ENABLED"] else {},
        "breadcrumbs": breadcrumbs,
        "og_type": "article" if guide else "website",
        "image": origin + ("/static/media/web/guide-ios-ready-3.9.1-720.webp" if guide else "/static/media/promo-poster.jpg"),
        "image_alt": translate("Porn Fetch native iPhone app with a video ready to download" if guide
                               else "Porn Fetch video downloader interface"),
        "image_width": 720 if guide else 1920,
        "image_height": 1281 if guide else 1080,
        "structured": {"@context": "https://schema.org", "@graph": graph},
    }
    return g.page_meta


def indexing_directive():
    """Only explicitly public pages on the configured product host are indexable."""
    from .onion import is_onion

    if is_onion():
        return "noindex, follow"
    if not current_app.config["SEO_INDEXING_ENABLED"] or not commercial_host():
        return "noindex, nofollow"
    return "index, follow" if page_metadata() else "noindex"


@seo_bp.app_context_processor
def seo_context():
    return {"page_meta": page_metadata(), "robots_directive": indexing_directive()}


@seo_bp.before_app_request
def canonical_www_redirect():
    """Keep the product www alias canonical even with an older proxy config."""
    origin = current_app.config["APP_DOMAIN"]
    host = urlsplit(origin).hostname
    if request.method in {"GET", "HEAD"} and normalized_hostname(request.host) == "www." + host:
        return redirect(origin + request.full_path.removesuffix("?"), code=308)


@seo_bp.after_app_request
def indexing_headers(response):
    # Documentation is a separate site with its own presentation and policy.
    if normalized_hostname(request.host).startswith("docs."):
        return response
    if request.endpoint == "static" or request.path in {"/robots.txt", "/sitemap.xml"}:
        return response
    directive = indexing_directive() if response.status_code == 200 else "noindex"
    # Preserve stricter feature-specific directives (downloads, referral blocks).
    response.headers.setdefault("X-Robots-Tag", directive)
    return response


def _commercial_origin():
    origin = current_app.config["APP_DOMAIN"]
    if not commercial_host():
        abort(404)
    return origin


@seo_bp.get("/robots.txt")
def robots():
    origin = _commercial_origin()
    # noindex is delivered in HTML/HTTP headers. Do not block crawling of it.
    lines = ["User-agent: *", "Allow: /"]
    if current_app.config["SEO_INDEXING_ENABLED"]:
        lines.extend(["", f"Sitemap: {origin}/sitemap.xml"])
    return Response("\n".join(lines) + "\n", mimetype="text/plain")


@seo_bp.get("/sitemap.xml")
def sitemap():
    origin = _commercial_origin()
    if not current_app.config["SEO_INDEXING_ENABLED"]:
        abort(404)
    from .download_pages import PLATFORMS, request_catalog

    paths = [
        *PUBLIC_PAGES,
        *(guide_path(provider) for provider in GUIDES),
        *(f"/download/{key}" for key in PLATFORMS),
    ]
    releases = {f"/releases/{release['version']}": release for release in request_catalog()["releases"]}
    entries = "\n".join(
        f"  <url><loc>{escape(origin + path_in_language(path, locale))}</loc>"
        + (f"<lastmod>{guide.get('updated', guide.get('published', GUIDE_DATE))}</lastmod>"
           if (guide := guide_for_path(path)) else "")
        + "</url>"
        for path in [*paths, *releases]
        for locale in published_languages(path, release=releases.get(path))
    )
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + entries
        + "\n</urlset>\n"
    )
    return Response(body, mimetype="application/xml")
