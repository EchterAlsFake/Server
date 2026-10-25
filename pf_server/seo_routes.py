"""Public product metadata and crawl discovery; private flows stay unindexed."""

from urllib.parse import urlsplit
from xml.sax.saxutils import escape

from flask import Blueprint, Response, abort, current_app, g, redirect, request

from .guide_content import GUIDES, GUIDE_DATE, guide_for_path, guide_path
from .http import normalized_hostname

seo_bp = Blueprint("seo", __name__)
PUBLIC_PAGES = {
    "/": (
        "Porn Fetch — Video Downloader for PornHub & More",
        "Download videos from PornHub, XHamster, XVideos and other supported adult websites with Porn Fetch. Get the app, read practical guides, and save files locally.",
    ),
    "/download": (
        "Download Porn Fetch — Windows, Linux, macOS, Android & CLI",
        "Official Porn Fetch downloads hosted here. Choose your platform and architecture, check requirements and SHA-256 checksums, and read local setup guides.",
    ),
    "/about": (
        "About Porn Fetch — Independent Software by Johannes Habel",
        "Meet Johannes Habel, the independent developer and maintainer of Porn Fetch. Learn about the app, source availability, Premium, and support.",
    ),
    "/help": (
        "Porn Fetch Help — Installation & License Activation",
        "Get help installing Porn Fetch, choosing a download, activating a license, and resolving common setup issues. Contact the developer directly.",
    ),
    "/releases": (
        "Porn Fetch Releases — Changelog & Previous Downloads",
        "Browse Porn Fetch release notes, publication dates, previous downloads, checksums and legal notices on the official product website.",
    ),
    "/guides": (
        "Video Download Guides for PornHub & More — Porn Fetch",
        "Learn how to download videos from all 15 supported websites with Porn Fetch. Find steps for PornHub, XHamster, XVideos, Eporner and more, with actual app limitations.",
    ),
    "/impress": (
        "Legal Disclosure / Impressum — Porn Fetch",
        "Legal disclosure and contact details for Porn Fetch, the independent software project maintained by Johannes Habel in Germany.",
    ),
    "/privacy_policy": (
        "Privacy Policy / Datenschutzerklärung — Porn Fetch",
        "How the Porn Fetch website handles session cookies, aggregate statistics, license purchases, payment providers and support. Read the English and German privacy policy.",
    ),
    "/terms": (
        "Terms of Service / AGB — Porn Fetch",
        "Read Porn Fetch’s terms for software licenses, activation, updates, purchases and use of the website in English and German.",
    ),
    "/refund_policy": (
        "Refund Policy — Porn Fetch",
        "Read the refund and cancellation policy for Porn Fetch licenses, including how to contact the developer about a purchase.",
    ),
    "/legal-statement": (
        "Legal Statement & Responsible Use — Porn Fetch",
        "Learn about Porn Fetch’s independent status, website compatibility, and responsible use of the software for content you are authorized to save.",
    ),
}


def page_metadata():
    if hasattr(g, "page_meta"):
        return g.page_meta
    path = request.path
    title_description = PUBLIC_PAGES.get(path)
    guide = guide_for_path(path)
    if guide:
        title_description = (
            f"How to Download {guide['name']} Videos — Porn Fetch",
            f"Learn how to download {guide['name']} videos with Porn Fetch. Follow the app’s actual steps, choose an available quality, and check supported links and limitations.",
        )
    if path.startswith("/download/"):
        from .download_pages import PLATFORMS

        platform = PLATFORMS.get(path.removeprefix("/download/"))
        if platform:
            title_description = (
                f"Download Porn Fetch for {platform['name']} — Installation & Requirements",
                f"Official Porn Fetch {platform['name']} downloads and installation guide. {platform['summary']} Requirements: {platform['requirements']}.",
            )
    elif path.startswith("/releases/"):
        from .download_pages import load_catalog

        version = path.removeprefix("/releases/")
        if any(item["version"] == version for item in load_catalog()["releases"]):
            title_description = (
                f"Porn Fetch {version} — Release Notes & Downloads",
                f"Read Porn Fetch {version} release notes and download its original packages, SHA-256 checksums, and legal notices.",
            )
    if not title_description:
        return None
    origin = current_app.config["APP_DOMAIN"]
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
                "url": origin + "/",
                "downloadUrl": origin + "/download",
                "applicationCategory": "MultimediaApplication",
                "operatingSystem": [
                    "Windows",
                    "Linux",
                    "macOS",
                    "Android",
                    "iOS: jailbroken iPhone, CLI only",
                ],
                "publisher": {"@id": origin + "/#maintainer"},
                "description": description,
            }
        )
    else:
        crumbs = [("Home", "/")]
        if guide:
            crumbs.append(("Guides", "/guides"))
        if path.startswith("/download/"):
            crumbs.append(("Downloads", "/download"))
        if path.startswith("/releases/"):
            crumbs.append(("Releases", "/releases"))
        crumbs.append((title.split(" — ")[0], path))
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
            "@id": origin + path + "#article",
            "headline": title.split(" — ")[0],
            "description": description,
            "mainEntityOfPage": origin + path,
            "inLanguage": "en",
            "datePublished": GUIDE_DATE,
            "dateModified": guide.get("updated", GUIDE_DATE),
            "author": {"@id": origin + "/#maintainer"},
            "publisher": {"@id": origin + "/#maintainer"},
        })
    g.page_meta = {
        "title": title,
        "description": description,
        "canonical": origin + path,
        "breadcrumbs": breadcrumbs,
        "og_type": "article" if guide else "website",
        "structured": {"@context": "https://schema.org", "@graph": graph},
    }
    return g.page_meta


def indexing_directive():
    """Only explicitly public pages on the configured product host are indexable."""
    from .onion import is_onion

    if is_onion():
        return "noindex, follow"
    if not current_app.config["SEO_INDEXING_ENABLED"] or not _is_commercial_host():
        return "noindex, nofollow"
    return "index, follow" if page_metadata() else "noindex"


@seo_bp.app_context_processor
def seo_context():
    return {"page_meta": page_metadata(), "robots_directive": indexing_directive()}


def _is_commercial_host():
    return normalized_hostname(request.host) == urlsplit(current_app.config["APP_DOMAIN"]).hostname


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
    if not _is_commercial_host():
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
    from .download_pages import PLATFORMS, load_catalog

    paths = [
        *PUBLIC_PAGES,
        *(guide_path(provider) for provider in GUIDES),
        *(f"/download/{key}" for key in PLATFORMS),
        *(f"/releases/{release['version']}" for release in load_catalog()["releases"]),
    ]
    entries = "\n".join(
        f"  <url><loc>{escape(origin + path)}</loc>"
        + (f"<lastmod>{guide_for_path(path).get('updated', GUIDE_DATE)}</lastmod>" if guide_for_path(path) else "")
        + "</url>" for path in paths
    )
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + entries
        + "\n</urlset>\n"
    )
    return Response(body, mimetype="application/xml")
