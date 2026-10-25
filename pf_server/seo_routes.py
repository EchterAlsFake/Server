"""Public product metadata and crawl discovery; private flows stay unindexed."""

from urllib.parse import urlsplit
from xml.sax.saxutils import escape

from flask import Blueprint, Response, abort, current_app, request

from .http import normalized_hostname

seo_bp = Blueprint("seo", __name__)
PUBLIC_PAGES = {
    "/": (
        "Porn Fetch — Download Videos & Collections to Your Device",
        "Porn Fetch saves supported videos, playlists and collections locally. Explore desktop, Android and CLI downloads, privacy controls, and the one-time Premium license.",
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
}


def page_metadata():
    path = request.path
    title_description = PUBLIC_PAGES.get(path)
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
        if path.startswith("/download/"):
            crumbs.append(("Downloads", "/download"))
        if path.startswith("/releases/"):
            crumbs.append(("Releases", "/releases"))
        crumbs.append((title.split(" — ")[0], path))
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
    return {
        "title": title,
        "description": description,
        "canonical": origin + path,
        "structured": {"@context": "https://schema.org", "@graph": graph},
    }


@seo_bp.app_context_processor
def seo_context():
    return {"page_meta": page_metadata()}


def _commercial_origin():
    origin = current_app.config["APP_DOMAIN"]
    if normalized_hostname(request.host) != urlsplit(origin).hostname:
        abort(404)
    return origin


@seo_bp.get("/robots.txt")
def robots():
    origin = _commercial_origin()
    # noindex is delivered in HTML/HTTP headers. Do not block crawling of it.
    lines = ["User-agent: *", "Allow: /"]
    if not current_app.config["NOWPAYMENTS_SANDBOX"]:
        lines.extend(["", f"Sitemap: {origin}/sitemap.xml"])
    else:
        lines = ["User-agent: *", "Disallow: /"]
    return Response("\n".join(lines) + "\n", mimetype="text/plain")


@seo_bp.get("/sitemap.xml")
def sitemap():
    origin = _commercial_origin()
    if current_app.config["NOWPAYMENTS_SANDBOX"]:
        abort(404)
    from .download_pages import PLATFORMS, load_catalog

    paths = [
        *PUBLIC_PAGES,
        *(f"/download/{key}" for key in PLATFORMS),
        *(f"/releases/{release['version']}" for release in load_catalog()["releases"]),
    ]
    entries = "\n".join(
        f"  <url><loc>{escape(origin + path)}</loc></url>" for path in paths
    )
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + entries
        + "\n</urlset>\n"
    )
    return Response(body, mimetype="application/xml")
