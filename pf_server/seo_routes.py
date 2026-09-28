"""Crawl discovery for the commercial host only."""

from urllib.parse import urlsplit
from xml.sax.saxutils import escape

from flask import Blueprint, Response, abort, current_app, request

from .http import normalized_hostname

seo_bp = Blueprint("seo", __name__)


def _commercial_origin() -> str:
    origin = current_app.config["APP_DOMAIN"]
    if normalized_hostname(request.host) != urlsplit(origin).hostname:
        abort(404)
    return origin


@seo_bp.route("/robots.txt", methods=["GET"])
def robots():
    origin = _commercial_origin()
    lines = ["User-agent: *", "Allow: /"]
    if not current_app.config["NOWPAYMENTS_SANDBOX"]:
        lines.extend(["", f"Sitemap: {origin}/sitemap.xml"])
    return Response("\n".join(lines) + "\n", mimetype="text/plain")


@seo_bp.route("/sitemap.xml", methods=["GET"])
def sitemap():
    origin = _commercial_origin()
    if current_app.config["NOWPAYMENTS_SANDBOX"]:
        abort(404)
    location = escape(f"{origin}/porn_fetch")
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"  <url><loc>{location}</loc></url>\n"
        "</urlset>\n"
    )
    return Response(body, mimetype="application/xml")
