"""Public, server-rendered guides for the app's supported providers."""

from datetime import date

from flask import Blueprint, abort, render_template

from .download_pages import load_catalog
from .guide_content import GUIDES, GUIDE_DATE, GUIDE_VERSION
from .product_catalog import WEBSITES

guides_bp = Blueprint("guides", __name__)


@guides_bp.get("/guides")
def index():
    return render_template("guides.html", guides=GUIDES)


@guides_bp.get("/guides/download-<provider>-videos")
def provider_guide(provider):
    guide = GUIDES.get(provider)
    if guide is None:
        abort(404)
    releases = load_catalog()
    updated = guide.get("updated", GUIDE_DATE)
    return render_template(
        "video_guide.html", guide=guide, guides=GUIDES, provider=provider,
        guide_date=updated, guide_version=GUIDE_VERSION,
        guide_date_label=date.fromisoformat(updated).strftime("%d %B %Y").lstrip("0"),
        supports_profiles=any(row[0] == guide["name"] and row[2] == "Yes" for row in WEBSITES),
        releases_available=bool(releases["releases"]),
        catalog_unavailable=releases["unavailable"],
    )
