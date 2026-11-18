"""Public, server-rendered guides for the app's supported providers."""

from datetime import date

from flask import Blueprint, abort, render_template

from .download_pages import load_catalog
from .guide_content import GUIDES, GUIDE_DATE, GUIDE_VERSION, RELATED_GUIDES
from .product_catalog import WEBSITES, WEBSITE_SUPPORT_VERSION
from .website_locale import language, translate
from .website_releases import latest_artifacts

guides_bp = Blueprint("guides", __name__)
GUIDE_DATE_FORMATS = {"en": "%d %B %Y", "de": "%d.%m.%Y", "es": "%d/%m/%Y", "hi": "%d/%m/%Y", "zh-hans": "%Y年%m月%d日"}


def localized_guides():
    return {
        key: {
            **guide,
            **{field: translate(guide[field]) for field in ("summary", "intro", "question", "answer")},
            "sections": [(translate(title), [translate(text) for text in paragraphs]) for title, paragraphs in guide["sections"]],
        }
        for key, guide in GUIDES.items()
    }


@guides_bp.get("/guides")
def index():
    return render_template("guides.html", guides=localized_guides(), support_version=WEBSITE_SUPPORT_VERSION)


@guides_bp.get("/guides/download-<provider>-videos")
def provider_guide(provider):
    if provider not in GUIDES:
        abort(404)
    guides = localized_guides()
    guide = guides[provider]
    releases = load_catalog()
    website = next(row for row in WEBSITES if row[0] == guide["name"])
    updated = guide.get("updated", guide.get("published", GUIDE_DATE))
    updated_date = date.fromisoformat(updated)
    return render_template(
        "video_guide.html", guide=guide, provider=provider,
        guide_date=updated, guide_version=guide.get("version", GUIDE_VERSION),
        related_guides={key: guides[key] for key in RELATED_GUIDES[provider]},
        guide_date_label=updated_date.strftime(GUIDE_DATE_FORMATS[language()]).lstrip("0"),
        supports_profiles=website[2] == "Yes", supports_collections=website[3] == "Yes",
        releases_available=bool(releases["releases"]),
        catalog_unavailable=releases["unavailable"],
        mobile_available={
            platform: any(not artifact["experimental"] for artifact in latest_artifacts(
                releases["releases"], platform, {kind},
            ))
            for platform, kind in (("android", "apk"), ("ios", "ipa"))
        },
    )
