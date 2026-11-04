"""Optional IPv6-first links; onion visitors never contact the direct origin."""
from flask import current_app

from .onion import is_onion


def direct_origin():
    if is_onion() or not current_app.config["DIRECT_DOWNLOADS_ENABLED"]:
        return ""
    return current_app.config["DIRECT_DOWNLOAD_ORIGIN"]


def download_href(path):
    return direct_origin() + path


def init_direct_downloads(app):
    app.context_processor(lambda: {
        "download_href": download_href,
        "direct_download_origin": direct_origin(),
    })
