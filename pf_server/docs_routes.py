"""Routes for serving the generated static documentation site."""

import os
from pathlib import Path

from flask import Blueprint, redirect, request, send_file
from werkzeug.utils import safe_join

from .http import normalized_hostname

docs_bp = Blueprint("docs", __name__)
DOCS_DIST = Path(__file__).resolve().parents[1] / "docs" / "dist"


def serve_docs_file(path: str):
    docs_dist = os.fspath(DOCS_DIST)
    if not isinstance(path, str) or "\\" in path or "\x00" in path:
        return None, "404"

    if not path:
        target_file = safe_join(docs_dist, "index.html")
    elif path.startswith("assets/"):
        target_file = safe_join(docs_dist, path)
    else:
        parts = path.split("/")
        api_dir = safe_join(docs_dist, parts[0])
        if not api_dir or not os.path.isdir(api_dir):
            return None, "404"
        if len(parts) == 1:
            return None, "redirect"
        if len(parts) == 2 and parts[1] in ("", "index.html"):
            target_file = safe_join(api_dir, "index.html")
        else:
            target_file = safe_join(docs_dist, path)

    if target_file and os.path.isfile(target_file):
        return target_file, "file"
    return None, "404"


def handle_docs_subdomain():
    """Serve the documentation root when a request arrives on a docs host."""
    if not normalized_hostname(request.host).startswith("docs."):
        return None

    path = request.path.lstrip("/")
    target_file, status = serve_docs_file(path)
    if status == "redirect":
        return redirect(f"/{path}/", code=301)
    if status == "404":
        return "Documentation File Not Found", 404
    return send_file(target_file)


@docs_bp.route("/docs/", defaults={"path": ""}, methods=["GET"])
@docs_bp.route("/docs/<path:path>", methods=["GET"])
def serve_docs_subpath(path):
    target_file, status = serve_docs_file(path)
    if status == "redirect":
        return redirect(f"/docs/{path}/", code=301)
    if status == "404":
        return "Documentation File Not Found", 404
    return send_file(target_file)

