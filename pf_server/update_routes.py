"""Release metadata and application update feeds."""

import os
import re
import threading
import time
from datetime import datetime, timezone
from email.utils import format_datetime
from xml.sax.saxutils import escape

import httpx
import markdown
from flask import Blueprint, Response, current_app, jsonify

updates_bp = Blueprint("updates", __name__)

update_cache = {"last_checked": 0.0, "data": None}
update_cache_lock = threading.Lock()


def get_update_information() -> dict:
    """Return normalized release metadata, using a five-minute GitHub cache."""
    now = time.monotonic()
    with update_cache_lock:
        data = update_cache.get("data")
        cache_age = now - float(update_cache.get("last_checked", 0))
        if data is None or cache_age > 5 * 60:
            headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            github_token = current_app.config.get("GITHUB_TOKEN")
            if github_token:
                headers["Authorization"] = f"Bearer {github_token}"

            try:
                response = httpx.get(
                    "https://api.github.com/repos/EchterAlsFake/Porn_Fetch/releases/latest",
                    headers=headers,
                    timeout=10.0,
                )
                response.raise_for_status()
                fetched_data = response.json()
                if not isinstance(fetched_data, dict):
                    raise TypeError("GitHub release response was not an object")
            except (httpx.HTTPError, TypeError, ValueError):
                current_app.logger.warning(
                    "Could not refresh Porn Fetch release metadata", exc_info=True
                )
                data = data or {}
            else:
                data = fetched_data
                update_cache["data"] = data
                update_cache["last_checked"] = now

    assets = data.get("assets", [])
    if not isinstance(assets, list):
        assets = []

    def get_asset(name: str) -> dict | None:
        asset = next(
            (
                candidate
                for candidate in assets
                if isinstance(candidate, dict) and candidate.get("name") == name
            ),
            None,
        )
        if data and asset is None:
            current_app.logger.warning("Missing asset on GitHub release: %s", name)
        return asset

    return {
        "version": data.get("tag_name", "unavailable"),
        "linux_x64": get_asset("PornFetch_Linux_GUI_x64.bin"),
        "linux_arm64": get_asset("PornFetch_Linux_GUI_arm64.bin"),
        "windows_x64": get_asset("PornFetch_Windows_GUI_x64.exe"),
        "windows_arm64": get_asset("PornFetch_Windows_GUI_arm64.exe"),
        "macos_universal": get_asset("PornFetch_macOS_GUI_Universal.dmg"),
        "url": data.get("html_url"),
        "published_at": data.get("published_at"),
    }


def _project_file(*parts: str) -> str:
    return os.path.join(current_app.config["PROJECT_ROOT"], *parts)


def _changelog_html() -> str:
    with open(_project_file("media_archiver_changelog.md"), encoding="utf-8") as file:
        return markdown.markdown(file.read().strip())


def load_signature_for_version(tag: str) -> str:
    """Load a Sparkle signature without allowing tag-based path traversal."""
    if not isinstance(tag, str) or re.fullmatch(r"[A-Za-z0-9._-]+", tag) is None:
        raise ValueError("Invalid release tag")
    with open(_project_file("signatures", f"{tag}.txt"), encoding="utf-8") as file:
        return file.read().strip()


def _published_datetime(value) -> datetime:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            current_app.logger.warning(
                "GitHub release has an invalid publication timestamp", exc_info=True
            )
    return datetime.now(timezone.utc)


@updates_bp.route("/update", methods=["GET"])
def update():
    release = get_update_information()

    def download_url(asset):
        return asset.get("browser_download_url") if isinstance(asset, dict) else None

    return (
        jsonify(
            {
                "version": str(release.get("version")),
                "url": release.get("url"),
                "anonymous_download": f"{current_app.config['APP_DOMAIN']}/download",
                "download_linux_x64": download_url(release.get("linux_x64")),
                "download_linux_arm64": download_url(release.get("linux_arm64")),
                "download_windows_x64": download_url(release.get("windows_x64")),
                "download_windows_arm64": download_url(release.get("windows_arm64")),
                "download_macos_universal": download_url(release.get("macos_universal")),
                "changelog": _changelog_html(),
                "important_info": "Nothing here ;)",
            }
        ),
        200,
    )


@updates_bp.route("/appcast.xml", methods=["GET"])
def appcast():
    release = get_update_information()
    tag = release.get("version")
    mac_asset = release.get("macos_universal")
    if not tag or tag == "unavailable" or not isinstance(mac_asset, dict):
        return jsonify({"error": "Release metadata is temporarily unavailable"}), 503

    dmg_url = mac_asset.get("browser_download_url")
    if not dmg_url:
        return jsonify({"error": "macOS release asset is unavailable"}), 503
    dmg_size = mac_asset.get("size", 0)
    if not isinstance(dmg_size, int) or isinstance(dmg_size, bool) or dmg_size < 0:
        dmg_size = 0

    try:
        signature = load_signature_for_version(tag)
    except (OSError, ValueError):
        current_app.logger.warning(
            "Sparkle signature is unavailable (release=%s)", tag, exc_info=True
        )
        return jsonify({"error": "Release signature is unavailable"}), 503

    tag_xml = escape(tag)
    dmg_url_xml = escape(str(dmg_url), {'"': "&quot;"})
    signature_xml = escape(signature, {'"': "&quot;"})
    changelog_cdata = _changelog_html().replace("]]>", "]]]]><![CDATA[>")
    published_at = format_datetime(_published_datetime(release.get("published_at")))

    xml = f"""<?xml version="1.0" encoding="utf-8"?>
    <rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
      <channel>
        <title>Porn Fetch Updates</title>

        <item>
          <title>Version {tag_xml}</title>
          <pubDate>{published_at}</pubDate>
          <description><![CDATA[{changelog_cdata}]]></description>

          <enclosure
            url="{dmg_url_xml}"
            length="{dmg_size}"
            type="application/x-apple-diskimage"
            sparkle:shortVersionString="{tag_xml}"
            sparkle:version="{tag_xml}"
            sparkle:edSignature="{signature_xml}"
          />
        </item>

      </channel>
    </rss>
    """
    return Response(xml, mimetype="application/rss+xml")
