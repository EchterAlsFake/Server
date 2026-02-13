from __future__ import annotations

import mimetypes
import os
import re
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import httpx
from flask import Flask, abort, jsonify, render_template, send_file, request, make_response

app = Flask(__name__)

# Root directory holding all artifacts in:
#   <RELEASE_ROOT>/<os>/<arch>/<version>/<filename>
RELEASE_ROOT = Path("/srv/porn_fetch/releases").resolve()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO = "EchterAlsFake/Porn_Fetch"
GITHUB_LATEST_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"

VERSION_RE = re.compile(r"^\d+(?:\.\d+)*$")  # 1.0 / 1.9 / 2.0 / 10.12.3 etc.

update_cache = {
    "last_checked": 0.0,
    "data": None,
}

# --- Artifacts mapping (independent of version) ---

@dataclass(frozen=True)
class Artifact:
    slug: str
    label: str
    os: str          # windows | linux | macos | android | other
    arch: str        # x64 | x86 | arm64 | x86_64 | aarch64 | any
    kind: str        # gui | cli | torrent | zip
    filename: str    # file name inside <os>/<arch>/<version>/
    note: str = ""
    sha256: str = ""


ARTIFACTS: Dict[str, Artifact] = {
    "linux-x64-gui": Artifact("linux-x64-gui", "Linux x64 (GUI)", "linux", "x64", "gui", "Porn_Fetch_Linux_x64_GUI.AppImage"),
    "windows-x64-gui": Artifact("windows-x64-gui", "Windows x64 (GUI)", "windows", "x64", "gui", "Porn_Fetch_Windows_x64_GUI.exe"),
    "windows-arm-gui": Artifact("windows-arm-gui", "Windows ARM (GUI)", "windows", "arm64", "gui", "Porn_Fetch_Windows_ARM64_GUI.exe"),
    "macos-x86_64-gui": Artifact("macos-x86_64-gui", "macOS x86_64 (GUI)", "macos", "x86_64", "gui", "Porn_Fetch_macOS_x86_64_GUI.dmg"),

    "windows-x86-cli": Artifact("windows-x86-cli", "Windows x32 (CLI)", "windows", "x86", "cli", "Porn_Fetch_Windows_x86_CLI.zip"),
    "windows-x64-cli": Artifact("windows-x64-cli", "Windows x64 (CLI)", "windows", "x64", "cli", "Porn_Fetch_Windows_x64_CLI.zip"),
    "linux-x64-cli": Artifact("linux-x64-cli", "Linux x64 (CLI)", "linux", "x64", "cli", "Porn_Fetch_Linux_x64_CLI.tar.gz"),
    "linux-x86-cli": Artifact("linux-x86-cli", "Linux x32 (CLI)", "linux", "x86", "cli", "Porn_Fetch_Linux_x86_CLI.tar.gz"),
    "macos-x86_64-cli": Artifact("macos-x86_64-cli", "macOS x86_64 (CLI)", "macos", "x86_64", "cli", "Porn_Fetch_macOS_x86_64_CLI.tar.gz"),

    "android-aarch64": Artifact("android-aarch64", "Android (aarch64)", "android", "aarch64", "gui", "Porn_Fetch_Android_aarch64.apk"),
    "android-x86_64": Artifact("android-x86_64", "Android (x86_64)", "android", "x86_64", "gui", "Porn_Fetch_Android_x86_64.apk"),

    # Store these under: other/any/<version>/
    "torrent": Artifact("torrent", "Torrent File", "other", "any", "torrent", "Porn_Fetch.torrent"),
    "full-zip": Artifact("full-zip", "Full Zip", "other", "any", "zip", "Porn_Fetch_FULL.zip"),
}


# --- GitHub latest release (cached) ---

def get_latest_release_version() -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (version_tag, html_url). Cached for 5 minutes.
    """
    now = time.monotonic()
    if update_cache["last_checked"] == 0 or (now - update_cache["last_checked"]) > 5 * 60:
        update_cache["last_checked"] = now
        try:
            headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            if GITHUB_TOKEN:
                headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

            r = httpx.get(GITHUB_LATEST_URL, headers=headers, timeout=10.0)
            r.raise_for_status()
            update_cache["data"] = r.json()
        except Exception:
            # Keep whatever was in cache (if any) and fall back below
            pass

    data = update_cache.get("data") or {}
    tag = data.get("tag_name")
    url = data.get("html_url")

    if isinstance(tag, str):
        tag = tag.strip()
        # Allow tags like "v1.9" by stripping leading "v"
        if tag.lower().startswith("v"):
            tag = tag[1:]
        if not VERSION_RE.match(tag):
            tag = None

    return tag, url


# --- Version discovery from local filesystem ---

def parse_version(v: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def list_local_versions() -> List[str]:
    """
    Finds versions that exist on disk by scanning:
      RELEASE_ROOT/<os>/<arch>/<version>/
    """
    versions: Set[str] = set()
    if not RELEASE_ROOT.exists():
        return []

    # os level
    for os_dir in RELEASE_ROOT.iterdir():
        if not os_dir.is_dir():
            continue
        for arch_dir in os_dir.iterdir():
            if not arch_dir.is_dir():
                continue
            for ver_dir in arch_dir.iterdir():
                if ver_dir.is_dir() and VERSION_RE.match(ver_dir.name):
                    versions.add(ver_dir.name)

    return sorted(versions, key=parse_version, reverse=True)


def normalize_version_param(v: str) -> str:
    v = (v or "").strip()
    if v.lower() == "latest":
        return "latest"
    if v.lower().startswith("v"):
        v = v[1:]
    if not VERSION_RE.match(v):
        abort(400, description="Invalid version format")
    return v


def artifact_path(version: str, a: Artifact) -> Path:
    """
    Builds: RELEASE_ROOT/<os>/<arch>/<version>/<filename>
    with traversal safety.
    """
    base = RELEASE_ROOT
    p = (base / a.os / a.arch / version / a.filename).resolve()

    # Ensure inside RELEASE_ROOT
    if base not in p.parents:
        raise RuntimeError("Invalid artifact path resolution")
    return p


