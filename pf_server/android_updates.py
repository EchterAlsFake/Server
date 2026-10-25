"""Verify and atomically expose Android TUF metadata over HTTPS and onion."""
import base64
import hmac
import json
import os
import re
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

from flask import Blueprint, abort, current_app, jsonify, request, send_file
from tuf.api.metadata import Metadata

from .extensions import csrf, limiter
from .website_releases import ReleaseError, catalog, no_symlinks, publication_lock, release_root

android_updates_bp = Blueprint("android_updates", __name__)
ROOT_FILE = Path(__file__).with_name("android_update_root.json")
ABIS = {"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}


def repository_root():
    return release_root() / "android-updates"


def current_metadata():
    path = repository_root() / "current" / "metadata"
    return path if path.is_dir() else None


@android_updates_bp.after_request
def update_headers(response):
    response.headers["X-Robots-Tag"] = "noindex"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.path.startswith(("/ci/", "/repo/android/metadata/")):
        response.headers["Cache-Control"] = "no-store"
    return response


def validate_files(files):
    if not isinstance(files, dict) or set(files) != {"root.json", "targets.json", "snapshot.json", "timestamp.json"}:
        raise ValueError("Expected four TUF metadata files")
    raw = {name: base64.b64decode(data, validate=True) for name, data in files.items()}
    parsed = {name: Metadata.from_bytes(data) for name, data in raw.items()}
    previous = current_metadata()
    trusted = Metadata.from_file(str(previous / "root.json" if previous else ROOT_FILE))
    root = parsed["root.json"]
    if root.signed.version not in {trusted.signed.version, trusted.signed.version + 1}:
        raise ValueError("Invalid update root version")
    trusted.signed.verify_delegate("root", root.signed_bytes, root.signatures)
    root.signed.verify_delegate("root", root.signed_bytes, root.signatures)
    if root.signed.version == trusted.signed.version and root.signed_bytes != trusted.signed_bytes:
        raise ValueError("Update root changed without a version increase")
    for role in ("targets", "snapshot", "timestamp"):
        item = parsed[role + ".json"]
        root.signed.verify_delegate(role, item.signed_bytes, item.signatures)
        if previous:
            old = Metadata.from_file(str(previous / (role + ".json")))
            if item.signed.version < old.signed.version or (item.signed.version == old.signed.version and item.signed_bytes != old.signed_bytes):
                raise ValueError("Update metadata rollback or conflicting version")
    if any(item.signed.is_expired() for item in parsed.values()):
        raise ValueError("Expired update metadata")
    timestamp, snapshot, targets = (parsed[name + ".json"] for name in ("timestamp", "snapshot", "targets"))
    snapshot_info = timestamp.signed.snapshot_meta
    targets_info = snapshot.signed.meta["targets.json"]
    if snapshot_info.version != snapshot.signed.version or targets_info.version != targets.signed.version:
        raise ValueError("TUF metadata versions do not match")
    snapshot_info.verify_length_and_hashes(raw["snapshot.json"])
    targets_info.verify_length_and_hashes(raw["targets.json"])
    if not root.signed.consistent_snapshot or not 1 <= len(targets.signed.targets) <= 4:
        raise ValueError("Expected a consistent-snapshot Android repository")
    return raw, parsed


def publish_metadata(files):
    with publication_lock():
        raw, parsed = validate_files(files)
        repo = no_symlinks(repository_root())
        repo.mkdir(exist_ok=True, mode=0o755)
        repo.chmod(0o755)
        releases = {release["version"]: release for release in catalog()}
        links = []
        for name, target in parsed["targets.json"].signed.targets.items():
            match = re.fullmatch(r"android/(arm64-v8a|armeabi-v7a|x86|x86_64)\.apk", name)
            custom = target.custom
            if not match or not custom or custom.get("abi") != match[1] or custom.get("package") != "to.pornfetch.app":
                raise ValueError("Invalid Android target")
            release = releases.get(custom.get("version"))
            artifact = next((a for a in release["artifacts"] if a["filename"] == custom.get("filename") and a["kind"] == "apk"), None) if release else None
            if not artifact or artifact["size"] != target.length or artifact["sha256"] != target.hashes.get("sha256"):
                raise ValueError("Android target does not match a published APK")
            arches = {"arm64-v8a": "arm64", "armeabi-v7a": "armv7", "x86_64": "x64", "x86": "x86"}
            if artifact["arch"] != arches[match[1]] or custom.get("release_timestamp") != int(datetime.fromisoformat(release["published_at"]).timestamp()):
                raise ValueError("Android target architecture or release date differs from the catalog")
            source = no_symlinks(release_root() / "public" / release["version"] / artifact["filename"])
            with source.open("rb") as binary:
                target.verify_length_and_hashes(binary)
            links.append((source, repo / "targets" / "android" / (target.hashes["sha256"] + "." + match[1] + ".apk")))
        for source, destination in links:
            no_symlinks(destination)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            (repo / "targets").chmod(0o755)
            destination.parent.chmod(0o755)
            if not destination.exists():
                os.link(source, destination)
        snapshot = Path(tempfile.mkdtemp(prefix="snapshot-", dir=repo))
        try:
            metadata = snapshot / "metadata"
            metadata.mkdir(mode=0o755)
            metadata.chmod(0o755)
            previous = current_metadata()
            if previous:
                for path in previous.glob("*.root.json"):
                    shutil.copyfile(path, metadata / path.name)
            for name, data in raw.items():
                (metadata / name).write_bytes(data)
                role = name.removesuffix(".json")
                if role != "timestamp":
                    (metadata / f"{parsed[name].signed.version}.{name}").write_bytes(data)
            for path in metadata.iterdir():
                path.chmod(0o644)
            snapshot.chmod(0o755)
            temporary = repo / ".next"
            temporary.unlink(missing_ok=True)
            temporary.symlink_to(snapshot.name, target_is_directory=True)
            os.replace(temporary, repo / "current")
        except BaseException:
            shutil.rmtree(snapshot)
            raise


@android_updates_bp.post("/ci/android-updates")
@csrf.exempt
@limiter.limit("60 per hour", key_func=lambda: "android-publisher")
def publish():
    expected = current_app.config.get("WEBSITE_RELEASE_TOKEN", "")
    if not expected:
        abort(503)
    if not hmac.compare_digest(request.headers.get("Authorization", "").encode(), ("Bearer " + expected).encode()):
        abort(401)
    request.max_content_length = 2 * 1024**2
    try:
        publish_metadata((request.get_json(silent=True) or {}).get("files"))
    except (ValueError, KeyError, TypeError, ReleaseError):
        return jsonify(error="Invalid Android update metadata"), 400
    except Exception:
        current_app.logger.exception("Android update publication failed")
        return jsonify(error="Android update publication failed verification"), 422
    return jsonify(published=True), 200


@android_updates_bp.get("/repo/android/metadata/<name>")
def metadata_file(name):
    if not re.fullmatch(r"(?:[0-9]+\.)?(?:root|targets|snapshot|timestamp)\.json", name):
        abort(404)
    directory = current_metadata()
    if not directory or not (directory / name).is_file():
        abort(404)
    response = send_file(directory / name, conditional=True)
    response.headers["Cache-Control"] = "no-store"
    return response


@android_updates_bp.get("/repo/android/targets/android/<name>")
def target_file(name):
    if not re.fullmatch(r"[a-f0-9]{64}\.(?:arm64-v8a|armeabi-v7a|x86|x86_64)\.apk", name):
        abort(404)
    path = no_symlinks(repository_root() / "targets" / "android" / name)
    if not path.is_file():
        abort(404)
    return send_file(path, conditional=True, as_attachment=True)
