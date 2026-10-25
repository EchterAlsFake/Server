"""Independent website releases: staged CI uploads and an immutable local catalog.

App updater feeds and the existing API publisher are deliberately separate.
Only authenticated CI writes here; public downloads never contact GitHub.
"""

import fcntl
import hashlib
import hmac
import json
import os
import re
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from flask import Blueprint, abort, current_app, jsonify, request, send_file
from werkzeug.exceptions import RequestEntityTooLarge

from .extensions import csrf, limiter

releases_bp = Blueprint("website_releases", __name__)
VERSION = re.compile(
    r"[0-9]{1,6}(?:\.[0-9]{1,6}){1,3}(?:-(?:alpha|beta|rc)(?:[.-]?[0-9]{1,6})?)?"
)
FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,179}")
PLATFORMS = {"windows", "linux", "macos", "android", "ios", "any"}
ARCHITECTURES = {"x64", "arm64", "x86", "armv7", "x32", "riscv64", "universal", "any"}
KINDS = {"gui", "cli", "installer", "apk", "source", "notices"}
EXTENSIONS = (
    ".zip",
    ".tar.gz",
    ".tar.xz",
    ".exe",
    ".bin",
    ".dmg",
    ".run",
    ".apk",
    ".whl",
    ".txt",
)


class ReleaseError(ValueError):
    pass


def release_root():
    return Path(current_app.config["WEBSITE_RELEASES_DIR"])


def safe_version(value):
    if not isinstance(value, str) or VERSION.fullmatch(value) is None:
        raise ReleaseError("Invalid release version.")
    return value


def safe_filename(value):
    if (
        not isinstance(value, str)
        or FILENAME.fullmatch(value) is None
        or ".." in value
        or value in {"manifest.json", "SHA256SUMS"}
        or not value.endswith(EXTENSIONS)
    ):
        raise ReleaseError("Invalid artifact filename.")
    return value


def plain_text(value, maximum):
    if not isinstance(value, str) or len(value) > maximum or "\x00" in value:
        raise ReleaseError("Invalid release text.")
    return value


def validate_manifest(value, *, uploading=False):
    if (
        not isinstance(value, dict)
        or type(value.get("schema")) is not int
        or value["schema"] != 1
    ):
        raise ReleaseError("Expected a schema-1 release manifest.")
    version = safe_version(value.get("version"))
    if not isinstance(value.get("channel"), str) or value["channel"] not in {
        "stable",
        "beta",
    }:
        raise ReleaseError("Release channel must be stable or beta.")
    if "-" in version and value["channel"] == "stable":
        raise ReleaseError("Prerelease versions must use the beta channel.")
    commit = value.get("commit")
    if not isinstance(commit, str) or re.fullmatch(r"[a-f0-9]{7,64}", commit) is None:
        raise ReleaseError("Invalid build commit.")
    try:
        published = datetime.fromisoformat(value.get("published_at", ""))
        if published.tzinfo is None:
            raise ValueError
    except ValueError, TypeError, AttributeError:
        raise ReleaseError("Publication date must include a timezone.") from None
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 150:
        raise ReleaseError("A release needs 1–150 artifacts.")
    records, names, variants = [], set(), set()
    for item in artifacts:
        if not isinstance(item, dict):
            raise ReleaseError("Invalid artifact record.")
        name = safe_filename(item.get("filename"))
        if name in names:
            raise ReleaseError("Duplicate artifact filename.")
        names.add(name)
        platform, arch, kind = (item.get(key) for key in ("platform", "arch", "kind"))
        if (
            not all(isinstance(field, str) for field in (platform, arch, kind))
            or platform not in PLATFORMS
            or arch not in ARCHITECTURES
            or kind not in KINDS
        ):
            raise ReleaseError("Unknown platform, architecture or package type.")
        if kind == "apk" and (platform != "android" or not name.endswith(".apk")):
            raise ReleaseError("APK artifacts must identify Android and use .apk.")
        if platform == "ios" and kind not in {"source", "notices"}:
            raise ReleaseError(
                "iOS uses the source-based CLI setup, not a native binary."
            )
        if platform == "android" and kind not in {"apk", "source", "notices"}:
            raise ReleaseError("Android binaries must be APKs; CLI setup uses source.")
        if kind in {"gui", "cli", "installer", "apk"}:
            variant = (platform, arch, kind)
            if variant in variants:
                raise ReleaseError("Duplicate platform/architecture/package variant.")
            variants.add(variant)
        size, digest = item.get("size"), item.get("sha256")
        if (
            type(size) is not int
            or size <= 0
            or (uploading and size > current_app.config["WEBSITE_MAX_ARTIFACT_BYTES"])
        ):
            raise ReleaseError("Artifact size is outside the configured limit.")
        if not isinstance(digest, str) or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
            raise ReleaseError("Invalid SHA-256 digest.")
        experimental = item.get("experimental", False)
        if type(experimental) is not bool or (kind == "installer" and not experimental):
            raise ReleaseError("Qt installers must be marked experimental.")
        records.append(
            {
                "filename": name,
                "platform": platform,
                "arch": arch,
                "kind": kind,
                "size": size,
                "sha256": digest,
                "experimental": experimental,
                "min_os": plain_text(item.get("min_os", ""), 160),
            }
        )
    return {
        "schema": 1,
        "version": version,
        "channel": value["channel"],
        "commit": commit,
        "published_at": published.astimezone(UTC).isoformat(),
        "notes": plain_text(value.get("notes", ""), 60000),
        "artifacts": sorted(records, key=lambda item: item["filename"]),
    }


def no_symlinks(path):
    """Reject symlinks in every existing path component, including the root."""
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ReleaseError("Release storage cannot contain symbolic links.")
    return path


def atomic_json(path, value, mode=0o600):
    descriptor, temporary = tempfile.mkstemp(prefix=".manifest-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, ensure_ascii=False, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), mode)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


@contextmanager
def publication_lock():
    root = no_symlinks(release_root())
    created_root = not root.exists()
    root.mkdir(parents=True, exist_ok=True, mode=0o751)
    if created_root:
        root.chmod(0o751)
    for name in ("staging", "public"):
        folder = no_symlinks(root / name)
        created_folder = not folder.exists()
        folder.mkdir(exist_ok=True, mode=0o700 if name == "staging" else 0o755)
        if created_folder and name == "public":
            # The service's 0077 umask must not make published files unreadable
            # to Caddy. Staging and the private catalog keep their private modes.
            folder.chmod(0o755)
    lock_path = no_symlinks(root / ".publish.lock")
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield root


def read_json(path):
    no_symlinks(path)
    return json.loads(path.read_text(encoding="utf-8"))


def catalog():
    path = no_symlinks(release_root() / "catalog.json")
    try:
        values = read_json(path)
    except FileNotFoundError:
        return []
    if not isinstance(values, list):
        raise ReleaseError("Invalid release catalog.")
    return sorted(
        (validate_manifest(value) for value in values), key=version_key, reverse=True
    )


def version_key(release):
    main, _, preview = release["version"].partition("-")
    numbers = tuple(int(part) for part in main.split("."))
    numbers += (0,) * (4 - len(numbers))
    rank = (
        3
        if not preview
        else next(
            i
            for i, prefix in enumerate(("alpha", "beta", "rc"))
            if preview.startswith(prefix)
        )
    )
    preview_number = re.search(r"[0-9]+", preview)
    return numbers, rank, int(preview_number[0]) if preview_number else 0


def latest_artifacts(releases, platform=None, kinds=None, channel=None):
    """Keep older variants when a newer publication is GUI-only or CLI-only."""
    selected = {}
    for release in sorted(releases, key=version_key, reverse=True):
        for artifact in release["artifacts"]:
            if platform and artifact["platform"] != platform:
                continue
            if kinds and artifact["kind"] not in kinds:
                continue
            key = (artifact["platform"], artifact["arch"], artifact["kind"])
            if channel and release["channel"] != channel:
                continue
            previous = selected.get(key)
            if previous and (
                previous["channel"] == "stable" or release["channel"] != "stable"
            ):
                continue
            selected[key] = dict(
                artifact,
                version=release["version"],
                channel=release["channel"],
                url=f"/downloads/{release['version']}/{artifact['filename']}",
            )
    return list(selected.values())


@releases_bp.before_request
def authenticate_publisher():
    if not request.path.startswith("/ci/website-releases"):
        return
    expected = current_app.config.get("WEBSITE_RELEASE_TOKEN", "")
    supplied = request.headers.get("Authorization", "")
    if not expected:
        abort(503, description="Website publishing is not configured.")
    if not hmac.compare_digest(supplied.encode(), ("Bearer " + expected).encode()):
        abort(401, description="Publisher authentication required.")
    if request.endpoint == "website_releases.upload":
        request.max_content_length = current_app.config["WEBSITE_MAX_ARTIFACT_BYTES"]


@releases_bp.errorhandler(ReleaseError)
def invalid_release(error):
    return jsonify(error=str(error)), 400


@releases_bp.errorhandler(RequestEntityTooLarge)
def upload_too_large(_error):
    return jsonify(error="Upload exceeds the configured artifact size limit."), 413


@releases_bp.after_request
def release_headers(response):
    response.headers["X-Robots-Tag"] = "noindex"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.path.startswith("/ci/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@releases_bp.post("/ci/website-releases")
@csrf.exempt
@limiter.limit("600 per hour", key_func=lambda: "website-publisher")
def stage():
    manifest = validate_manifest(request.get_json(silent=True), uploading=True)
    with publication_lock() as root:
        public = root / "public" / manifest["version"]
        staging = root / "staging" / manifest["version"]
        existing = public if public.exists() else staging
        if existing.exists():
            if read_json(existing / "manifest.json") != manifest:
                return jsonify(
                    error="This version already has a different manifest."
                ), 409
            return jsonify(version=manifest["version"], published=public.exists()), 200
        staging.mkdir(mode=0o700)
        atomic_json(staging / "manifest.json", manifest)
    return jsonify(version=manifest["version"], published=False), 201


@releases_bp.put("/ci/website-releases/<version>/files/<filename>")
@csrf.exempt
@limiter.limit("600 per hour", key_func=lambda: "website-publisher")
def upload(version, filename):
    safe_version(version)
    safe_filename(filename)
    with publication_lock() as root:
        staging = no_symlinks(root / "staging" / version)
        public = no_symlinks(root / "public" / version)
        directory = public if public.exists() else staging
        if not directory.exists():
            abort(404)
        manifest = read_json(directory / "manifest.json")
        item = next(
            (item for item in manifest["artifacts"] if item["filename"] == filename),
            None,
        )
        if not item:
            abort(404)
        if public.exists():
            return jsonify(error="Published files are immutable."), 409
        if (
            request.content_length is not None
            and request.content_length != item["size"]
        ):
            return jsonify(error="Upload length differs from the manifest."), 400
        destination = no_symlinks(staging / filename)
        descriptor, temporary = tempfile.mkstemp(prefix=".upload-", dir=staging)
        digest, size = hashlib.sha256(), 0
        try:
            with os.fdopen(descriptor, "wb") as output:
                while chunk := request.stream.read(
                    min(1024 * 1024, item["size"] + 1 - size)
                ):
                    size += len(chunk)
                    if size > item["size"]:
                        return jsonify(error="Upload exceeds its declared size."), 400
                    digest.update(chunk)
                    output.write(chunk)
                if size != item["size"] or digest.hexdigest() != item["sha256"]:
                    return jsonify(error="Upload size or SHA-256 mismatch."), 422
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, destination)
        finally:
            Path(temporary).unlink(missing_ok=True)
    return jsonify(uploaded=filename), 201


@releases_bp.post("/ci/website-releases/<version>/publish")
@csrf.exempt
@limiter.limit("600 per hour", key_func=lambda: "website-publisher")
def publish(version):
    safe_version(version)
    with publication_lock() as root:
        staging = no_symlinks(root / "staging" / version)
        public = no_symlinks(root / "public" / version)
        directory = public if public.exists() else staging
        if not directory.exists():
            abort(404)
        manifest = validate_manifest(read_json(directory / "manifest.json"))
        if not public.exists():
            checksums = []
            for item in manifest["artifacts"]:
                path = no_symlinks(staging / item["filename"])
                if not path.is_file() or path.stat().st_size != item["size"]:
                    return jsonify(error="Release is incomplete."), 409
                with path.open("rb") as source:
                    digest = hashlib.file_digest(source, "sha256").hexdigest()
                if digest != item["sha256"]:
                    return jsonify(error="Artifact changed after upload."), 409
                checksum = f"{digest}  {item['filename']}\n"
                sidecar = no_symlinks(staging / (item["filename"] + ".sha256"))
                sidecar.write_text(checksum, encoding="ascii")
                checksums.append(checksum)
            (staging / "SHA256SUMS").write_text("".join(checksums), encoding="ascii")
            for path in staging.iterdir():
                no_symlinks(path)
                path.chmod(0o644)
            staging.chmod(0o755)
            os.rename(staging, public)
        # A retry repairs an interrupted catalog update after the directory rename.
        releases = [entry for entry in catalog() if entry["version"] != version]
        releases.append(manifest)
        atomic_json(
            root / "catalog.json", sorted(releases, key=version_key, reverse=True)
        )
    return jsonify(version=version, published=True), 200


@releases_bp.get("/download/catalog.json")
def public_catalog():
    releases = catalog()
    if version := request.args.get("version"):
        safe_version(version)
        releases = [release for release in releases if release["version"] == version]
    response = jsonify(releases=releases)
    response.headers["Cache-Control"] = "public, max-age=60"
    return response


@releases_bp.get("/downloads/<version>/<filename>")
def download_file(version, filename):
    """Development/test fallback. Production Caddy serves the public tree directly."""
    try:
        safe_version(version)
        directory = no_symlinks(release_root() / "public" / version)
        manifest = read_json(directory / "manifest.json")
        allowed = {item["filename"] for item in manifest["artifacts"]}
        allowed |= {name + ".sha256" for name in tuple(allowed)}
        # The published snapshot is public metadata, just like catalog.json.
        allowed |= {"SHA256SUMS", "manifest.json"}
        if filename not in allowed:
            abort(404)
        path = no_symlinks(directory / filename)
        if not path.is_file():
            abort(404)
    except ReleaseError, FileNotFoundError:
        abort(404)
    return send_file(
        path,
        as_attachment=True,
        download_name=filename,
        conditional=True,
        max_age=31536000,
    )
