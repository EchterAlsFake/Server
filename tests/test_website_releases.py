"""Synthetic releases verify isolation, integrity, recovery and public discovery."""

import hashlib
import io
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from _support import ServerTestCase, main

from pf_server import website_releases as service


class WebsiteReleaseTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "releases"
        settings = patch.dict(
            main.app.config,
            {
                "WEBSITE_RELEASES_DIR": str(self.root),
                "WEBSITE_RELEASE_TOKEN": "synthetic-website-token",
                "WEBSITE_MAX_ARTIFACT_BYTES": 1024 * 1024,
            },
        )
        settings.start()
        self.addCleanup(settings.stop)
        self.headers = {"Authorization": "Bearer synthetic-website-token"}
        self.payload = b"synthetic application package, not executable"

    def manifest(self, version="3.9.66", channel="beta", kind="gui", arch="x64"):
        return {
            "schema": 1,
            "version": version,
            "channel": channel,
            "published_at": "2026-10-24T12:00:00Z",
            "commit": "a" * 40,
            "notes": "A real release note. <script>alert('unsafe')</script>",
            "artifacts": [
                {
                    "filename": f"PornFetch_linux_{kind.upper()}_{arch}.zip",
                    "platform": "linux",
                    "arch": arch,
                    "kind": kind,
                    "size": len(self.payload),
                    "sha256": hashlib.sha256(self.payload).hexdigest(),
                    "experimental": False,
                    "min_os": "Linux",
                }
            ],
        }

    def stage(self, manifest):
        response = self.client.post(
            "/ci/website-releases", json=manifest, headers=self.headers
        )
        self.assertIn(response.status_code, (200, 201), response.data)
        return response

    def upload(self, manifest, payload=None):
        return self.client.put(
            f"/ci/website-releases/{manifest['version']}/files/{manifest['artifacts'][0]['filename']}",
            data=self.payload if payload is None else payload,
            headers=self.headers,
        )

    def publish(self, manifest):
        return self.client.post(
            f"/ci/website-releases/{manifest['version']}/publish",
            json={},
            headers=self.headers,
        )

    def complete(self, manifest):
        self.stage(manifest)
        self.assertEqual(self.upload(manifest).status_code, 201)
        response = self.publish(manifest)
        self.assertEqual(response.status_code, 200, response.data)
        return response

    def test_publishing_is_authenticated_and_browser_csrf_rules_are_unchanged(self):
        with patch.dict(main.app.config, {"WTF_CSRF_ENABLED": True}):
            self.assertEqual(
                self.client.post(
                    "/ci/website-releases", json=self.manifest()
                ).status_code,
                401,
            )
            self.stage(self.manifest())
            self.assertEqual(
                self.client.post("/checkout/start", json={}).status_code, 400
            )
        with patch.dict(main.app.config, {"WEBSITE_RELEASE_TOKEN": ""}):
            self.assertEqual(
                self.client.post("/ci/website-releases", json={}).status_code, 503
            )
        self.assertFalse((self.root / "public/3.9.66").exists())

    def test_atomic_publication_download_range_headers_and_immutable_versions(self):
        manifest = self.manifest()
        self.stage(manifest)
        name = manifest["artifacts"][0]["filename"]
        url = f"/downloads/{manifest['version']}/{name}"
        self.assertEqual(self.client.get(url).status_code, 404)
        self.assertEqual(self.publish(manifest).status_code, 409)
        self.assertEqual(self.upload(manifest).status_code, 201)
        self.assertEqual(self.client.get(url).status_code, 404)
        self.assertEqual(self.publish(manifest).status_code, 200)
        response = self.client.get(url, headers={"Range": "bytes=0-4"})
        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.data, self.payload[:5])
        self.assertEqual(
            response.headers["Content-Range"], f"bytes 0-4/{len(self.payload)}"
        )
        self.assertIn("attachment", response.headers["Content-Disposition"])
        self.assertIn("max-age=31536000", response.headers["Cache-Control"])
        self.assertEqual(response.headers["X-Robots-Tag"], "noindex")
        head = self.client.head(url)
        self.assertEqual(int(head.headers["Content-Length"]), len(self.payload))
        checksum = self.client.get(url + ".sha256").data.decode()
        self.assertIn(hashlib.sha256(self.payload).hexdigest(), checksum)
        self.assertEqual(
            self.client.get(
                url, headers={"If-None-Match": head.headers["ETag"]}
            ).status_code,
            304,
        )
        self.assertEqual(self.upload(manifest).status_code, 409)
        altered = self.manifest()
        altered["notes"] = "Cannot rewrite a published version"
        self.assertEqual(
            self.client.post(
                "/ci/website-releases", json=altered, headers=self.headers
            ).status_code,
            409,
        )
        self.assertEqual(self.publish(manifest).status_code, 200)
        self.assertEqual(
            len(self.client.get("/download/catalog.json").json["releases"]), 1
        )
        self.assertEqual(
            self.client.get("/downloads/3.9.66/manifest.json").json["version"], "3.9.66"
        )
        self.assertEqual(
            self.client.get("/downloads/3.9.66/not-declared.zip").status_code, 404
        )

    def test_bad_and_truncated_uploads_never_replace_a_verified_file(self):
        manifest = self.manifest()
        self.stage(manifest)
        self.assertEqual(self.upload(manifest).status_code, 201)
        self.assertEqual(self.upload(manifest, b"short").status_code, 400)
        self.assertEqual(
            self.upload(manifest, b"x" * len(self.payload)).status_code, 422
        )
        path = self.root / "staging/3.9.66" / manifest["artifacts"][0]["filename"]
        self.assertEqual(path.read_bytes(), self.payload)
        self.assertEqual(list(path.parent.glob(".upload-*")), [])
        self.assertEqual(self.publish(manifest).status_code, 200)

    def test_traversal_duplicate_variants_and_hidden_installer_flags_are_rejected(self):
        for name in (
            "../payload.zip",
            "nested/payload.zip",
            "payload.html",
            "manifest.json",
            "payload.zip.sha256",
        ):
            manifest = self.manifest()
            manifest["artifacts"][0]["filename"] = name
            self.assertEqual(
                self.client.post(
                    "/ci/website-releases", json=manifest, headers=self.headers
                ).status_code,
                400,
                name,
            )
        for change in ({"kind": "installer"}, {"platform": "ios"}, {"kind": "apk"}):
            manifest = self.manifest()
            manifest["artifacts"][0].update(change)
            self.assertEqual(
                self.client.post(
                    "/ci/website-releases", json=manifest, headers=self.headers
                ).status_code,
                400,
                change,
            )
        manifest = self.manifest()
        duplicate = dict(manifest["artifacts"][0], filename="another.zip")
        manifest["artifacts"].append(duplicate)
        self.assertEqual(
            self.client.post(
                "/ci/website-releases", json=manifest, headers=self.headers
            ).status_code,
            400,
        )

    def test_symlinks_and_post_upload_tampering_cannot_be_published(self):
        manifest = self.manifest()
        self.stage(manifest)
        self.assertEqual(self.upload(manifest).status_code, 201)
        path = self.root / "staging/3.9.66" / manifest["artifacts"][0]["filename"]
        path.write_bytes(b"x" * len(self.payload))
        self.assertEqual(self.publish(manifest).status_code, 409)
        path.unlink()
        outside = self.root / "private.zip"
        outside.write_bytes(self.payload)
        path.symlink_to(outside)
        self.assertEqual(self.publish(manifest).status_code, 400)
        self.assertEqual(self.upload(manifest).status_code, 400)
        self.assertEqual(outside.read_bytes(), self.payload)

    def test_catalog_update_retry_repairs_an_interrupted_publish(self):
        manifest = self.manifest()
        self.stage(manifest)
        self.assertEqual(self.upload(manifest).status_code, 201)
        with (
            patch.object(
                service, "atomic_json", side_effect=OSError("synthetic disk error")
            ),
            self.assertRaises(OSError),
        ):
            self.publish(manifest)
        self.assertTrue((self.root / "public/3.9.66").is_dir())
        self.assertEqual(self.client.get("/download/catalog.json").json["releases"], [])
        self.stage(manifest)
        self.assertEqual(self.publish(manifest).status_code, 200)
        self.assertEqual(
            len(self.client.get("/download/catalog.json").json["releases"]), 1
        )

    def test_concurrent_publications_do_not_lose_releases(self):
        manifests = [self.manifest("3.9.66"), self.manifest("3.9.67")]
        for manifest in manifests:
            self.stage(manifest)
            self.assertEqual(self.upload(manifest).status_code, 201)

        def publish(version):
            with main.app.test_client() as client:
                return client.post(
                    f"/ci/website-releases/{version}/publish",
                    json={},
                    headers=self.headers,
                ).status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(list(pool.map(publish, ["3.9.66", "3.9.67"])), [200, 200])
        self.assertEqual(
            len(self.client.get("/download/catalog.json").json["releases"]), 2
        )

    def test_gui_cli_channel_selection_preserves_original_versions(self):
        for manifest in (
            self.manifest("3.9.60", "stable"),
            self.manifest("3.9.66"),
            self.manifest("3.9.67", kind="cli"),
        ):
            self.complete(manifest)
        with main.app.app_context():
            selected = service.latest_artifacts(
                service.catalog(), "linux", {"gui", "cli"}
            )
            self.assertEqual(
                {item["kind"]: item["version"] for item in selected},
                {"gui": "3.9.60", "cli": "3.9.67"},
            )
            beta = service.latest_artifacts(service.catalog(), "linux", {"gui"}, "beta")
            self.assertEqual(beta[0]["version"], "3.9.66")
        page = self.client.get("/download/linux?channel=beta").data
        self.assertIn(b"3.9.66", page)
        self.assertNotIn(b"3.9.60", page)

    def test_public_pages_work_without_github_and_escape_release_notes(self):
        self.complete(self.manifest())
        with patch("httpx.get", side_effect=AssertionError("No website GitHub calls")):
            for path in (
                "/",
                "/download",
                "/download/ios",
                "/download/linux",
                "/releases",
                "/releases/3.9.66",
                "/help",
                "/about",
            ):
                page = self.client.get(path)
                self.assertEqual(page.status_code, 200, path)
                self.assertNotIn(b'id="age-overlay"', page.data)
            page = self.client.get("/releases/3.9.66").data
            self.assertIn(b"&lt;script&gt;", page)
            self.assertNotIn(b"<script>alert('unsafe')", page)
        self.assertIn(b'id="age-overlay"', self.client.get("/porn_fetch").data)
        self.assertEqual(self.client.get("/download/missing").status_code, 404)

    def test_production_seo_uses_canonical_origin_and_excludes_private_routes(self):
        self.complete(self.manifest())
        with patch.dict(
            main.app.config,
            {"APP_DOMAIN": "https://pornfetch.to", "NOWPAYMENTS_SANDBOX": False},
        ):
            for path in (
                "/",
                "/download",
                "/download/ios",
                "/help",
                "/about",
                "/releases/3.9.66",
            ):
                page = self.client.get(path, base_url="https://pornfetch.to").data
                self.assertIn(b'content="index, follow"', page)
                self.assertIn(f'href="https://pornfetch.to{path}"'.encode(), page)
                self.assertIn(b"application/ld+json", page)
                self.assertNotIn(b"AggregateRating", page)
                self.assertNotIn(b"Organization", page)
            sitemap = self.client.get(
                "/sitemap.xml", base_url="https://pornfetch.to"
            ).data
            self.assertIn(b"/download/ios", sitemap)
            self.assertIn(b"/releases/3.9.66", sitemap)
            self.assertNotIn(b"/buy_card", sitemap)
            self.assertNotIn(b"/downloads/", sitemap)
            self.assertIn(b'content="noindex"', self.client.get("/buy_card").data)
        self.assertIn(b'content="noindex, nofollow"', self.client.get("/download").data)

    def test_upload_limit_is_scoped_and_cannot_hide_existing_releases(self):
        manifest = self.manifest()
        self.complete(manifest)
        with patch.dict(main.app.config, {"WEBSITE_MAX_ARTIFACT_BYTES": 8}):
            oversized = self.manifest("3.9.68")
            self.assertEqual(
                self.client.post(
                    "/ci/website-releases", json=oversized, headers=self.headers
                ).status_code,
                400,
            )
            self.assertEqual(
                len(self.client.get("/download/catalog.json").json["releases"]), 1
            )
        self.assertEqual(main.app.config["MAX_CONTENT_LENGTH"], 200 * 1024)
        self.assertEqual(
            self.client.post(
                "/checkout/start",
                data=b"x" * (201 * 1024),
                content_type="application/json",
            ).status_code,
            413,
        )

    def test_large_upload_override_and_interrupted_stream_are_isolated(self):
        self.payload = b"x" * (256 * 1024)
        manifest = self.manifest()
        self.stage(manifest)
        path = (
            f"/ci/website-releases/3.9.66/files/{manifest['artifacts'][0]['filename']}"
        )
        self.assertEqual(self.client.put(path, data=self.payload).status_code, 401)
        self.assertEqual(self.upload(manifest).status_code, 201)
        response = self.client.open(
            path,
            method="PUT",
            headers=self.headers,
            environ_overrides={
                "CONTENT_LENGTH": str(len(self.payload)),
                "wsgi.input": io.BytesIO(b"interrupted"),
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(list((self.root / "staging/3.9.66").glob(".upload-*")), [])
        self.assertEqual(self.publish(manifest).status_code, 200)

    def test_malformed_metadata_types_return_validation_errors(self):
        for field in (
            "schema",
            "channel",
            "commit",
            "published_at",
            "notes",
            "artifacts",
        ):
            manifest = self.manifest()
            manifest[field] = {}
            self.assertEqual(
                self.client.post(
                    "/ci/website-releases", json=manifest, headers=self.headers
                ).status_code,
                400,
                field,
            )
        for field in (
            "platform",
            "arch",
            "kind",
            "filename",
            "size",
            "sha256",
            "min_os",
        ):
            manifest = self.manifest()
            manifest["artifacts"][0][field] = []
            self.assertEqual(
                self.client.post(
                    "/ci/website-releases", json=manifest, headers=self.headers
                ).status_code,
                400,
                field,
            )
