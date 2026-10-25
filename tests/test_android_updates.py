"""Synthetic signed feeds verify atomic publication and APK binding offline."""
import base64
import hashlib
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import Metadata, MetaFile, Root, Snapshot, TargetFile, Targets, Timestamp

from _support import ServerTestCase, main
from pf_server import android_updates
from pf_server.website_releases import atomic_json


class AndroidUpdateTests(ServerTestCase):
    @staticmethod
    def signed_files(root_bytes, targets, signer):
        now = datetime.now(timezone.utc)
        target = Metadata(Targets(expires=now + timedelta(days=2), targets=targets))
        target.sign(signer)
        target_bytes = target.to_bytes()
        snapshot = Metadata(Snapshot(expires=now + timedelta(days=2), meta={"targets.json": MetaFile.from_data(1, target_bytes, ["sha256"])}))
        snapshot.sign(signer)
        snapshot_bytes = snapshot.to_bytes()
        timestamp = Metadata(Timestamp(expires=now + timedelta(days=1), snapshot_meta=MetaFile.from_data(1, snapshot_bytes, ["sha256"])))
        timestamp.sign(signer)
        return {"root.json": root_bytes, "targets.json": target_bytes,
                "snapshot.json": snapshot_bytes, "timestamp.json": timestamp.to_bytes()}

    def setUp(self):
        super().setUp()
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.root_signer = CryptoSigner.generate_ed25519()
        self.signer = CryptoSigner.generate_ed25519()
        root = Metadata(Root(expires=datetime.now(timezone.utc) + timedelta(days=365)))
        root.signed.add_key(self.root_signer.public_key, "root")
        for role in ("targets", "snapshot", "timestamp"):
            root.signed.add_key(self.signer.public_key, role)
        root.sign(self.root_signer)
        self.root_bytes = root.to_bytes()
        trust = self.directory / "trust.json"
        trust.write_bytes(self.root_bytes)
        settings = patch.dict(main.app.config, {"WEBSITE_RELEASES_DIR": str(self.directory), "WEBSITE_RELEASE_TOKEN": "synthetic-token"})
        settings.start()
        self.addCleanup(settings.stop)
        trust_patch = patch.object(android_updates, "ROOT_FILE", trust)
        trust_patch.start()
        self.addCleanup(trust_patch.stop)
        self.payload = b"synthetic APK, no executable code"
        name = "PornFetch_android_GUI_arm64-v8a.apk"
        public = self.directory / "public/3.9.77"
        public.mkdir(parents=True)
        (public / name).write_bytes(self.payload)
        self.target = TargetFile(len(self.payload), {"sha256": hashlib.sha256(self.payload).hexdigest()}, "android/arm64-v8a.apk")
        self.target.unrecognized_fields["custom"] = {"version": "3.9.77", "abi": "arm64-v8a", "package": "to.pornfetch.app", "filename": name,
                                                    "release_timestamp": int(datetime(2026, 10, 25, tzinfo=timezone.utc).timestamp())}
        atomic_json(self.directory / "catalog.json", [{"schema": 1, "version": "3.9.77", "channel": "beta", "commit": "a" * 40,
                    "published_at": "2026-10-25T00:00:00+00:00", "notes": "notes", "artifacts": [{"filename": name,
                    "platform": "android", "arch": "arm64", "kind": "apk", "experimental": False,
                    "min_os": "Android 9", "size": len(self.payload), "sha256": self.target.hashes["sha256"]}]}])

    def publish(self, files, token="synthetic-token"):
        return self.client.post("/ci/android-updates", headers={"Authorization": "Bearer " + token},
                                json={"files": {name: base64.b64encode(data).decode() for name, data in files.items()}})

    def test_atomic_feed_range_and_failed_retry(self):
        files = self.signed_files(self.root_bytes, {self.target.path: self.target}, self.signer)
        self.assertEqual(self.publish(files, token="wrong").status_code, 401)
        response = self.publish(files)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self.client.get("/repo/android/metadata/timestamp.json").data, files["timestamp.json"])
        name = self.target.hashes["sha256"] + ".arm64-v8a.apk"
        response = self.client.get("/repo/android/targets/android/" + name, headers={"Range": "bytes=0-2"})
        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.data, self.payload[:3])
        tampered = dict(files, **{"targets.json": files["targets.json"].replace(b'3.9.77', b'3.9.78')})
        self.assertIn(self.publish(tampered).status_code, (400, 422))
        self.assertEqual(self.client.get("/repo/android/metadata/timestamp.json").data, files["timestamp.json"])

    def test_expired_timestamp_and_changed_apk_are_rejected(self):
        files = self.signed_files(self.root_bytes, {self.target.path: self.target}, self.signer)
        expired = Metadata.from_bytes(files["timestamp.json"])
        expired.signed.expires = datetime.now(timezone.utc) - timedelta(seconds=1)
        expired.sign(self.signer)
        self.assertIn(self.publish(dict(files, **{"timestamp.json": expired.to_bytes()})).status_code, (400, 422))
        next((self.directory / "public/3.9.77").glob("*.apk")).write_bytes(b"tampered")
        self.assertIn(self.publish(files).status_code, (400, 422))
        self.assertEqual(self.client.get("/repo/android/metadata/timestamp.json").status_code, 404)

    def test_private_service_umask_keeps_public_metadata_traversable(self):
        files = self.signed_files(self.root_bytes, {self.target.path: self.target}, self.signer)
        previous = os.umask(0o077)
        try:
            self.assertEqual(self.publish(files).status_code, 200)
        finally:
            os.umask(previous)
        directory = self.directory / "android-updates/current/metadata"
        self.assertEqual(directory.stat().st_mode & 0o005, 0o005)
