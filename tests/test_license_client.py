import json
from pathlib import Path
import tempfile
import unittest

import httpx
from license_client import LicenseClient, LicenseError
from license_fixtures import *

class ClientTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.now = NOW
        self.online = False
        self.revoked = False
        self.limit = False
        self.fingerprint = None
        self.client = self.make_client()

    def make_client(self):
        client = LicenseClient(self.directory.name, public_key=PUBLIC, account_id=ACCOUNT,
                               product_id=PRODUCT, policy_id=POLICY,
                               transport=httpx.MockTransport(self.transport),
                               clock=lambda: self.now, monotonic=lambda: self.now)
        self.addCleanup(client.close)
        return client

    def transport(self, request):
        if not self.online:
            raise httpx.ConnectError("offline")
        path = request.url.path
        if path.endswith("validate-key"):
            return httpx.Response(200, json={"meta": {"valid": bool(self.fingerprint) and not self.revoked,
                                                      "code": "SUSPENDED" if self.revoked else "NO_MACHINES"}})
        if path.endswith("/machines") and request.method == "POST":
            if self.limit:
                return httpx.Response(422, json={"errors": [{"code": "MACHINE_LIMIT_EXCEEDED"}]})
            self.fingerprint = json.loads(request.content)["data"]["attributes"]["fingerprint"]
            return httpx.Response(201, json={"data": {"id": MACHINE}})
        if path.endswith("check-out"):
            return httpx.Response(200, json={"data": {"attributes": {"certificate": permit(self.fingerprint, now=self.now)}}})
        if request.method == "DELETE":
            self.fingerprint = None
            return httpx.Response(204)
        return httpx.Response(200, json={"data": {"id": MACHINE}})

    def import_file(self):
        return self.client.import_license(json.dumps({"schema": 2, "license_key": signed_key()}))

    def test_provisional_deadline_survives_restart_and_reimport(self):
        first = self.import_file()
        self.assertEqual(first.state, "provisional")
        self.now += 604799
        self.client = self.make_client()
        self.assertTrue(self.import_file().allowed)
        self.now += 1
        self.assertFalse(self.import_file().allowed)
        self.assertEqual(self.client.check().state, "expired_grace")

    def test_activation_offline_expiry_and_recovery(self):
        self.online = True
        self.assertEqual(self.import_file().state, "valid")
        self.online = False
        self.now += 86400
        self.assertEqual(self.client.check().state, "offline_grace")
        self.now += 604800 - 86400
        self.assertFalse(self.client.check().allowed)
        self.online = True
        self.assertTrue(self.client.check(force=True).allowed)

    def test_denial_never_becomes_provisional(self):
        self.online = True
        self.limit = True
        self.assertEqual(self.import_file().state, "installation_limit")
        self.online = False
        self.assertFalse(self.client.check(force=True).allowed)
        self.assertFalse(self.import_file().allowed)

    def test_revocation_stays_denied_during_outage(self):
        self.online = True
        self.import_file()
        self.revoked = True
        self.assertEqual(self.client.check(force=True).state, "revoked")
        self.online = False
        self.assertFalse(self.client.check(force=True).allowed)

    def test_tampering_wrong_product_and_excess_ttl(self):
        key = signed_key()
        with self.assertRaises(LicenseError):
            self.client.verify_key(key[:-5] + "AAAAA")
        self.client.product_id = ACCOUNT
        with self.assertRaises(LicenseError):
            self.client.verify_key(key)
        self.client.product_id = PRODUCT
        for ttl in (604801, 0):
            with self.assertRaises(LicenseError):
                self.client.verify_permit(permit("fingerprint", ttl=ttl), license_id=LICENSE,
                                          installation_id="fingerprint", now=NOW)
        with self.assertRaises(LicenseError):
            self.client.verify_permit(permit("other"), license_id=LICENSE,
                                      installation_id="fingerprint", now=NOW)

    def test_clock_rollback_requires_recovery(self):
        self.import_file()
        self.now -= 600
        self.assertEqual(self.client.check().state, "clock_invalid")

    def test_deactivation_needs_server_and_clears_access(self):
        self.online = True
        self.import_file()
        self.online = False
        self.assertEqual(self.client.deactivate().state, "deactivation_pending")
        self.online = True
        self.assertEqual(self.client.deactivate().state, "deactivated")
        self.assertFalse(self.client.check().allowed)

    def test_persistent_uuid_and_private_state(self):
        with self.client._state() as state:
            fingerprint = state["installation_id"]
        other = self.make_client()
        with other._state() as state:
            self.assertEqual(state["installation_id"], fingerprint)
        self.assertEqual((Path(self.directory.name)/"licensing.sqlite3").stat().st_mode & 0o777, 0o600)
