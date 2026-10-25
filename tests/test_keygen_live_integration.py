"""Automated integration tests against the live Keygen CE licensing instance.

Tests license issuance, cryptographic Ed25519 signature verification,
machine limit enforcement (10 active machines limit), 11th machine rejection,
slot reclamation upon deactivation, machine permit checkout, suspension lifecycle,
and end-to-end LicenseClient integration.
"""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import httpx

from license_client import LicenseClient, LicenseError


def _load_credentials() -> dict[str, str] | None:
    """Finds product credentials from environment, local repo, or container storage."""
    token = os.environ.get("KEYGEN_PRODUCT_TOKEN")
    root = Path(__file__).resolve().parents[1]
    candidate_paths = [
        root / "deploy/keygen/credentials/product.json",
        root / "license_client/production.json",
        Path("/srv/keygen/credentials/product.json"),
        Path("/var/lib/pornfetch/.local/share/containers/storage/volumes/keygen-credentials-data/_data/product.json"),
    ]

    creds: dict[str, str] = {}
    for p in candidate_paths:
        if p.is_file():
            try:
                data = json.loads(p.read_text())
                for key in ("account_id", "product_id", "policy_id", "public_key", "product_token"):
                    if key in data and key not in creds:
                        creds[key] = data[key]
            except (OSError, json.JSONDecodeError):
                continue

    if token:
        creds["product_token"] = token

    required = ("account_id", "product_id", "policy_id", "public_key", "product_token")
    if all(k in creds for k in required):
        return creds
    return None


class LocalKeygenTransport(httpx.BaseTransport):
    """Rewrites outgoing requests to target the local Keygen API port with proper host header."""

    def __init__(self, target_port: int, host_header: str = "licenses.pornfetch.to"):
        self._transport = httpx.HTTPTransport()
        self.target_port = target_port
        self.host_header = host_header

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        headers = [(k, v) for k, v in request.headers.raw if k.lower() != b"host"]
        headers.append((b"host", self.host_header.encode("ascii")))
        headers.append((b"x-forwarded-proto", b"https"))
        url = request.url.copy_with(scheme="http", host="127.0.0.1", port=self.target_port)
        rewritten = httpx.Request(
            method=request.method,
            url=url,
            headers=headers,
            content=request.content,
        )
        return self._transport.handle_request(rewritten)

    def close(self):
        self._transport.close()


class KeygenLiveIntegrationTests(unittest.TestCase):
    """Full live test suite for Keygen CE licensing instance."""

    credentials: dict[str, str]
    base_url: str
    target_port: int
    admin_client: httpx.Client
    public_key: Ed25519PublicKey
    created_licenses: set[str]

    @classmethod
    def setUpClass(cls):
        creds = _load_credentials()
        if not creds:
            raise unittest.SkipTest("Keygen credentials (product.json / product_token) not available.")

        cls.credentials = creds
        cls.target_port = int(os.environ.get("KEYGEN_PORT", "18004"))
        cls.base_url = f"http://127.0.0.1:{cls.target_port}/v1/"
        cls.host_header = os.environ.get("KEYGEN_HOST", "licenses.pornfetch.to")

        # Check API health
        try:
            with httpx.Client(timeout=3.0) as check:
                health = check.get(
                    f"http://127.0.0.1:{cls.target_port}/v1/health",
                    headers={"Host": cls.host_header},
                )
                if health.status_code != 204:
                    raise unittest.SkipTest(
                        f"Keygen API health check returned unexpected status {health.status_code}"
                    )
        except httpx.HTTPError:
            raise unittest.SkipTest(
                f"Keygen API not reachable at 127.0.0.1:{cls.target_port}. Is container keygen-api running?"
            )

        cls.public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(creds["public_key"]))
        cls.admin_client = httpx.Client(
            base_url=cls.base_url,
            headers={
                "Host": cls.host_header,
                "X-Forwarded-Proto": "https",
                "Authorization": f"Bearer {creds['product_token']}",
                "Content-Type": "application/vnd.api+json",
                "Accept": "application/vnd.api+json",
            },
            timeout=15.0,
            trust_env=False,
        )

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "admin_client"):
            cls.admin_client.close()

    def setUp(self):
        self.created_licenses = set()

    def tearDown(self):
        # Guarantee cleanup of all created test licenses
        for lic_id in list(self.created_licenses):
            try:
                self.admin_client.delete(f"licenses/{lic_id}")
            except Exception:
                pass
            self.created_licenses.discard(lic_id)

    # -------------------------------------------------------------------------
    # Helper methods
    # -------------------------------------------------------------------------

    def create_test_license(self, metadata: dict | None = None) -> tuple[str, str, dict]:
        """Creates a fresh test license on the live Keygen instance."""
        lic_id = str(uuid.uuid4())
        meta = {"test": True, "created_by": "automated-test-suite", **(metadata or {})}
        payload = {
            "data": {
                "type": "licenses",
                "id": lic_id,
                "attributes": {"metadata": meta},
                "relationships": {
                    "policy": {"data": {"type": "policies", "id": self.credentials["policy_id"]}}
                },
            }
        }
        resp = self.admin_client.post("licenses", json=payload)
        self.assertEqual(resp.status_code, 201, f"Failed to create license: {resp.text}")
        data = resp.json()["data"]
        key = data["attributes"]["key"]
        self.created_licenses.add(lic_id)
        return lic_id, key, data

    def license_headers(self, key: str) -> dict[str, str]:
        """Returns request headers authenticated via license key."""
        return {
            "Host": self.host_header,
            "X-Forwarded-Proto": "https",
            "Authorization": f"License {key}",
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json",
        }

    # -------------------------------------------------------------------------
    # Test Cases
    # -------------------------------------------------------------------------

    def test_01_keygen_api_connectivity_and_headers(self):
        """1. Verify Keygen CE health endpoint, version, edition, and security headers."""
        resp = self.admin_client.get("health")
        self.assertEqual(resp.status_code, 204)
        self.assertEqual(resp.headers.get("Keygen-Edition"), "CE")
        self.assertEqual(resp.headers.get("Keygen-Mode"), "singleplayer")
        self.assertTrue(resp.headers.get("Keygen-Version", "").startswith("1."))

    def test_02_policy_configuration_and_ten_machine_limit(self):
        """2. Verify policy settings: 10 machines limit, ED25519_SIGN scheme, floating strict mode."""
        resp = self.admin_client.get(f"policies/{self.credentials['policy_id']}")
        self.assertEqual(resp.status_code, 200)
        attrs = resp.json()["data"]["attributes"]
        self.assertEqual(attrs["maxMachines"], 10, "Policy maxMachines must be exactly 10")
        self.assertEqual(attrs["scheme"], "ED25519_SIGN")
        self.assertEqual(attrs["machineUniquenessStrategy"], "UNIQUE_PER_LICENSE")
        self.assertEqual(attrs["authenticationStrategy"], "LICENSE")
        self.assertTrue(attrs["strict"])
        self.assertTrue(attrs["floating"])

    def test_03_license_issuance_and_ed25519_cryptographic_verification(self):
        """3. Test license issuance and cryptographically verify the Ed25519 key signature."""
        lic_id, key, data = self.create_test_license({"scenario": "crypto_issuance"})
        self.assertEqual(data["id"], lic_id)
        self.assertTrue(key.startswith("key/"), "License key must have 'key/' prefix")

        # Parse key: key/<base64_claims>.<base64_signature>
        message, signature_b64 = key.rsplit(".", 1)
        self.assertTrue(message.startswith("key/"))
        claims_b64 = message[4:]

        # Verify Ed25519 cryptographic signature
        sig_bytes = base64.urlsafe_b64decode(signature_b64 + "==")
        try:
            self.public_key.verify(sig_bytes, message.encode("ascii"))
        except InvalidSignature:
            self.fail("Cryptographic Ed25519 signature verification failed for issued license key!")

        # Decode claims payload
        claims = json.loads(base64.urlsafe_b64decode(claims_b64 + "=="))
        self.assertEqual(claims["account"]["id"], self.credentials["account_id"])
        self.assertEqual(claims["product"]["id"], self.credentials["product_id"])
        self.assertEqual(claims["policy"]["id"], self.credentials["policy_id"])
        self.assertEqual(claims["license"]["id"], lic_id)
        self.assertIsNotNone(claims["license"]["created"])

    def test_04_license_key_validation_pre_activation(self):
        """4. Verify validate-key returns NO_MACHINES when no machine is registered yet."""
        _, key, _ = self.create_test_license()
        resp = self.admin_client.post("licenses/actions/validate-key", json={"meta": {"key": key}})
        self.assertEqual(resp.status_code, 200)
        meta = resp.json()["meta"]
        self.assertFalse(meta.get("valid"))
        self.assertIn(meta.get("code"), ("NO_MACHINE", "NO_MACHINES"))

    def test_05_machine_limit_enforcement_ten_installations_and_eleventh_fails(self):
        """5. Core test: activate 10 machines randomly, assert 11th is rejected with MACHINE_LIMIT_EXCEEDED."""
        lic_id, key, _ = self.create_test_license({"scenario": "machine_limit_10"})
        headers = self.license_headers(key)
        created_machines: list[str] = []

        # Activate 10 distinct machines with random fingerprints
        for i in range(1, 11):
            fingerprint = f"inst-fp-{uuid.uuid4()}"
            resp = self.admin_client.post(
                "machines",
                headers=headers,
                json={
                    "data": {
                        "type": "machines",
                        "attributes": {
                            "fingerprint": fingerprint,
                            "name": f"Automated Test Host {i}",
                        },
                        "relationships": {
                            "license": {"data": {"type": "licenses", "id": lic_id}}
                        },
                    }
                },
            )
            self.assertEqual(resp.status_code, 201, f"Machine {i}/10 failed to activate: {resp.text}")
            created_machines.append(resp.json()["data"]["id"])

        self.assertEqual(len(created_machines), 10)

        # Confirm license currently has exactly 10 machines
        list_resp = self.admin_client.get("machines", params={"license": lic_id, "limit": 20})
        self.assertEqual(list_resp.status_code, 200)
        self.assertEqual(len(list_resp.json()["data"]), 10)

        # Attempt to activate 11th machine: MUST be rejected with HTTP 422 MACHINE_LIMIT_EXCEEDED
        fp_11 = f"inst-fp-{uuid.uuid4()}"
        resp_11 = self.admin_client.post(
            "machines",
            headers=headers,
            json={
                "data": {
                    "type": "machines",
                    "attributes": {
                        "fingerprint": fp_11,
                        "name": "Automated Test Host 11 (Overflow)",
                    },
                    "relationships": {
                        "license": {"data": {"type": "licenses", "id": lic_id}}
                    },
                }
            },
        )
        self.assertEqual(
            resp_11.status_code,
            422,
            f"11th machine was not rejected! Returned HTTP {resp_11.status_code}",
        )
        errors = resp_11.json().get("errors", [])
        self.assertTrue(any(e.get("code") == "MACHINE_LIMIT_EXCEEDED" for e in errors), errors)

        # Confirm total machine count is STILL exactly 10
        list_resp2 = self.admin_client.get("machines", params={"license": lic_id, "limit": 20})
        self.assertEqual(len(list_resp2.json()["data"]), 10)

    def test_06_machine_deactivation_and_slot_reclamation(self):
        """6. Core test: fill 10 machines, deactivate 2, verify 2 new machines succeed, and 11th fails again."""
        lic_id, key, _ = self.create_test_license({"scenario": "slot_reclamation"})
        headers = self.license_headers(key)
        created_machines: list[str] = []

        # Step 1: Fill all 10 slots
        for i in range(1, 11):
            fp = f"reclaim-fp-{uuid.uuid4()}"
            resp = self.admin_client.post(
                "machines",
                headers=headers,
                json={
                    "data": {
                        "type": "machines",
                        "attributes": {"fingerprint": fp, "name": f"Node {i}"},
                        "relationships": {"license": {"data": {"type": "licenses", "id": lic_id}}},
                    }
                },
            )
            self.assertEqual(resp.status_code, 201)
            created_machines.append(resp.json()["data"]["id"])

        # Step 2: Deactivate 2 machines
        del1 = self.admin_client.delete(f"machines/{created_machines[0]}", headers=headers)
        self.assertEqual(del1.status_code, 204, "Failed to deactivate machine 1")
        del2 = self.admin_client.delete(f"machines/{created_machines[1]}", headers=headers)
        self.assertEqual(del2.status_code, 204, "Failed to deactivate machine 2")

        # Step 3: Verify count dropped to 8
        count_resp = self.admin_client.get("machines", params={"license": lic_id})
        self.assertEqual(len(count_resp.json()["data"]), 8)

        # Step 4: Reclaim slot 9 (should succeed)
        fp_reclaim_1 = f"reclaim-fp-{uuid.uuid4()}"
        resp_r1 = self.admin_client.post(
            "machines",
            headers=headers,
            json={
                "data": {
                    "type": "machines",
                    "attributes": {"fingerprint": fp_reclaim_1, "name": "Reclaimed Node 9"},
                    "relationships": {"license": {"data": {"type": "licenses", "id": lic_id}}},
                }
            },
        )
        self.assertEqual(resp_r1.status_code, 201, "Slot 9 reclamation failed")

        # Step 5: Reclaim slot 10 (should succeed)
        fp_reclaim_2 = f"reclaim-fp-{uuid.uuid4()}"
        resp_r2 = self.admin_client.post(
            "machines",
            headers=headers,
            json={
                "data": {
                    "type": "machines",
                    "attributes": {"fingerprint": fp_reclaim_2, "name": "Reclaimed Node 10"},
                    "relationships": {"license": {"data": {"type": "licenses", "id": lic_id}}},
                }
            },
        )
        self.assertEqual(resp_r2.status_code, 201, "Slot 10 reclamation failed")

        # Step 6: Attempt slot 11 again (MUST fail with MACHINE_LIMIT_EXCEEDED)
        fp_overflow = f"reclaim-fp-{uuid.uuid4()}"
        resp_over = self.admin_client.post(
            "machines",
            headers=headers,
            json={
                "data": {
                    "type": "machines",
                    "attributes": {"fingerprint": fp_overflow, "name": "Overflow Node 11"},
                    "relationships": {"license": {"data": {"type": "licenses", "id": lic_id}}},
                }
            },
        )
        self.assertEqual(resp_over.status_code, 422)
        errors = resp_over.json().get("errors", [])
        self.assertTrue(any(e.get("code") == "MACHINE_LIMIT_EXCEEDED" for e in errors))

    def test_07_machine_fingerprint_uniqueness_per_license(self):
        """7. Verify duplicate fingerprint registration on same license returns FINGERPRINT_TAKEN."""
        lic_id, key, _ = self.create_test_license()
        headers = self.license_headers(key)
        shared_fp = f"unique-fp-{uuid.uuid4()}"

        resp1 = self.admin_client.post(
            "machines",
            headers=headers,
            json={
                "data": {
                    "type": "machines",
                    "attributes": {"fingerprint": shared_fp},
                    "relationships": {"license": {"data": {"type": "licenses", "id": lic_id}}},
                }
            },
        )
        self.assertEqual(resp1.status_code, 201)

        # Attempt same fingerprint again
        resp2 = self.admin_client.post(
            "machines",
            headers=headers,
            json={
                "data": {
                    "type": "machines",
                    "attributes": {"fingerprint": shared_fp},
                    "relationships": {"license": {"data": {"type": "licenses", "id": lic_id}}},
                }
            },
        )
        self.assertEqual(resp2.status_code, 422)
        codes = [e.get("code") for e in resp2.json().get("errors", [])]
        self.assertIn("FINGERPRINT_TAKEN", codes)

    def test_08_machine_checkout_and_cryptographic_permit_verification(self):
        """8. Test check-out action, certificate formatting, and Ed25519 signature of machine permit."""
        lic_id, key, _ = self.create_test_license()
        headers = self.license_headers(key)
        fp = f"checkout-fp-{uuid.uuid4()}"

        m_resp = self.admin_client.post(
            "machines",
            headers=headers,
            json={
                "data": {
                    "type": "machines",
                    "attributes": {"fingerprint": fp},
                    "relationships": {"license": {"data": {"type": "licenses", "id": lic_id}}},
                }
            },
        )
        self.assertEqual(m_resp.status_code, 201)
        machine_id = m_resp.json()["data"]["id"]

        # Check out machine permit certificate
        co_resp = self.admin_client.post(
            f"machines/{machine_id}/actions/check-out",
            headers=headers,
            json={"meta": {"ttl": 604800, "algorithm": "base64+ed25519", "include": ["license"]}},
        )
        self.assertEqual(co_resp.status_code, 200)
        cert = co_resp.json()["data"]["attributes"]["certificate"]

        prefix = "-----BEGIN MACHINE FILE-----\n"
        suffix = "-----END MACHINE FILE-----\n"
        self.assertTrue(cert.startswith(prefix))
        self.assertTrue(cert.endswith(suffix))

        raw_b64 = "".join(cert[len(prefix) : -len(suffix)].split())
        doc = json.loads(base64.b64decode(raw_b64))
        self.assertEqual(doc["alg"], "base64+ed25519")

        # Verify Ed25519 signature of document
        sig = base64.b64decode(doc["sig"])
        msg = ("machine/" + doc["enc"]).encode("ascii")
        try:
            self.public_key.verify(sig, msg)
        except InvalidSignature:
            self.fail("Machine certificate cryptographic signature is invalid!")

        # Verify payload claims
        payload = json.loads(base64.b64decode(doc["enc"]))
        self.assertEqual(payload["data"]["id"], machine_id)
        self.assertEqual(payload["data"]["attributes"]["fingerprint"], fp)
        self.assertEqual(payload["meta"]["ttl"], 604800)

        # Verify oversize TTL is rejected
        bad_ttl = self.admin_client.post(
            f"machines/{machine_id}/actions/check-out",
            headers=headers,
            json={"meta": {"ttl": 604801, "include": ["license"]}},
        )
        self.assertIn(bad_ttl.status_code, (400, 422))

    def test_09_license_suspension_and_reinstatement_lifecycle(self):
        """9. Test admin suspend action, enforcement of suspended state, and reinstatement."""
        lic_id, key, _ = self.create_test_license()
        headers = self.license_headers(key)
        fp = f"suspend-fp-{uuid.uuid4()}"

        # 1. Suspend license
        sus_resp = self.admin_client.post(f"licenses/{lic_id}/actions/suspend")
        self.assertEqual(sus_resp.status_code, 200)

        # 2. validate-key returns SUSPENDED
        val_resp = self.admin_client.post("licenses/actions/validate-key", json={"meta": {"key": key}})
        self.assertEqual(val_resp.status_code, 200)
        self.assertFalse(val_resp.json()["meta"]["valid"])
        self.assertEqual(val_resp.json()["meta"]["code"], "SUSPENDED")

        # 3. Activation fails on suspended license (HTTP 403 LICENSE_SUSPENDED)
        act_resp = self.admin_client.post(
            "machines",
            headers=headers,
            json={
                "data": {
                    "type": "machines",
                    "attributes": {"fingerprint": fp},
                    "relationships": {"license": {"data": {"type": "licenses", "id": lic_id}}},
                }
            },
        )
        self.assertEqual(act_resp.status_code, 403)
        codes = [e.get("code") for e in act_resp.json().get("errors", [])]
        self.assertIn("LICENSE_SUSPENDED", codes)

        # 4. Reinstate license
        rein_resp = self.admin_client.post(f"licenses/{lic_id}/actions/reinstate")
        self.assertEqual(rein_resp.status_code, 200)

        # 5. Activation now succeeds
        act2_resp = self.admin_client.post(
            "machines",
            headers=headers,
            json={
                "data": {
                    "type": "machines",
                    "attributes": {"fingerprint": fp},
                    "relationships": {"license": {"data": {"type": "licenses", "id": lic_id}}},
                }
            },
        )
        self.assertEqual(act2_resp.status_code, 201)

    def test_10_end_to_end_license_client_integration(self):
        """10. Test high-level LicenseClient: import -> activation -> check -> deactivation."""
        lic_id, key, _ = self.create_test_license({"scenario": "license_client_e2e"})
        transport = LocalKeygenTransport(self.target_port, self.host_header)

        try:
            with tempfile.TemporaryDirectory(prefix="keygen-client-test-") as tmpdir:
                client = LicenseClient(
                    tmpdir,
                    public_key=self.credentials["public_key"],
                    account_id=self.credentials["account_id"],
                    product_id=self.credentials["product_id"],
                    policy_id=self.credentials["policy_id"],
                    build_release_date="2026-10-05T00:00:00Z",
                    transport=transport,
                )
                try:
                    # 1. Import license
                    blob = json.dumps({"schema": 2, "license_key": key})
                    status1 = client.import_license(blob)
                    self.assertTrue(status1.allowed)
                    self.assertEqual(status1.state, "valid")

                    # 2. Check cached validation
                    status2 = client.check()
                    self.assertTrue(status2.allowed)
                    self.assertEqual(status2.state, "valid")

                    # 3. Confirm remote machine exists
                    with client._state() as state:
                        installation_id = state["installation_id"]
                    m_list = self.admin_client.get("machines", params={"license": lic_id}).json()["data"]
                    self.assertEqual(len(m_list), 1)
                    self.assertEqual(m_list[0]["attributes"]["fingerprint"], installation_id)

                    # 4. Deactivate from client
                    deact = client.deactivate()
                    self.assertFalse(deact.allowed)
                    self.assertEqual(deact.state, "deactivated")

                    # 5. Confirm remote machine was deleted on server
                    m_list_after = self.admin_client.get("machines", params={"license": lic_id}).json()["data"]
                    self.assertEqual(len(m_list_after), 0)
                finally:
                    client.close()
        finally:
            transport.close()

    def test_11_concurrent_activation_limit_race(self):
        """11. Race test: concurrent activations must never exceed the 10 machine cap."""
        lic_id, key, _ = self.create_test_license({"scenario": "concurrent_race"})
        blob = json.dumps({"schema": 2, "license_key": key})

        # Activate initial client to establish license expiry timestamp on Keygen (FROM_FIRST_ACTIVATION policy)
        with tempfile.TemporaryDirectory(prefix="keygen-c0-") as tmpdir0:
            c0 = LicenseClient(
                tmpdir0,
                public_key=self.credentials["public_key"],
                account_id=self.credentials["account_id"],
                product_id=self.credentials["product_id"],
                policy_id=self.credentials["policy_id"],
                build_release_date="2026-10-05T00:00:00Z",
                transport=LocalKeygenTransport(self.target_port, self.host_header),
            )
            try:
                st0 = c0.import_license(blob)
                self.assertEqual(st0.state, "valid")
            finally:
                c0.close()

        # Now race remaining 11 clients in parallel across the remaining 9 available slots
        def run_client(idx: int) -> str:
            with tempfile.TemporaryDirectory(prefix=f"keygen-crace-{idx}-") as tmpdir:
                c = LicenseClient(
                    tmpdir,
                    public_key=self.credentials["public_key"],
                    account_id=self.credentials["account_id"],
                    product_id=self.credentials["product_id"],
                    policy_id=self.credentials["policy_id"],
                    build_release_date="2026-10-05T00:00:00Z",
                    transport=LocalKeygenTransport(self.target_port, self.host_header),
                )
                try:
                    res = c.import_license(blob)
                    return res.state
                finally:
                    c.close()

        with ThreadPoolExecutor(max_workers=11) as pool:
            remaining_states = list(pool.map(run_client, range(11)))

        # Exactly 9 must succeed (total 10 on server), exactly 2 must be rejected with installation_limit
        self.assertEqual(remaining_states.count("valid"), 9)
        self.assertEqual(remaining_states.count("installation_limit"), 2)

        # Server must hold exactly 10 machines
        m_resp = self.admin_client.get("machines", params={"license": lic_id, "limit": 20})
        self.assertEqual(len(m_resp.json()["data"]), 10)


if __name__ == "__main__":
    unittest.main()
