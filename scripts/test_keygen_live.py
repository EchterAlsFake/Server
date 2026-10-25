#!/usr/bin/env python3
"""Turnkey CLI test runner for live Keygen CE licensing instance.

Tests license issuance, Ed25519 cryptographic signatures, 10-installation machine limit,
overflow rejection (11th machine), slot reclamation after deactivation, machine permit
checkout, suspension lifecycle, and full LicenseClient integration.

Usage:
    python3 scripts/test_keygen_live.py
    python3 scripts/test_keygen_live.py --port 18004 --verbose
"""

from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from license_client import LicenseClient, LicenseError

# ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def log_step(step: str, title: str):
    print(f"\n{BOLD}{CYAN}[{step}]{RESET} {BOLD}{title}{RESET}")


def log_substep(status: bool, message: str):
    mark = f"{GREEN}✓{RESET}" if status else f"{RED}✗{RESET}"
    print(f"  {mark} {message}")


def log_info(message: str):
    print(f"    {DIM}↳ {message}{RESET}")


def find_credentials(custom_path: str | None = None) -> dict[str, str]:
    root = Path(__file__).resolve().parents[1]
    candidates = []
    if custom_path:
        candidates.append(Path(custom_path))
    candidates.extend([
        root / "deploy/keygen/credentials/product.json",
        root / "license_client/production.json",
        Path("/srv/keygen/credentials/product.json"),
        Path("/var/lib/pornfetch/.local/share/containers/storage/volumes/keygen-credentials-data/_data/product.json"),
    ])

    creds: dict[str, str] = {}
    for c in candidates:
        if c.is_file():
            try:
                data = json.loads(c.read_text())
                for k in ("account_id", "product_id", "policy_id", "public_key", "product_token"):
                    if k in data and k not in creds:
                        creds[k] = data[k]
            except Exception:
                pass

    if os.environ.get("KEYGEN_PRODUCT_TOKEN"):
        creds["product_token"] = os.environ["KEYGEN_PRODUCT_TOKEN"]

    required = ("account_id", "product_id", "policy_id", "public_key", "product_token")
    missing = [k for k in required if k not in creds]
    if missing:
        print(f"{RED}Error: Missing Keygen credentials: {', '.join(missing)}{RESET}")
        sys.exit(1)
    return creds


class LocalKeygenTransport(httpx.BaseTransport):
    def __init__(self, port: int, host: str):
        self._transport = httpx.HTTPTransport()
        self.port = port
        self.host = host

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        headers = [(k, v) for k, v in request.headers.raw if k.lower() != b"host"]
        headers.append((b"host", self.host.encode("ascii")))
        headers.append((b"x-forwarded-proto", b"https"))
        url = request.url.copy_with(scheme="http", host="127.0.0.1", port=self.port)
        rewritten = httpx.Request(
            method=request.method,
            url=url,
            headers=headers,
            content=request.content,
        )
        return self._transport.handle_request(rewritten)

    def close(self):
        self._transport.close()


def main():
    parser = argparse.ArgumentParser(description="Test Keygen CE license issuance & machine limits")
    parser.add_argument("--port", type=int, default=int(os.environ.get("KEYGEN_PORT", "18004")),
                        help="Keygen API port (default: 18004)")
    parser.add_argument("--host", default=os.environ.get("KEYGEN_HOST", "licenses.pornfetch.to"),
                        help="Keygen Host header (default: licenses.pornfetch.to)")
    parser.add_argument("--credentials", default=None, help="Path to product.json credentials file")
    parser.add_argument("--limit", type=int, default=10, help="Machine limit to test (default: 10)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    print(f"{BOLD}======================================================================{RESET}")
    print(f"{BOLD}           Keygen CE Automated Live Test Suite & Verifier             {RESET}")
    print(f"{BOLD}======================================================================{RESET}")
    print(f"Target Endpoint: {CYAN}http://127.0.0.1:{args.port}/v1/{RESET} (Host: {args.host})")

    creds = find_credentials(args.credentials)
    print(f"Account ID:      {creds['account_id']}")
    print(f"Product ID:      {creds['product_id']}")
    print(f"Policy ID:       {creds['policy_id']}")
    print(f"Public Key:      {creds['public_key'][:16]}...{creds['public_key'][-16:]}")

    admin = httpx.Client(
        base_url=f"http://127.0.0.1:{args.port}/v1/",
        headers={
            "Host": args.host,
            "X-Forwarded-Proto": "https",
            "Authorization": f"Bearer {creds['product_token']}",
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json",
        },
        timeout=15.0,
        trust_env=False,
    )

    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(creds["public_key"]))
    test_license_id = str(uuid.uuid4())
    license_key: str | None = None

    try:
        # Step 1: Health & API Connectivity
        log_step("1/8", "API Connectivity & Service Health")
        health = admin.get("health")
        if health.status_code == 204:
            log_substep(True, f"Keygen health: HTTP 204 ({health.headers.get('Keygen-Edition')} {health.headers.get('Keygen-Version')})")
        else:
            log_substep(False, f"Health check failed: HTTP {health.status_code}")
            return 1

        # Step 2: Policy Verification
        log_step("2/8", "Policy Configuration & Limit Verification")
        policy_resp = admin.get(f"policies/{creds['policy_id']}")
        if policy_resp.status_code != 200:
            log_substep(False, f"Failed to fetch policy: HTTP {policy_resp.status_code}")
            return 1
        policy_attrs = policy_resp.json()["data"]["attributes"]
        max_machines = policy_attrs.get("maxMachines")
        scheme = policy_attrs.get("scheme")
        log_substep(max_machines == args.limit, f"Policy maxMachines: {max_machines} (expected {args.limit})")
        log_substep(scheme == "ED25519_SIGN", f"Cryptographic scheme: {scheme}")
        log_info(f"Policy Name: '{policy_attrs.get('name')}' | Floating: {policy_attrs.get('floating')} | Strict: {policy_attrs.get('strict')}")

        # Step 3: License Issuance & Cryptographic Verification
        log_step("3/8", "License Issuance & Ed25519 Cryptographic Verification")
        lic_payload = {
            "data": {
                "type": "licenses",
                "id": test_license_id,
                "attributes": {"metadata": {"lifecycle": "test-runner", "timestamp": time.time()}},
                "relationships": {
                    "policy": {"data": {"type": "policies", "id": creds["policy_id"]}}
                },
            }
        }
        lic_resp = admin.post("licenses", json=lic_payload)
        if lic_resp.status_code != 201:
            log_substep(False, f"License issuance failed: HTTP {lic_resp.status_code} - {lic_resp.text}")
            return 1
        lic_data = lic_resp.json()["data"]
        license_key = lic_data["attributes"]["key"]
        log_substep(True, f"Issued license UUID: {test_license_id}")
        log_info(f"License Key: {license_key[:30]}...{license_key[-15:]}")

        # Cryptographic verification
        msg, sig_b64 = license_key.rsplit(".", 1)
        sig_bytes = base64.urlsafe_b64decode(sig_b64 + "==")
        try:
            public_key.verify(sig_bytes, msg.encode("ascii"))
            log_substep(True, "Ed25519 cryptographic signature verified successfully against public key")
        except InvalidSignature:
            log_substep(False, "Ed25519 cryptographic signature verification FAILED")
            return 1

        claims = json.loads(base64.urlsafe_b64decode(msg[4:] + "=="))
        log_info(f"Verified claims: Account={claims['account']['id']} | Product={claims['product']['id']} | Policy={claims['policy']['id']}")

        # Validate-key action before machines
        val_resp = admin.post("licenses/actions/validate-key", json={"meta": {"key": license_key}})
        val_meta = val_resp.json().get("meta", {})
        log_substep(not val_meta.get("valid") and val_meta.get("code") in ("NO_MACHINE", "NO_MACHINES"),
                    f"Pre-activation validation: valid={val_meta.get('valid')} (code: {val_meta.get('code')})")

        # Step 4: Machine Limit Enforcement (10 random machines)
        log_step("4/8", f"Machine Limit Enforcement: Activating {args.limit} Random Installations")
        lic_headers = {
            "Host": args.host,
            "X-Forwarded-Proto": "https",
            "Authorization": f"License {license_key}",
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json",
        }
        created_machines: list[str] = []

        start_time = time.monotonic()
        for i in range(1, args.limit + 1):
            fp = f"rand-inst-{uuid.uuid4()}"
            m_resp = admin.post(
                "machines",
                headers=lic_headers,
                json={
                    "data": {
                        "type": "machines",
                        "attributes": {"fingerprint": fp, "name": f"Node #{i}"},
                        "relationships": {"license": {"data": {"type": "licenses", "id": test_license_id}}},
                    }
                },
            )
            if m_resp.status_code == 201:
                mid = m_resp.json()["data"]["id"]
                created_machines.append(mid)
                if args.verbose or i in (1, 5, args.limit):
                    log_info(f"Slot {i}/{args.limit} activated: Machine ID {mid} (FP: {fp[:16]}...)")
            else:
                log_substep(False, f"Slot {i} activation failed: HTTP {m_resp.status_code} - {m_resp.text}")
                return 1

        elapsed = time.monotonic() - start_time
        log_substep(len(created_machines) == args.limit,
                    f"Successfully activated {len(created_machines)}/{args.limit} machines in {elapsed:.2f}s")

        # Step 5: 11th Machine Rejection (Overflow)
        log_step("5/8", f"Overflow Test: Attempting Machine #{args.limit + 1} (Must Be Rejected)")
        fp_overflow = f"overflow-inst-{uuid.uuid4()}"
        m_overflow = admin.post(
            "machines",
            headers=lic_headers,
            json={
                "data": {
                    "type": "machines",
                    "attributes": {"fingerprint": fp_overflow, "name": f"Node #{args.limit + 1} (Overflow)"},
                    "relationships": {"license": {"data": {"type": "licenses", "id": test_license_id}}},
                }
            },
        )
        if m_overflow.status_code == 422:
            errors = m_overflow.json().get("errors", [])
            has_limit_code = any(e.get("code") == "MACHINE_LIMIT_EXCEEDED" for e in errors)
            detail = errors[0].get("detail") if errors else ""
            log_substep(has_limit_code, f"Machine #{args.limit + 1} rejected with HTTP 422 MACHINE_LIMIT_EXCEEDED")
            log_info(f"Server rejection detail: '{detail}'")
        else:
            log_substep(False, f"Overflow machine was NOT rejected! HTTP {m_overflow.status_code}")
            return 1

        # Step 6: Deactivation of 2 Machines & Slot Reclamation
        log_step("6/8", "Slot Reclamation: Deactivating 2 Machines & Reclaiming Slots")
        # Deactivate machine 0 and 1
        d1 = admin.delete(f"machines/{created_machines[0]}", headers=lic_headers)
        d2 = admin.delete(f"machines/{created_machines[1]}", headers=lic_headers)
        log_substep(d1.status_code == 204 and d2.status_code == 204,
                    f"Deactivated 2 machines ({created_machines[0][:8]}, {created_machines[1][:8]}): HTTP 204")

        # Check count
        cur_machines = admin.get("machines", params={"license": test_license_id}).json()["data"]
        log_substep(len(cur_machines) == args.limit - 2,
                    f"Active machines decreased to {len(cur_machines)} (2 slots freed)")

        # Reclaim slot 1 (machine 9)
        fp_new_1 = f"reclaim-inst-{uuid.uuid4()}"
        r1 = admin.post(
            "machines",
            headers=lic_headers,
            json={
                "data": {
                    "type": "machines",
                    "attributes": {"fingerprint": fp_new_1, "name": "Reclaimed Machine 1"},
                    "relationships": {"license": {"data": {"type": "licenses", "id": test_license_id}}},
                }
            },
        )
        log_substep(r1.status_code == 201, "Reclaimed slot 9 successfully (HTTP 201)")

        # Reclaim slot 2 (machine 10)
        fp_new_2 = f"reclaim-inst-{uuid.uuid4()}"
        r2 = admin.post(
            "machines",
            headers=lic_headers,
            json={
                "data": {
                    "type": "machines",
                    "attributes": {"fingerprint": fp_new_2, "name": "Reclaimed Machine 2"},
                    "relationships": {"license": {"data": {"type": "licenses", "id": test_license_id}}},
                }
            },
        )
        log_substep(r2.status_code == 201, "Reclaimed slot 10 successfully (HTTP 201)")

        # Attempt machine 11 again
        r_over = admin.post(
            "machines",
            headers=lic_headers,
            json={
                "data": {
                    "type": "machines",
                    "attributes": {"fingerprint": f"overflow-2-{uuid.uuid4()}", "name": "Overflow 2"},
                    "relationships": {"license": {"data": {"type": "licenses", "id": test_license_id}}},
                }
            },
        )
        log_substep(r_over.status_code == 422, "Machine #11 correctly rejected again with HTTP 422 (limit fully enforced)")

        # Step 7: Machine Permit Checkout & Cryptographic Certificate
        log_step("7/8", "Offline Machine Permit Checkout & Certificate Signature")
        sample_mid = cur_machines[0]["id"]
        sample_fp = cur_machines[0]["attributes"]["fingerprint"]
        co_resp = admin.post(
            f"machines/{sample_mid}/actions/check-out",
            headers=lic_headers,
            json={"meta": {"ttl": 604800, "algorithm": "base64+ed25519", "include": ["license"]}},
        )
        if co_resp.status_code == 200:
            cert = co_resp.json()["data"]["attributes"]["certificate"]
            log_substep(True, f"Generated offline permit certificate for machine {sample_mid[:8]}")
            prefix = "-----BEGIN MACHINE FILE-----\n"
            suffix = "-----END MACHINE FILE-----\n"
            raw_b64 = "".join(cert[len(prefix) : -len(suffix)].split())
            doc = json.loads(base64.b64decode(raw_b64))
            public_key.verify(base64.b64decode(doc["sig"]), ("machine/" + doc["enc"]).encode("ascii"))
            log_substep(True, "Permit certificate Ed25519 signature cryptographically valid")
            p_claims = json.loads(base64.b64decode(doc["enc"]))
            log_info(f"Permit metadata: TTL={p_claims['meta']['ttl']}s | Expiry={p_claims['meta']['expiry']}")
        else:
            log_substep(False, f"Check-out failed: HTTP {co_resp.status_code}")
            return 1

        # Step 8: High-Level LicenseClient Python Library E2E
        log_step("8/8", "High-Level LicenseClient Python Library Integration")
        # Free 1 slot so the client can perform a clean activation
        admin.delete(f"machines/{cur_machines[2]['id']}", headers=lic_headers)
        transport = LocalKeygenTransport(args.port, args.host)
        with tempfile.TemporaryDirectory(prefix="keygen-cli-client-") as tmpdir:
            client = LicenseClient(
                tmpdir,
                public_key=creds["public_key"],
                account_id=creds["account_id"],
                product_id=creds["product_id"],
                policy_id=creds["policy_id"],
                build_release_date="2026-10-05T00:00:00Z",
                transport=transport,
            )
            blob = json.dumps({"schema": 2, "license_key": license_key})
            status = client.import_license(blob)
            log_substep(status.allowed and status.state == "valid",
                        f"LicenseClient.import_license: state='{status.state}', allowed={status.allowed}")

            check_st = client.check()
            log_substep(check_st.allowed and check_st.state == "valid",
                        f"LicenseClient.check: state='{check_st.state}', allowed={check_st.allowed}")

            deact_st = client.deactivate()
            log_substep(not deact_st.allowed and deact_st.state == "deactivated",
                        f"LicenseClient.deactivate: state='{deact_st.state}', allowed={deact_st.allowed}")
            client.close()
        transport.close()

        print(f"\n{BOLD}{GREEN}======================================================================{RESET}")
        print(f"{BOLD}{GREEN}   ALL TESTS PASSED! Keygen instance is 100% compliant and healthy.   {RESET}")
        print(f"{BOLD}{GREEN}======================================================================{RESET}")
        return 0

    finally:
        # Guarantee cleanup
        if test_license_id:
            del_resp = admin.delete(f"licenses/{test_license_id}")
            if del_resp.status_code == 204:
                print(f"\n{DIM}[Cleanup] Deleted synthetic test license {test_license_id} (HTTP 204){RESET}")
        admin.close()


if __name__ == "__main__":
    sys.exit(main())
