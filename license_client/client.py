"""Keygen CE client. Python 3.10+, cryptography and httpx.

The application calls check() at startup and periodically from a background thread.
State deletion/cloning and a modified application are outside this trust boundary.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

WEEK = 604800
DAY = 86400


class LicenseError(ValueError):
    """Invalid input or unusable local licensing state; contains no credentials."""


class TemporaryFailure(Exception):
    pass


class Rejected(Exception):
    def __init__(self, state):
        self.state = state


@dataclass(frozen=True)
class LicenseStatus:
    state: str
    allowed: bool
    expires_at: float | None = None


def decode(value: str, *, url=False) -> bytes:
    return base64.b64decode(value, altchars=b"-_" if url else None, validate=True)


def timestamp(value: str) -> float:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Naive timestamp")
    return parsed.timestamp()


class LicenseClient:
    def __init__(self, state_dir, *, public_key: str, account_id: str,
                 product_id: str, policy_id: str,
                 base_url="https://licenses.echteralsfake.me", transport=None,
                 clock=time.time, monotonic=time.monotonic):
        if not base_url.startswith("https://"):
            raise LicenseError("The licensing endpoint must use HTTPS")
        self.public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key))
        self.account_id, self.product_id, self.policy_id = account_id, product_id, policy_id
        self.clock, self.monotonic = clock, monotonic
        self.anchor_wall, self.anchor_mono = clock(), monotonic()
        directory = Path(state_dir)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = directory / "licensing.sqlite3"
        if not self.path.exists():
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        os.chmod(self.path, 0o600)
        self.http = httpx.Client(base_url=base_url.rstrip("/") + "/v1/",
                                timeout=httpx.Timeout(10, connect=3),
                                follow_redirects=False, trust_env=False, transport=transport,
                                headers={"Accept": "application/vnd.api+json",
                                         "Content-Type": "application/vnd.api+json",
                                         "User-Agent": "license-client"})
        with self._state() as state:
            state.setdefault("installation_id", str(uuid.uuid4()))
            state.setdefault("licenses", {})

    @contextmanager
    def _state(self):
        connection = sqlite3.connect(self.path, timeout=30)
        try:
            connection.execute("CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT value FROM state WHERE id=1").fetchone()
            state = json.loads(row[0]) if row else {}
            yield state
            connection.execute("INSERT OR REPLACE INTO state VALUES (1, ?)", (json.dumps(state),))
            connection.commit()
        except (sqlite3.Error, json.JSONDecodeError):
            connection.rollback()
            raise LicenseError("Local license state is unreadable; do not reset it automatically") from None
        finally:
            connection.close()

    def close(self):
        self.http.close()

    def verify_key(self, key: str) -> dict:
        try:
            if not isinstance(key, str) or len(key) > 16384 or not key.startswith("key/"):
                raise ValueError()
            message, signature = key.rsplit(".", 1)
            self.public_key.verify(decode(signature, url=True), message.encode("ascii"))
            payload = json.loads(decode(message[4:], url=True))
            if (payload["account"]["id"] != self.account_id
                or payload["product"]["id"] != self.product_id
                or payload["policy"]["id"] != self.policy_id
                or payload["policy"]["duration"] is not None
                or payload["license"]["expiry"] is not None):
                raise ValueError()
            uuid.UUID(payload["license"]["id"])
            timestamp(payload["license"]["created"])
            return payload
        except (ValueError, KeyError, TypeError, UnicodeError, InvalidSignature):
            raise LicenseError("License signature or signed claims are invalid") from None

    def verify_permit(self, certificate: str, *, license_id: str, installation_id: str, now: float) -> dict:
        try:
            if not isinstance(certificate, str) or len(certificate) > 65536:
                raise ValueError()
            prefix, suffix = "-----BEGIN MACHINE FILE-----\n", "-----END MACHINE FILE-----\n"
            if not certificate.startswith(prefix) or not certificate.endswith(suffix):
                raise ValueError()
            encoded = "".join(certificate[len(prefix):-len(suffix)].split())
            document = json.loads(decode(encoded))
            if document["alg"] != "base64+ed25519":
                raise ValueError()
            self.public_key.verify(decode(document["sig"]), ("machine/" + document["enc"]).encode("ascii"))
            payload = json.loads(decode(document["enc"]))
            meta, machine = payload["meta"], payload["data"]
            issued, expiry = timestamp(meta["issued"]), timestamp(meta["expiry"])
            if type(meta["ttl"]) is not int or not 0 < meta["ttl"] <= WEEK:
                raise ValueError()
            if abs(expiry - issued - meta["ttl"]) > 1 or issued > now + 300:
                raise ValueError()
            relationships = machine["relationships"]
            if (machine["type"] != "machines"
                or relationships["account"]["data"]["id"] != self.account_id
                or relationships["product"]["data"]["id"] != self.product_id
                or relationships["license"]["data"]["id"] != license_id
                or machine["attributes"]["fingerprint"] != installation_id):
                raise ValueError()
            licenses = [item for item in payload["included"] if item["type"] == "licenses" and item["id"] == license_id]
            if len(licenses) != 1:
                raise ValueError()
            attributes = licenses[0]["attributes"]
            if attributes["suspended"] or attributes["expiry"] is not None:
                raise ValueError()
            if licenses[0]["relationships"]["policy"]["data"]["id"] != self.policy_id:
                raise ValueError()
            return {"issued": issued, "expiry": expiry, "machine_id": machine["id"]}
        except (ValueError, KeyError, TypeError, UnicodeError, InvalidSignature):
            raise LicenseError("Machine permit signature or signed claims are invalid") from None

    def _request(self, method, path, key, **kwargs):
        try:
            response = self.http.request(method, path, headers={"Authorization": "License " + key}, **kwargs)
        except httpx.HTTPError:
            raise TemporaryFailure() from None
        if response.status_code in (408, 429) or response.status_code >= 500:
            raise TemporaryFailure()
        if response.status_code == 404:
            raise Rejected("not_found")
        if response.status_code not in (200, 201, 204):
            try:
                codes = {e.get("code") for e in response.json().get("errors", [])}
            except (ValueError, TypeError, AttributeError):
                codes = set()
            if any("LIMIT" in (code or "") for code in codes):
                raise Rejected("installation_limit")
            if codes & {"LICENSE_SUSPENDED", "LICENSE_EXPIRED", "SUSPENDED", "EXPIRED"}:
                raise Rejected("revoked")
            if "FINGERPRINT_TAKEN" in codes:
                raise Rejected("duplicate")
            raise Rejected("rejected")
        if response.status_code == 204:
            return {}
        try:
            return response.json()
        except ValueError:
            raise TemporaryFailure() from None

    def import_license(self, blob: bytes | str) -> LicenseStatus:
        try:
            if len(blob) > 32768:
                raise ValueError()
            envelope = json.loads(blob)
            if envelope["schema"] != 2:
                raise ValueError()
            key = envelope["license_key"]
            claims = self.verify_key(key)
        except (ValueError, KeyError, TypeError):
            raise LicenseError("Import a valid schema-2 license file") from None
        license_id = claims["license"]["id"]
        with self._state() as state:
            state["active"] = license_id
            record = state["licenses"].setdefault(license_id, {
                "key": key, "first_import": self.clock(), "activated": False,
            })
            if record["key"] != key:
                raise LicenseError("A different credential already exists for this license")
        return self.check(force=True)

    def _refresh(self, state, record, license_id, now):
        key, fingerprint = record["key"], state["installation_id"]
        response = self._request("POST", "licenses/actions/validate-key", key,
                                 json={"meta": {"key": key, "scope": {"fingerprint": fingerprint,
                                       "product": self.product_id, "policy": self.policy_id}}})
        meta = response["meta"]
        code = meta.get("code")
        if not meta.get("valid") and code not in ("NO_MACHINE", "NO_MACHINES", "FINGERPRINT_SCOPE_MISMATCH"):
            raise Rejected("revoked" if code in ("SUSPENDED", "EXPIRED") else
                           "installation_limit" if code in ("TOO_MANY_MACHINES", "MACHINE_LIMIT_EXCEEDED") else "rejected")
        if not meta.get("valid"):
            try:
                self._request("POST", "machines", key, json={"data": {
                    "type": "machines", "attributes": {"fingerprint": fingerprint},
                    "relationships": {"license": {"data": {"type": "licenses", "id": license_id}}},
                }})
            except Rejected as error:
                if error.state != "duplicate":
                    raise
        # Resolve by fingerprint: a lost activation response cannot consume another slot.
        machine = self._request("GET", "machines/" + fingerprint, key)["data"]
        certificate = self._request("POST", "machines/" + machine["id"] + "/actions/check-out", key,
                                    json={"meta": {"ttl": WEEK, "algorithm": "base64+ed25519", "include": ["license"]}})["data"]["attributes"]["certificate"]
        permit = self.verify_permit(certificate, license_id=license_id, installation_id=fingerprint, now=now)
        if permit["expiry"] <= now:
            raise LicenseError("The renewed permit has already expired")
        record.update(permit=certificate, activated=True, blocked=None, offline=False,
                      retry_at=0, failures=0, renewed=permit["issued"])
        return permit

    def check(self, *, force=False) -> LicenseStatus:
        now = self.clock()
        with self._state() as state:
            license_id = state.get("active")
            if not license_id:
                return LicenseStatus("unlicensed", False)
            record = state["licenses"][license_id]
            try:
                self.verify_key(record["key"])
            except LicenseError:
                return LicenseStatus("invalid_signature", False)
            expected = self.anchor_wall + (self.monotonic() - self.anchor_mono)
            rollback = now < max(state.get("last_seen", now), expected) - 300
            state["last_seen"] = max(now, state.get("last_seen", now))
            due = force or rollback or now - record.get("renewed", 0) >= DAY
            if due and (force or now >= record.get("retry_at", 0)):
                try:
                    self._refresh(state, record, license_id, now)
                except TemporaryFailure:
                    failures = min(record.get("failures", 0) + 1, 7)
                    record.update(offline=True, failures=failures, retry_at=now + min(60 * 2 ** (failures - 1), 3600))
                except Rejected as error:
                    record.update(blocked=error.state, retry_at=now + 60)
                except (LicenseError, KeyError, TypeError):
                    record.update(blocked="invalid_signature", retry_at=now + 60)
            if rollback:
                return LicenseStatus("clock_invalid", False)
            if record.get("blocked"):
                return LicenseStatus(record["blocked"], False)
            if record["activated"]:
                try:
                    permit = self.verify_permit(record["permit"], license_id=license_id,
                                                installation_id=state["installation_id"], now=now)
                except (LicenseError, KeyError):
                    return LicenseStatus("invalid_signature", False)
                expiry = permit["expiry"]
                return LicenseStatus("expired_grace" if now >= expiry else
                                     "offline_grace" if record.get("offline") else "valid",
                                     now < expiry, expiry)
            expiry = record["first_import"] + WEEK
            return LicenseStatus("provisional" if now < expiry else "expired_grace", now < expiry, expiry)

    def deactivate(self) -> LicenseStatus:
        with self._state() as state:
            license_id = state.get("active")
            if not license_id:
                return LicenseStatus("unlicensed", False)
            record = state["licenses"][license_id]
            try:
                machine = self._request("GET", "machines/" + state["installation_id"], record["key"])["data"]
                self._request("DELETE", "machines/" + machine["id"], record["key"])
            except TemporaryFailure:
                return LicenseStatus("deactivation_pending", False)
            except Rejected as error:
                if error.state != "not_found":
                    return LicenseStatus("deactivation_failed", False)
            record.update(blocked="deactivated", permit=None, activated=True, retry_at=0)
            state.pop("active", None)
            return LicenseStatus("deactivated", False)
