"""Shared isolated application fixture for server regression tests."""

import base64
import hashlib
import hmac
import json
import os
import tempfile
import unittest
from unittest.mock import patch

TEST_RUNTIME = tempfile.TemporaryDirectory(prefix="server-tests-")
os.environ["PF_SERVER_DATA_DIR"] = TEST_RUNTIME.name
os.environ["PF_SERVER_DB"] = os.path.join(TEST_RUNTIME.name, "server.db")
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["PATREON_SECRET"] = "patreon-test-secret"
os.environ["NOWPAYMENTS_IPN_SECRET"] = "nowpayments-test-secret"
os.environ["NOWPAYMENTS_SANDBOX"] = "true"
os.environ["LICENSE_PRIVATE_KEY_B64"] = base64.b64encode(bytes(range(32))).decode(
    "ascii"
)

import main  # noqa: E402
from pf_server.country_service import CountryEvidence  # noqa: E402
from pf_server.models import (  # noqa: E402
    Checklist,
    CiStatus,
    License,
    PatreonLicenseDelivery,
    Transaction,
)

with main.app.app_context():
    main.db.create_all()


class ServerTestCase(unittest.TestCase):
    def setUp(self):
        main.app.config.update(
            TESTING=True,
            RATELIMIT_ENABLED=False,
            WTF_CSRF_ENABLED=False,
        )
        self.client = main.app.test_client()
        self.country_lookup = patch.object(
            main.app.extensions["country_resolver"],
            "lookup",
            return_value=CountryEvidence(
                status="found",
                country_code="DE",
                subdivision="Saxony-Anhalt",
                database_label="DB-IP City Lite test fixture",
            ),
        )
        self.mock_country_lookup = self.country_lookup.start()
        with main.app.app_context():
            for model in (
                Checklist,
                CiStatus,
                PatreonLicenseDelivery,
                License,
                Transaction,
            ):
                main.db.session.execute(main.db.delete(model))
            main.db.session.commit()

    def tearDown(self):
        self.country_lookup.stop()
        with main.app.app_context():
            main.db.session.remove()

    @staticmethod
    def eligible_patreon_payload(
        member_id: str = "member-123",
        email: str | None = "member@example.com",
    ) -> dict:
        return {
            "data": {
                "type": "member",
                "id": member_id,
                "attributes": {
                    "email": email,
                    "patron_status": "active_patron",
                    "last_charge_status": "Paid",
                    "currently_entitled_amount_cents": 1999,
                    "campaign_lifetime_support_cents": 1999,
                    "is_free_trial": False,
                    "is_gifted": False,
                },
                "relationships": {
                    "currently_entitled_tiers": {
                        "data": [{"type": "tier", "id": "license-tier"}]
                    },
                    "user": {"data": {"type": "user", "id": "user-123"}},
                },
            },
            "included": [],
        }

    def post_patreon(
        self,
        payload: dict,
        event: str = "members:pledge:create",
        secret: str | None = None,
        base_url: str = "https://api.echteralsfake.me",
    ):
        raw_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signing_secret = secret or main.app.config["PATREON_SECRET"]
        signature = hmac.new(
            signing_secret.encode("utf-8"), raw_body, hashlib.md5
        ).hexdigest()
        return self.client.post(
            "/patreon-webhook",
            data=raw_body,
            headers={
                "Content-Type": "application/json",
                "X-Patreon-Event": event,
                "X-Patreon-Signature": signature,
            },
            base_url=base_url,
        )

    @staticmethod
    def nowpayments_signature(payload: object) -> str:
        canonical_body = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(
            main.app.config["NOWPAYMENTS_IPN_SECRET"].encode("utf-8"),
            canonical_body,
            hashlib.sha512,
        ).hexdigest()
