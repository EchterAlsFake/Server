import base64
import hashlib
import hmac
import json
import os
import string
import tempfile
import unittest
from unittest.mock import patch


TEST_RUNTIME = tempfile.TemporaryDirectory(prefix="server-webhook-tests-")
os.environ["PF_SERVER_DB"] = os.path.join(TEST_RUNTIME.name, "server.db")
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["PATREON_SECRET"] = "patreon-test-secret"
os.environ["NOWPAYMENTS_IPN_SECRET"] = "nowpayments-test-secret"
os.environ["NOWPAYMENTS_SANDBOX"] = "true"
os.environ["LICENSE_PRIVATE_KEY_B64"] = base64.b64encode(bytes(range(32))).decode("ascii")

import main  # noqa: E402


class PaymentWebhookTests(unittest.TestCase):
    def setUp(self):
        main.app.config.update(TESTING=True, RATELIMIT_ENABLED=False, WTF_CSRF_ENABLED=False)
        self.client = main.app.test_client()
        with main.app.app_context():
            main.db.session.execute(main.db.delete(main.PatreonLicenseDelivery))
            main.db.session.execute(main.db.delete(main.License))
            main.db.session.execute(main.db.delete(main.Transaction))
            main.db.session.commit()

    def tearDown(self):
        with main.app.app_context():
            main.db.session.remove()

    @staticmethod
    def eligible_payload(member_id="member-123", email="member@example.com"):
        attributes = {
            "email": email,
            "patron_status": "active_patron",
            "last_charge_status": "Paid",
            "currently_entitled_amount_cents": 1999,
            "campaign_lifetime_support_cents": 1999,
            "is_free_trial": False,
            "is_gifted": False,
        }
        return {
            "data": {
                "type": "member",
                "id": member_id,
                "attributes": attributes,
                "relationships": {
                    "currently_entitled_tiers": {
                        "data": [{"type": "tier", "id": "license-tier"}]
                    },
                    "user": {"data": {"type": "user", "id": "user-123"}},
                },
            },
            "included": [],
        }

    def post_patreon(self, payload, event="members:pledge:create", secret=None):
        raw_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signing_secret = secret if secret is not None else main.PATREON_SECRET
        signature = hmac.new(signing_secret.encode("utf-8"), raw_body, hashlib.md5).hexdigest()
        return self.client.post(
            "/patreon-webhook",
            data=raw_body,
            headers={
                "Content-Type": "application/json",
                "X-Patreon-Event": event,
                "X-Patreon-Signature": signature,
            },
            base_url="https://api.echteralsfake.me",
        )

    def test_patreon_signature_is_checked_before_processing(self):
        response = self.post_patreon(self.eligible_payload(), secret="wrong-secret")

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json(), {"error": "invalid_signature"})
        with main.app.app_context():
            self.assertEqual(main.PatreonLicenseDelivery.query.count(), 0)
            self.assertEqual(main.License.query.count(), 0)

    def test_paid_member_receives_one_signed_license_for_both_events(self):
        deliveries = []

        def capture_email(recipient, license_file):
            deliveries.append((recipient, license_file))

        payload = self.eligible_payload()
        with patch.object(main, "send_license_email", side_effect=capture_email):
            first = self.post_patreon(payload, event="members:create")
            duplicate = self.post_patreon(payload, event="members:pledge:create")
            paid_update = self.post_patreon(payload, event="members:update")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(duplicate.status_code, 200)
        self.assertEqual(paid_update.status_code, 200)
        self.assertEqual(len(deliveries), 1)
        self.assertEqual(deliveries[0][0], "member@example.com")
        license_payload = json.loads(deliveries[0][1])
        self.assertEqual(license_payload["product"], "porn-fetch")
        self.assertEqual(license_payload["features"], ["full_unlock"])
        self.assertTrue(license_payload["stripe_session_id"].startswith("PT-"))
        self.assertNotIn("member@example.com", deliveries[0][1].decode("utf-8"))

        with main.app.app_context():
            delivery = main.db.session.get(main.PatreonLicenseDelivery, "member-123")
            self.assertEqual(delivery.status, "sent")
            self.assertIsNotNone(delivery.sent_at)
            self.assertEqual(main.License.query.count(), 1)
            self.assertFalse(hasattr(delivery, "email"))

    def test_failed_email_is_retried_with_the_same_license(self):
        attempted_files = []

        def fail_once(_recipient, license_file):
            attempted_files.append(license_file)
            if len(attempted_files) == 1:
                raise RuntimeError("simulated SMTP failure")

        with patch.object(main, "send_license_email", side_effect=fail_once):
            failed = self.post_patreon(self.eligible_payload())
            retried = self.post_patreon(self.eligible_payload())

        self.assertEqual(failed.status_code, 503)
        self.assertEqual(retried.status_code, 200)
        self.assertEqual(len(attempted_files), 2)
        self.assertEqual(attempted_files[0], attempted_files[1])
        with main.app.app_context():
            delivery = main.db.session.get(main.PatreonLicenseDelivery, "member-123")
            self.assertEqual(delivery.status, "sent")
            self.assertEqual(main.License.query.count(), 1)

    def test_free_declined_and_gifted_members_do_not_receive_a_license(self):
        payloads = []
        for change in (
            {"currently_entitled_amount_cents": 0, "last_charge_status": None, "patron_status": None},
            {"last_charge_status": "Declined", "patron_status": "declined_patron"},
            {"is_gifted": True},
        ):
            payload = self.eligible_payload(member_id=f"member-{len(payloads)}")
            payload["data"]["attributes"].update(change)
            payloads.append(payload)

        with patch.object(main, "send_license_email") as send_email:
            responses = [self.post_patreon(payload) for payload in payloads]

        self.assertTrue(all(response.status_code == 200 for response in responses))
        self.assertTrue(all(response.get_json() == {"status": "not_eligible"} for response in responses))
        send_email.assert_not_called()
        with main.app.app_context():
            self.assertEqual(main.PatreonLicenseDelivery.query.count(), 0)

    def test_paid_member_update_delivers_after_an_initial_pending_charge(self):
        pending = self.eligible_payload()
        pending["data"]["attributes"].update(
            {"last_charge_status": "Pending", "patron_status": "active_patron"}
        )
        initial_response = self.post_patreon(pending, event="members:pledge:create")

        with patch.object(main, "send_license_email") as send_email:
            paid_response = self.post_patreon(
                self.eligible_payload(), event="members:update"
            )

        self.assertEqual(initial_response.get_json(), {"status": "not_eligible"})
        self.assertEqual(paid_response.status_code, 200)
        send_email.assert_called_once()

    def test_configured_tier_allow_list_is_enforced(self):
        with (
            patch.object(main, "PATREON_LICENSE_TIER_IDS", frozenset({"different-tier"})),
            patch.object(main, "send_license_email") as send_email,
        ):
            response = self.post_patreon(self.eligible_payload())

        self.assertEqual(response.get_json(), {"status": "not_eligible"})
        send_email.assert_not_called()
        with main.app.app_context():
            self.assertEqual(main.PatreonLicenseDelivery.query.count(), 0)

    def test_missing_email_and_unrelated_event_are_acknowledged_without_storage(self):
        missing_email = self.eligible_payload(email=None)
        no_email_response = self.post_patreon(missing_email)
        unrelated_response = self.post_patreon(
            self.eligible_payload(),
            event="members:pledge:delete",
        )

        self.assertEqual(no_email_response.get_json(), {"status": "email_unavailable"})
        self.assertEqual(unrelated_response.get_json(), {"status": "ignored_event"})
        with main.app.app_context():
            self.assertEqual(main.PatreonLicenseDelivery.query.count(), 0)

    def test_invalid_member_identifier_is_rejected_before_database_access(self):
        payload = self.eligible_payload(member_id="'; DROP TABLE license; --")
        response = self.post_patreon(payload)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json(), {"error": "invalid_payload"})
        with main.app.app_context():
            self.assertEqual(main.License.query.count(), 0)

    def test_patreon_payload_types_are_validated_without_coercion(self):
        malformed_payloads = []
        for field_name, invalid_value in (
            ("currently_entitled_amount_cents", True),
            ("is_free_trial", "false"),
        ):
            payload = self.eligible_payload()
            payload["data"]["attributes"][field_name] = invalid_value
            malformed_payloads.append(payload)

        invalid_relationships = self.eligible_payload()
        invalid_relationships["data"]["relationships"] = []
        malformed_payloads.append(invalid_relationships)

        too_many_included_resources = self.eligible_payload()
        too_many_included_resources["included"] = [{} for _ in range(101)]
        malformed_payloads.append(too_many_included_resources)

        responses = [self.post_patreon(payload) for payload in malformed_payloads]

        self.assertTrue(all(response.status_code == 400 for response in responses))
        self.assertTrue(
            all(response.get_json() == {"error": "invalid_payload"} for response in responses)
        )

    def test_payment_webhooks_are_available_only_on_api_subdomain(self):
        payload = self.eligible_payload()
        raw_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signature = hmac.new(
            main.PATREON_SECRET.encode("utf-8"), raw_body, hashlib.md5
        ).hexdigest()
        wrong_host = self.client.post(
            "/patreon-webhook",
            data=raw_body,
            headers={
                "X-Patreon-Event": "members:pledge:create",
                "X-Patreon-Signature": signature,
            },
            base_url="https://echteralsfake.me",
        )
        old_nowpayments_path = self.client.post(
            "/nowpayments_ipn",
            data=b"{}",
            base_url="https://api.echteralsfake.me",
        )

        self.assertEqual(wrong_host.status_code, 404)
        self.assertEqual(old_nowpayments_path.status_code, 404)

    def test_nowpayments_ipn_uses_hyphenated_api_route(self):
        payload = {"order_id": "NP-test", "payment_status": "waiting"}
        raw_body = json.dumps(payload).encode("utf-8")
        canonical_body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = hmac.new(
            main.NOWPAYMENTS_IPN_SECRET.encode("utf-8"),
            canonical_body,
            hashlib.sha512,
        ).hexdigest()

        response = self.client.post(
            "/nowpayments-ipn",
            data=raw_body,
            headers={"x-nowpayments-sig": signature},
            base_url="https://api.echteralsfake.me",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), "OK")

    def test_nowpayments_payload_types_and_ranges_are_validated_without_coercion(self):
        for payload in (
            {"payment_status": "waiting"},
            {"order_id": 123, "payment_status": "waiting"},
            {"order_id": "NP-test", "payment_id": True},
            {"order_id": "NP-test", "actually_paid": -1},
        ):
            raw_body = json.dumps(payload).encode("utf-8")
            canonical_body = json.dumps(
                payload, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            signature = hmac.new(
                main.NOWPAYMENTS_IPN_SECRET.encode("utf-8"),
                canonical_body,
                hashlib.sha512,
            ).hexdigest()

            with self.subTest(payload=payload):
                response = self.client.post(
                    "/nowpayments-ipn",
                    data=raw_body,
                    headers={"x-nowpayments-sig": signature},
                    base_url="https://api.echteralsfake.me",
                )

                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.get_json(), {"error": "Invalid payload schema"})

    def test_new_crypto_invoices_receive_the_api_subdomain_callback(self):
        class FakeNowPaymentsResponse:
            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return {"id": "invoice-123", "invoice_url": "https://pay.example/invoice-123"}

        with (
            patch.object(main, "NOWPAYMENTS_API_KEY", "test-api-key"),
            patch.object(main.httpx, "post", return_value=FakeNowPaymentsResponse()) as post,
        ):
            response = self.client.post(
                "/create-crypto-payment",
                json={},
                base_url="https://echteralsfake.me",
            )

        self.assertEqual(response.status_code, 200)
        request_payload = post.call_args.kwargs["json"]
        self.assertEqual(
            request_payload["ipn_callback_url"],
            "https://api.echteralsfake.me/nowpayments-ipn",
        )

    def test_email_translation_catalogs_have_matching_keys_and_placeholders(self):
        for language in ("de", "en"):
            catalog_path = os.path.join(
                os.path.dirname(main.__file__), "i18n", f"license_email_{language}.json"
            )
            with open(catalog_path, "r", encoding="utf-8") as catalog_file:
                self.assertIs(json.load(catalog_file)["reviewed"], False)

        catalogs = {
            language: main.load_license_email_catalog(language)
            for language in ("de", "en")
        }
        self.assertEqual(set(catalogs["de"]), set(catalogs["en"]))

        formatter = string.Formatter()
        for key in catalogs["de"]:
            for language in catalogs:
                self.assertNotRegex(catalogs[language][key], r"<[^>]+>")
            placeholders = {
                language: {
                    field_name
                    for _, field_name, _, _ in formatter.parse(catalogs[language][key])
                    if field_name
                }
                for language in catalogs
            }
            self.assertEqual(placeholders["de"], placeholders["en"])

    def test_updated_privacy_pages_render_in_both_languages(self):
        english = self.client.get("/privacy_policy")
        german = self.client.get("/datenschutz")

        self.assertEqual(english.status_code, 200)
        self.assertEqual(german.status_code, 200)
        self.assertIn(b"Patreon Membership and License Delivery", english.data)
        self.assertIn("Patreon-Mitgliedschaft und Lizenzzustellung".encode("utf-8"), german.data)


if __name__ == "__main__":
    unittest.main()
