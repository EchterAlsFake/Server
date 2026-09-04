"""Patreon webhook eligibility and idempotent delivery tests."""

import json
from unittest.mock import patch

from _support import ServerTestCase, main

import pf_server.patreon_service as patreon_service
from pf_server.models import License, PatreonLicenseDelivery


class PatreonWebhookTests(ServerTestCase):
    def test_patreon_signature_is_checked_before_processing(self):
        response = self.post_patreon(
            self.eligible_patreon_payload(), secret="wrong-secret"
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json(), {"error": "invalid_signature"})
        with main.app.app_context():
            self.assertEqual(PatreonLicenseDelivery.query.count(), 0)
            self.assertEqual(License.query.count(), 0)

    def test_paid_member_receives_one_signed_license_for_both_events(self):
        deliveries = []

        def capture_email(recipient, license_file):
            deliveries.append((recipient, license_file))

        payload = self.eligible_patreon_payload()
        with patch.object(
            patreon_service,
            "send_license_email",
            side_effect=capture_email,
        ):
            first = self.post_patreon(payload, event="members:create")
            duplicate = self.post_patreon(payload, event="members:pledge:create")
            paid_update = self.post_patreon(payload, event="members:update")
            pledge_update = self.post_patreon(payload, event="members:pledge:update")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(duplicate.status_code, 200)
        self.assertEqual(paid_update.status_code, 200)
        self.assertEqual(pledge_update.status_code, 200)
        self.assertEqual(len(deliveries), 1)
        self.assertEqual(deliveries[0][0], "member@example.com")
        license_payload = json.loads(deliveries[0][1])
        self.assertEqual(license_payload["product"], "porn-fetch")
        self.assertEqual(license_payload["features"], ["full_unlock"])
        self.assertTrue(license_payload["issuance_reference"].startswith("PT-"))
        self.assertNotIn("stripe_session_id", license_payload)
        self.assertNotIn("member@example.com", deliveries[0][1].decode("utf-8"))

        with main.app.app_context():
            delivery = main.db.session.get(PatreonLicenseDelivery, "member-123")
            self.assertEqual(delivery.status, "sent")
            self.assertIsNotNone(delivery.sent_at)
            self.assertEqual(License.query.count(), 1)
            self.assertFalse(hasattr(delivery, "email"))

    def test_failed_email_is_retried_with_the_same_license(self):
        attempted_files = []

        def fail_once(_recipient, license_file):
            attempted_files.append(license_file)
            if len(attempted_files) == 1:
                raise RuntimeError("simulated SMTP failure")

        with patch.object(
            patreon_service,
            "send_license_email",
            side_effect=fail_once,
        ):
            failed = self.post_patreon(self.eligible_patreon_payload())
            retried = self.post_patreon(self.eligible_patreon_payload())

        self.assertEqual(failed.status_code, 503)
        self.assertEqual(retried.status_code, 200)
        self.assertEqual(len(attempted_files), 2)
        self.assertEqual(attempted_files[0], attempted_files[1])
        with main.app.app_context():
            delivery = main.db.session.get(PatreonLicenseDelivery, "member-123")
            self.assertEqual(delivery.status, "sent")
            self.assertEqual(License.query.count(), 1)

    def test_busy_delivery_requests_retry_and_a_stale_lease_is_recovered(self):
        with main.app.app_context():
            main.db.session.add(
                PatreonLicenseDelivery(
                    member_id="member-123",
                    status="sending",
                    created_at="2026-01-01T00:00:00+00:00",
                    updated_at="2026-01-01T00:00:00+00:00",
                    lease_expires_at="2999-01-01T00:00:00+00:00",
                )
            )
            main.db.session.commit()

        with patch.object(patreon_service, "send_license_email") as send_email:
            busy = self.post_patreon(self.eligible_patreon_payload())
            with main.app.app_context():
                delivery = main.db.session.get(PatreonLicenseDelivery, "member-123")
                delivery.lease_expires_at = "2000-01-01T00:00:00+00:00"
                main.db.session.commit()
            recovered = self.post_patreon(self.eligible_patreon_payload())

        self.assertEqual(busy.status_code, 503)
        self.assertEqual(busy.headers["Retry-After"], "30")
        self.assertEqual(recovered.status_code, 200)
        send_email.assert_called_once()

    def test_free_declined_and_gifted_members_do_not_receive_a_license(self):
        payloads = []
        for change in (
            {
                "currently_entitled_amount_cents": 0,
                "last_charge_status": None,
                "patron_status": None,
            },
            {"last_charge_status": "Declined", "patron_status": "declined_patron"},
            {"is_gifted": True},
        ):
            payload = self.eligible_patreon_payload(member_id=f"member-{len(payloads)}")
            payload["data"]["attributes"].update(change)
            payloads.append(payload)

        with patch.object(patreon_service, "send_license_email") as send_email:
            responses = [self.post_patreon(payload) for payload in payloads]

        self.assertTrue(all(response.status_code == 200 for response in responses))
        self.assertTrue(
            all(
                response.get_json() == {"status": "not_eligible"}
                for response in responses
            )
        )
        send_email.assert_not_called()
        with main.app.app_context():
            self.assertEqual(PatreonLicenseDelivery.query.count(), 0)

    def test_paid_member_update_delivers_after_an_initial_pending_charge(self):
        pending = self.eligible_patreon_payload()
        pending["data"]["attributes"].update(
            {"last_charge_status": "Pending", "patron_status": "active_patron"}
        )
        initial_response = self.post_patreon(pending, event="members:pledge:create")

        with patch.object(patreon_service, "send_license_email") as send_email:
            paid_response = self.post_patreon(
                self.eligible_patreon_payload(), event="members:update"
            )

        self.assertEqual(initial_response.get_json(), {"status": "not_eligible"})
        self.assertEqual(paid_response.status_code, 200)
        send_email.assert_called_once()

    def test_configured_tier_allow_list_is_enforced(self):
        with (
            patch.dict(
                main.app.config,
                {"PATREON_LICENSE_TIER_IDS": frozenset({"different-tier"})},
            ),
            patch.object(patreon_service, "send_license_email") as send_email,
        ):
            response = self.post_patreon(self.eligible_patreon_payload())

        self.assertEqual(response.get_json(), {"status": "not_eligible"})
        send_email.assert_not_called()
        with main.app.app_context():
            self.assertEqual(PatreonLicenseDelivery.query.count(), 0)

    def test_missing_email_and_unrelated_event_are_acknowledged_without_storage(self):
        missing_email = self.eligible_patreon_payload(email=None)
        no_email_response = self.post_patreon(missing_email)
        unrelated_response = self.post_patreon(
            self.eligible_patreon_payload(),
            event="members:pledge:delete",
        )

        self.assertEqual(no_email_response.get_json(), {"status": "email_unavailable"})
        self.assertEqual(unrelated_response.get_json(), {"status": "ignored_event"})
        with main.app.app_context():
            self.assertEqual(PatreonLicenseDelivery.query.count(), 0)

    def test_invalid_member_identifier_is_rejected_before_database_access(self):
        response = self.post_patreon(
            self.eligible_patreon_payload(member_id="'; DROP TABLE license; --")
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json(), {"error": "invalid_payload"})
        with main.app.app_context():
            self.assertEqual(License.query.count(), 0)

    def test_patreon_payload_types_are_validated_without_coercion(self):
        malformed_payloads = []
        for field_name, invalid_value in (
            ("currently_entitled_amount_cents", True),
            ("is_free_trial", "false"),
        ):
            payload = self.eligible_patreon_payload()
            payload["data"]["attributes"][field_name] = invalid_value
            malformed_payloads.append(payload)

        invalid_relationships = self.eligible_patreon_payload()
        invalid_relationships["data"]["relationships"] = []
        malformed_payloads.append(invalid_relationships)

        too_many_included_resources = self.eligible_patreon_payload()
        too_many_included_resources["included"] = [{} for _ in range(101)]
        malformed_payloads.append(too_many_included_resources)

        responses = [self.post_patreon(payload) for payload in malformed_payloads]
        self.assertTrue(all(response.status_code == 400 for response in responses))
        self.assertTrue(
            all(
                response.get_json() == {"error": "invalid_payload"}
                for response in responses
            )
        )
