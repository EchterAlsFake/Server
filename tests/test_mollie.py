"""Retired Mollie cannot be re-enabled by stale production configuration."""

from unittest.mock import patch
from _support import ServerTestCase, main
from pf_server import mollie_service


class MollieRetirementTests(ServerTestCase):
    def test_stale_credentials_cannot_reopen_checkout(self):
        with patch.dict(
            main.app.config,
            MOLLIE_LIVE_ENABLED=True,
            MOLLIE_TEST_ENABLED=True,
            MOLLIE_LIVE_API_KEY="live_old",
            MOLLIE_TEST_API_KEY="test_old",
            MOLLIE_PROFILE_ID="pfl_Old",
        ):
            with main.app.app_context():
                self.assertFalse(mollie_service.enabled())
                self.assertFalse(mollie_service.live_enabled())
            page = self.client.get("/porn_fetch")
            self.assertEqual(page.status_code, 200)
            self.assertNotIn("via Mollie", page.text)
            self.assertNotIn("Unlock Mollie", page.text)
            for path in ("/mollie/test", "/mollie/launch"):
                self.assertIn(self.client.get(path).status_code, (404, 410))
            for path in ("/mollie/unlock", "/mollie/checkout"):
                self.assertEqual(self.client.post(path).status_code, 404)

    def test_worker_does_not_create_queued_mollie_payments(self):
        from pf_server.extensions import db
        from pf_server.models import Transaction
        from pf_server.mollie_models import MollieCheckout

        with main.app.app_context():
            stamp = mollie_service.now().isoformat()
            db.session.add(Transaction(session_id="retired-order", provider="mollie",
                provider_payment_id="mollie-pending-retired-order", provider_reference_type="payment",
                expected_price_amount="29.99", expected_price_currency="EUR", customer_country="Germany",
                country_evidence="local", geolocation_database="test", created_at=stamp))
            db.session.add(MollieCheckout(session_id="retired-order", profile_id="pfl_Old", payload="{}",
                idempotency_key="retired-key", pricing_version="v1", country_code="DE", next_attempt_at=stamp))
            db.session.commit()
            with patch.object(mollie_service, "request_api") as provider:
                self.assertFalse(mollie_service.process_order("retired-order", force=True))
                provider.assert_not_called()
            self.assertEqual(db.session.get(MollieCheckout, "retired-order").last_error, "provider_retired")
