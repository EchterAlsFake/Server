"""Mollie boundaries: real entitlement only after verified test payment."""

import json
from datetime import timedelta
from unittest.mock import patch

import httpx
from werkzeug.security import generate_password_hash

from _support import ServerTestCase, main
from pf_server.extensions import db, limiter
from pf_server.models import Transaction, License, CryptoLicenseDelivery
from pf_server.mollie_models import MollieCheckout, MollieGrant
from pf_server import mollie_service as mollie

REAL_REQUEST_API = mollie.request_api
PASSWORD_HASH = generate_password_hash("private-test-password")
PROFILE = "pfl_QGqZL2B4xY"


class MollieTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.settings = patch.dict(
            main.app.config,
            MOLLIE_TEST_ENABLED=True,
            MOLLIE_TEST_API_KEY="test_synthetic",
            MOLLIE_PROFILE_ID=PROFILE,
            MOLLIE_TEST_PASSWORD_HASH=PASSWORD_HASH,
            LICENSE_SMTP_HOST="localhost",
            LICENSE_EMAIL_FROM="test@example.com",
            NOWPAYMENTS_SANDBOX=False,
        )
        self.settings.start()
        self.addCleanup(self.settings.stop)
        with main.app.app_context():
            db.session.execute(db.delete(MollieCheckout))
            db.session.execute(db.delete(MollieGrant))
            db.session.commit()
        self.provider = patch.object(mollie, "request_api", side_effect=self.api)
        self.api_mock = self.provider.start()
        self.addCleanup(self.provider.stop)
        self.mail = patch("pf_server.crypto_delivery.send_license_email")
        self.mail_mock = self.mail.start()
        self.addCleanup(self.mail.stop)
        self.status = "open"
        self.change = {}

    def api(self, method, path, **kwargs):
        if method == "POST":
            order = kwargs["json"]["metadata"]["order_id"]
            self.order = order
        return dict(
            resource="payment",
            id="tr_Synthetic123",
            profileId=PROFILE,
            mode="test",
            metadata={"order_id": self.order},
            amount={"currency": "EUR", "value": "29.99"},
            status=self.status,
            _links={
                "checkout": {
                    "href": "https://www.mollie.com/checkout/select-method/Synthetic123"
                }
            },
            **self.change,
        )

    def unlock(self):
        return self.client.post(
            "/mollie/unlock", data={"password": "private-test-password"}
        )

    def form(self):
        with main.app.app_context():
            digest = mollie.offer_digest()
        return dict(
            offer_digest=digest,
            email="tester@example.com",
            country="DE",
            age_terms_accepted="yes",
            withdrawal_accepted="yes",
            test_acknowledged="yes",
        )

    def create(self):
        self.assertEqual(self.unlock().status_code, 303)
        response = self.client.post("/mollie/checkout", data=self.form())
        self.assertEqual(response.status_code, 303)
        with main.app.app_context():
            row = MollieCheckout.query.one()
            return row.session_id

    def reconcile(self, identifier):
        with main.app.app_context():
            return mollie.process_order(identifier, force=True)

    def test_unlock_hides_mollie_until_password_and_preserves_commercial_options(self):
        page = self.client.get("/porn_fetch").get_data(as_text=True)
        self.assertIn("NOWPayments", page)
        self.assertIn("Patreon", page)
        self.assertIn("Tester access", page)
        self.assertNotIn(PASSWORD_HASH, page)
        self.assertEqual(self.client.get("/mollie/test").status_code, 403)
        self.assertEqual(
            self.client.post("/mollie/checkout", data=self.form()).status_code, 403
        )
        self.assertEqual(
            self.client.post("/mollie/unlock", data={"password": "wrong"}).status_code,
            403,
        )
        self.unlock()
        review = self.client.get("/mollie/test")
        self.assertEqual(review.status_code, 200)
        self.assertIn("real lifetime license", review.get_data(as_text=True))
        self.assertIn("no-store", review.headers["Cache-Control"])
        self.assertNotIn('name="refund_method_accepted"', review.get_data(as_text=True))

    def test_invalid_or_disabled_configuration_affects_only_mollie(self):
        for settings in (
            {"MOLLIE_TEST_ENABLED": False},
            {"MOLLIE_TEST_API_KEY": "live_forbidden"},
            {"MOLLIE_PROFILE_ID": ""},
            {"MOLLIE_TEST_PASSWORD_HASH": ""},
        ):
            with patch.dict(main.app.config, settings):
                self.assertEqual(self.unlock().status_code, 404)
                page = self.client.get("/porn_fetch").get_data(as_text=True)
                self.assertNotIn("Tester access", page)
                self.assertIn("NOWPayments", page)
                self.assertIn("Patreon", page)
        self.api_mock.assert_not_called()

    def test_expired_rotated_and_locked_grants_cannot_create(self):
        self.unlock()
        with main.app.app_context():
            row = MollieGrant.query.one()
            row.expires_at = (mollie.now() - timedelta(seconds=1)).isoformat()
            db.session.commit()
        self.assertEqual(
            self.client.post("/mollie/checkout", data=self.form()).status_code, 403
        )
        self.unlock()
        with patch.dict(
            main.app.config, MOLLIE_TEST_PASSWORD_HASH=generate_password_hash("rotated")
        ):
            self.assertEqual(self.client.get("/mollie/test").status_code, 403)
        self.assertEqual(self.client.post("/mollie/lock").status_code, 303)
        self.assertEqual(self.client.get("/mollie/test").status_code, 403)
        self.api_mock.assert_not_called()

    def test_csrf_and_address_rate_limits(self):
        with patch.dict(main.app.config, WTF_CSRF_ENABLED=True):
            self.assertEqual(self.unlock().status_code, 400)
        limiter.enabled = True
        for _ in range(5):
            response = main.app.test_client().post(
                "/mollie/unlock", data={"password": "wrong"}
            )
            self.assertEqual(response.status_code, 403)
        self.assertEqual(
            main.app.test_client()
            .post("/mollie/unlock", data={"password": "wrong"})
            .status_code,
            429,
        )
        limiter.enabled = False

    def test_validated_email_country_consent_and_offer_required(self):
        self.unlock()
        for change in (
            {"email": ""},
            {"country": "XX"},
            {"age_terms_accepted": ""},
            {"withdrawal_accepted": ""},
            {"test_acknowledged": ""},
            {"offer_digest": "stale"},
        ):
            form = dict(self.form(), **change)
            self.assertIn(
                self.client.post("/mollie/checkout", data=form).status_code, (400, 409)
            )
        self.api_mock.assert_not_called()
        with main.app.app_context():
            self.assertEqual(Transaction.query.count(), 0)

    def test_country_mismatch_and_network_failure_fail_closed(self):
        self.unlock()
        self.assertEqual(
            self.client.post(
                "/mollie/checkout", data=dict(self.form(), country="FR")
            ).status_code,
            409,
        )
        self.mock_tor_lookup.return_value = "unavailable"
        self.assertEqual(
            self.client.post("/mollie/checkout", data=self.form()).status_code, 503
        )
        self.api_mock.assert_not_called()

    def test_retry_creates_one_order_and_price_is_server_controlled(self):
        self.unlock()
        form = dict(
            self.form(), amount="0.01", currency="USD", profile_id="pfl_Attacker"
        )
        self.assertEqual(
            self.client.post("/mollie/checkout", data=form).status_code, 303
        )
        self.assertEqual(
            self.client.post("/mollie/checkout", data=form).status_code, 303
        )
        posts = [
            call for call in self.api_mock.call_args_list if call.args[0] == "POST"
        ]
        self.assertEqual(len(posts), 1)
        self.assertEqual(
            posts[0].kwargs["json"]["amount"], {"currency": "EUR", "value": "29.99"}
        )
        self.assertNotIn("tester@example.com", json.dumps(posts[0].kwargs))
        with main.app.app_context():
            self.assertEqual(Transaction.query.count(), 1)
            self.assertEqual(License.query.count(), 0)
            row = MollieCheckout.query.one()
            self.assertEqual(row.country_code, "DE")
            self.assertEqual(row.pricing_version, "lifetime-eur-v1")

    def test_paid_issues_real_license_once_and_sandbox_documents(self):
        identifier = self.create()
        self.status = "paid"
        self.assertTrue(self.reconcile(identifier))
        self.assertTrue(self.reconcile(identifier))
        response = self.client.get(
            "/check-payment-status", query_string={"session_id": identifier}
        )
        self.assertEqual(response.json["status"], "finished")
        self.assertTrue(response.json["license_key"].startswith("key/"))
        self.assertEqual(response.json["delivery_status"], "sent")
        self.assertEqual(
            self.client.get(
                "/download_license", query_string={"session_id": identifier}
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.get(
                "/download_invoice", query_string={"session_id": identifier}
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.get(
                "/download_contract", query_string={"session_id": identifier}
            ).status_code,
            200,
        )
        with main.app.app_context():
            self.assertEqual(License.query.count(), 1)
            transaction = db.session.get(Transaction, identifier)
            data = json.loads(transaction.contract_snapshot)
            self.assertEqual(transaction.environment, "sandbox")
            self.assertEqual(data["refund_terms"], "")
            self.assertFalse(data["refund_method_accepted"])
            self.assertNotIn("tester@example.com", transaction.contract_snapshot)
        self.mail_mock.assert_called_once()
        self.assertEqual(
            self.mail_mock.call_args.kwargs["payment_environment"], "sandbox"
        )

    def test_recovery_binds_order_and_survives_disabling_test_access(self):
        identifier = self.create()
        outsider = main.app.test_client()
        self.assertEqual(
            outsider.get(
                "/buy_success", query_string={"session_id": identifier}
            ).status_code,
            410,
        )
        self.assertEqual(
            outsider.get(
                "/download_license", query_string={"session_id": identifier}
            ).status_code,
            410,
        )
        self.assertEqual(
            self.client.get(
                "/mollie/launch", query_string={"session_id": identifier}
            ).status_code,
            303,
        )
        with patch.dict(main.app.config, MOLLIE_TEST_ENABLED=False):
            self.status = "paid"
            self.assertTrue(self.reconcile(identifier))
            self.assertEqual(
                self.client.get(
                    "/download_license", query_string={"session_id": identifier}
                ).status_code,
                200,
            )
            self.assertEqual(self.unlock().status_code, 404)

    def test_forged_notifications_and_redirect_do_not_issue_license(self):
        identifier = self.create()
        self.assertEqual(
            self.client.get(
                "/buy_success",
                query_string={"session_id": identifier, "status": "paid"},
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                "/mollie/webhook", data={"id": "tr_Synthetic123"}
            ).status_code,
            404,
        )
        calls = self.api_mock.call_count
        for payment_id in (
            "tr_Unknown123",
            "https://attacker.invalid/",
            "tr_Synthetic123",
        ):
            self.assertEqual(
                self.client.post(
                    "/mollie/webhook",
                    data={"id": payment_id, "status": "paid"},
                    base_url=main.app.config["API_DOMAIN"],
                ).status_code,
                200,
            )
        self.assertEqual(self.api_mock.call_count, calls)
        with main.app.app_context():
            self.assertEqual(License.query.count(), 0)
            mollie.process_pending()
            self.assertEqual(License.query.count(), 0)

    def test_all_nonpaid_statuses_withhold_licenses(self):
        identifier = self.create()
        for state in ("authorized", "pending", "failed", "canceled", "expired", "open"):
            self.status = state
            self.assertTrue(self.reconcile(identifier))
            with main.app.app_context():
                self.assertEqual(License.query.count(), 0)
                self.assertEqual(
                    db.session.get(Transaction, identifier).status, "pending"
                )

    def test_authenticated_response_must_match_entire_order(self):
        identifier = self.create()
        original_api = self.api
        self.status = "paid"
        changes = (
            {"mode": "live"},
            {"profileId": "pfl_Wrong"},
            {"metadata": {"order_id": "wrong"}},
            {"amount": {"currency": "EUR", "value": "0.01"}},
            {"amount": {"currency": "USD", "value": "29.99"}},
            {"id": "tr_Wrong123"},
            {"status": "unknown"},
        )
        for change in changes:

            def corrupt(*args, **kwargs):
                return dict(original_api(*args, **kwargs), **change)

            self.api_mock.side_effect = corrupt
            self.assertFalse(self.reconcile(identifier))
            with main.app.app_context():
                self.assertEqual(License.query.count(), 0)
                self.assertEqual(
                    db.session.get(Transaction, identifier).status, "pending"
                )

    def test_creation_timeout_retries_same_payload_and_key_then_stops_before_expiry(
        self,
    ):
        self.unlock()
        self.api_mock.side_effect = httpx.ReadTimeout("synthetic timeout")
        self.assertEqual(
            self.client.post("/mollie/checkout", data=self.form()).status_code, 303
        )
        first = self.api_mock.call_args
        with main.app.app_context():
            row = MollieCheckout.query.one()
            identifier = row.session_id
        self.reconcile(identifier)
        self.assertEqual(first, self.api_mock.call_args)
        with main.app.app_context():
            row = db.session.get(MollieCheckout, identifier)
            row.first_attempt_at = (mollie.now() - timedelta(minutes=56)).isoformat()
            db.session.commit()
        count = self.api_mock.call_count
        self.assertFalse(self.reconcile(identifier))
        self.assertEqual(self.api_mock.call_count, count)
        with main.app.app_context():
            self.assertEqual(db.session.get(MollieCheckout, identifier).state, "review")

    def test_keygen_and_mail_outages_retry_without_duplicate_entitlement(self):
        from pf_server.keygen_service import KeygenUnavailable

        identifier = self.create()
        self.status = "paid"
        with patch(
            "pf_server.licensing.ensure_license",
            side_effect=KeygenUnavailable("synthetic outage"),
        ):
            self.assertFalse(self.reconcile(identifier))
        self.mail_mock.side_effect = RuntimeError("synthetic SMTP outage")
        self.assertTrue(self.reconcile(identifier))
        self.mail_mock.side_effect = None
        with main.app.app_context():
            mollie.process_pending()
            self.assertEqual(License.query.count(), 1)
            self.assertEqual(
                db.session.get(CryptoLicenseDelivery, identifier).delivery_status,
                "sent",
            )

    def test_refunds_and_chargebacks_recorded_without_revocation(self):
        identifier = self.create()
        self.status = "paid"
        self.reconcile(identifier)
        self.change = {
            "amountRefunded": {"currency": "EUR", "value": "29.99"},
            "amountChargedBack": {"currency": "EUR", "value": "29.99"},
        }
        self.assertTrue(self.reconcile(identifier))
        with main.app.app_context():
            self.assertEqual(License.query.one().state, "valid")
            self.assertEqual(db.session.get(Transaction, identifier).status, "finished")
            self.assertEqual(
                db.session.get(MollieCheckout, identifier).refunded_amount, "29.99"
            )
            self.assertEqual(
                db.session.get(MollieCheckout, identifier).chargeback_amount, "29.99"
            )

    def test_worker_lease_prevents_overlapping_processing(self):
        identifier = self.create()
        self.status = "paid"
        with main.app.app_context():
            row = db.session.get(MollieCheckout, identifier)
            row.lease_token = "other-worker"
            row.lease_expires_at = (mollie.now() + timedelta(minutes=1)).isoformat()
            db.session.commit()
        count = self.api_mock.call_count
        self.assertFalse(self.reconcile(identifier))
        self.assertEqual(self.api_mock.call_count, count)
        with main.app.app_context():
            self.assertEqual(License.query.count(), 0)

    def test_url_and_credential_validation(self):
        for url in (
            "https://attacker.invalid/checkout/a",
            "https://www.mollie.com.evil/checkout/a",
            "http://www.mollie.com/checkout/a",
            "https://user@www.mollie.com/checkout/a",
            "https://www.mollie.com:444/checkout/a",
            "https://www.mollie.com/dashboard",
        ):
            self.assertIsNone(mollie.checkout_url(url))
        with main.app.app_context(), patch.object(mollie.httpx, "request") as request:
            with patch.dict(main.app.config, MOLLIE_TEST_API_KEY="live_rejected"):
                with self.assertRaises(ValueError):
                    REAL_REQUEST_API("GET", "/payments/tr_Test")
                request.assert_not_called()

    def test_creation_read_requires_authenticated_paid_result(self):
        self.unlock()
        original = self.api

        def create_paid_read_open(method, path, **kwargs):
            data = original(method, path, **kwargs)
            data["status"] = "paid" if method == "POST" else "open"
            return data

        self.api_mock.side_effect = create_paid_read_open
        self.client.post("/mollie/checkout", data=self.form())
        with main.app.app_context():
            self.assertEqual(License.query.count(), 0)

    def test_order_resumes_even_if_first_response_cookie_is_lost(self):
        self.unlock()
        with self.client.session_transaction() as browser:
            original_grant = browser["mollie_grant"]
        response = self.client.post("/mollie/checkout", data=self.form())
        self.assertEqual(response.status_code, 303)
        with self.client.session_transaction() as browser:
            browser.pop("checkout_recovery")
            browser["mollie_grant"] = original_grant
        self.assertEqual(self.client.post("/mollie/checkout", data={}).status_code, 303)
        self.assertEqual(self.client.get(response.location).status_code, 200)
        with main.app.app_context():
            self.assertEqual(Transaction.query.count(), 1)

    def test_nowpayments_paths_cannot_finish_a_mollie_order(self):
        from pf_server.nowpayments_service import _validate_finished_payment
        from pf_server.webhook_models import NowPaymentsWebhook

        identifier = self.create()
        with main.app.app_context():
            transaction = db.session.get(Transaction, identifier)
            self.assertEqual(
                _validate_finished_payment(
                    transaction,
                    NowPaymentsWebhook.from_mapping(
                        {
                            "payment_id": "tr_Synthetic123",
                            "order_id": identifier,
                            "payment_status": "finished",
                            "price_amount": 29.99,
                            "price_currency": "eur",
                        }
                    ),
                ),
                "provider_mismatch",
            )
        with patch.dict(
            main.app.config,
            NOWPAYMENTS_SANDBOX=True,
            NOWPAYMENTS_LOCAL_SIMULATION_ENABLED=True,
        ):
            self.assertEqual(
                self.client.post(
                    "/simulate-payment-success", json={"session_id": identifier}
                ).status_code,
                404,
            )
        with main.app.app_context():
            self.assertEqual(License.query.count(), 0)

    def test_reversal_before_fulfillment_withholds_new_entitlement(self):
        identifier = self.create()
        self.status = "paid"
        self.change = {"amountRefunded": {"currency": "EUR", "value": "29.99"}}
        self.assertTrue(self.reconcile(identifier))
        with main.app.app_context():
            self.assertEqual(License.query.count(), 0)

    def test_live_http_adapter_uses_test_key_and_never_follows_redirects(self):
        response = httpx.Response(
            200, json={"resource": "payment"}, request=httpx.Request("GET", mollie.API)
        )
        with (
            main.app.app_context(),
            patch.object(mollie.httpx, "request", return_value=response) as request,
        ):
            REAL_REQUEST_API("GET", "/payments/tr_Test")
            self.assertEqual(
                request.call_args.kwargs["headers"]["Authorization"],
                "Bearer test_synthetic",
            )
            self.assertFalse(request.call_args.kwargs["follow_redirects"])
            self.assertEqual(
                request.call_args.args[1], "https://api.mollie.com/v2/payments/tr_Test"
            )

    def test_notification_during_processing_is_not_lost(self):
        identifier = self.create()
        self.status = "paid"
        self.reconcile(identifier)
        original = self.api

        def notify_during_read(*args, **kwargs):
            result = original(*args, **kwargs)
            db.session.execute(
                db.update(MollieCheckout)
                .where(MollieCheckout.session_id == identifier)
                .values(notification_version=MollieCheckout.notification_version + 1)
            )
            db.session.commit()
            return result

        self.api_mock.side_effect = notify_during_read
        self.reconcile(identifier)
        self.api_mock.side_effect = original
        with main.app.app_context():
            row = db.session.get(MollieCheckout, identifier)
            self.assertGreater(
                row.notification_version, row.processed_notification_version
            )
            row.next_attempt_at = mollie.now().isoformat()
            db.session.commit()
            self.assertEqual(mollie.process_pending(), 1)
            db.session.refresh(row)
            self.assertEqual(
                row.notification_version, row.processed_notification_version
            )

    def test_simultaneous_requests_consume_only_one_grant(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        from flask import session
        from pf_server.country_service import CheckoutCountryDecision

        self.unlock()
        with self.client.session_transaction() as browser:
            token = browser["mollie_grant"]
        barrier = Barrier(2)
        decision = CheckoutCountryDecision(
            status="verified",
            country_name="Germany",
            evidence_source="local",
            database_label="test",
        )

        def reserve():
            with main.app.test_request_context("/mollie/checkout"):
                session["mollie_grant"] = token
                access = mollie.grant()
                barrier.wait(timeout=5)
                return mollie.reserve(access, decision, "DE", "tester@example.com")

        with ThreadPoolExecutor(max_workers=2) as executor:
            identifiers = list(executor.map(lambda _: reserve(), range(2)))
        self.assertEqual(identifiers[0], identifiers[1])
        with main.app.app_context():
            self.assertEqual(MollieCheckout.query.count(), 1)
            self.assertEqual(Transaction.query.count(), 1)

    def test_live_checkout_is_public_primary_and_uses_production_documents(self):
        original = self.api
        self.api_mock.side_effect = lambda *a, **kw: dict(
            original(*a, **kw), mode="live"
        )
        with patch.dict(
            main.app.config,
            MOLLIE_LIVE_ENABLED=True,
            MOLLIE_LIVE_API_KEY="live_synthetic",
        ):
            page = self.client.get("/porn_fetch")
            self.assertEqual(page.status_code, 200)
            self.assertIn('id="premium-form"', page.text)
            self.assertIn("Pay · €29.99", page.text)
            self.assertNotIn("sandbox", page.text.lower())
            self.assertNotIn('name="test_acknowledged"', page.text)
            form = self.form()
            form.pop("test_acknowledged")
            response = self.client.post(
                "/mollie/checkout", data=form, headers={"Accept": "application/json"}
            )
            self.assertEqual(response.status_code, 200)
            self.status = "paid"
            self.reconcile(self.order)
            with main.app.app_context():
                from pf_server.invoice_service import load_invoice

                transaction = db.session.get(Transaction, self.order)
                self.assertEqual(transaction.environment, "production")
                self.assertNotIn("No money is charged", transaction.contract_snapshot)
                invoice = load_invoice(self.order)
                self.assertEqual(invoice["Environment"], "production")
                self.assertTrue(invoice["Invoice Number"].startswith("INV-ML-"))
            self.assertEqual(
                self.mail_mock.call_args.kwargs["payment_environment"], "production"
            )
            tracking = self.client.get(response.json["next"]).text
            self.assertNotIn("Mollie sandbox", tracking)
            self.assertNotIn("no money is charged", tracking.lower())
            for call in self.api_mock.call_args_list:
                self.assertEqual(call.kwargs["environment"], "production")

    def test_live_activation_requires_both_live_flag_and_live_key(self):
        for settings in (
            {"MOLLIE_LIVE_ENABLED": True, "MOLLIE_LIVE_API_KEY": "test_wrong"},
            {"MOLLIE_LIVE_ENABLED": False, "MOLLIE_LIVE_API_KEY": "live_synthetic"},
        ):
            with patch.dict(main.app.config, settings):
                self.assertNotIn(
                    'id="premium-form"', self.client.get("/porn_fetch").text
                )

    def test_existing_sandbox_order_retains_environment_after_live_activation(self):
        identifier = self.create()
        self.status = "paid"
        self.api_mock.reset_mock()
        with patch.dict(
            main.app.config,
            MOLLIE_LIVE_ENABLED=True,
            MOLLIE_LIVE_API_KEY="live_synthetic",
        ):
            self.assertTrue(self.reconcile(identifier))
            self.assertEqual(self.api_mock.call_args.kwargs["environment"], "sandbox")
            self.assertEqual(
                self.mail_mock.call_args.kwargs["payment_environment"], "sandbox"
            )
            self.assertIn(
                "Mollie sandbox",
                self.client.get(
                    "/buy_success", query_string={"session_id": identifier}
                ).text,
            )

    def test_live_order_rejects_sandbox_response(self):
        with patch.dict(
            main.app.config,
            MOLLIE_LIVE_ENABLED=True,
            MOLLIE_LIVE_API_KEY="live_synthetic",
        ):
            self.client.get("/porn_fetch")
            self.status = "paid"
            self.client.post("/mollie/checkout", data=self.form())
            with main.app.app_context():
                self.assertEqual(License.query.count(), 0)
                self.assertEqual(Transaction.query.one().status, "pending")

    def test_live_http_adapter_uses_only_live_credential(self):
        response = httpx.Response(
            200, json={"resource": "payment"}, request=httpx.Request("GET", mollie.API)
        )
        with (
            main.app.app_context(),
            patch.dict(main.app.config, MOLLIE_LIVE_API_KEY="live_synthetic"),
            patch.object(mollie.httpx, "request", return_value=response) as request,
        ):
            REAL_REQUEST_API("GET", "/payments/tr_Test", environment="production")
            self.assertEqual(
                request.call_args.kwargs["headers"]["Authorization"],
                "Bearer live_synthetic",
            )
