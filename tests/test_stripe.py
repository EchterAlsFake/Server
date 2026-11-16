"""Stripe boundaries: real entitlement only after verified test payment."""

import json
from datetime import timedelta
from unittest.mock import patch

import httpx
from werkzeug.security import generate_password_hash

from _support import ServerTestCase, main
from pf_server.extensions import db, limiter
from pf_server.models import Transaction, License, CryptoLicenseDelivery
from pf_server.stripe_models import StripeCheckout, StripeGrant
from pf_server import stripe_service as stripe

REAL_REQUEST_API = stripe.request_api
PASSWORD_HASH = generate_password_hash("private-test-password")
ACCOUNT = "acct_Synthetic"


class StripeTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.settings = patch.dict(
            main.app.config,
            STRIPE_TEST_ENABLED=True,
            STRIPE_TEST_API_KEY="sk_test_synthetic",
            STRIPE_ACCOUNT_ID=ACCOUNT,
            STRIPE_TEST_PASSWORD_HASH=PASSWORD_HASH,
            STRIPE_TEST_WEBHOOK_SECRET="whsec_test",
            STRIPE_LIVE_WEBHOOK_SECRET="whsec_live",
            LICENSE_SMTP_HOST="localhost",
            LICENSE_EMAIL_FROM="test@example.com",
            NOWPAYMENTS_SANDBOX=False,
        )
        self.settings.start()
        self.addCleanup(self.settings.stop)
        with main.app.app_context():
            db.session.execute(db.delete(StripeCheckout))
            db.session.execute(db.delete(StripeGrant))
            db.session.commit()
        self.provider = patch.object(stripe, "request_api", side_effect=self.api)
        self.api_mock = self.provider.start()
        self.addCleanup(self.provider.stop)
        self.mail = patch("pf_server.crypto_delivery.send_license_email")
        self.mail_mock = self.mail.start()
        self.addCleanup(self.mail.stop)
        self.status = "open"
        self.change = {}
        self.orders = {}

    def api(self, method, path, **kwargs):
        environment = kwargs.get("environment", "sandbox")
        if path == "/account":
            return {"id": ACCOUNT}
        if method == "POST":
            self.order = kwargs["json"]["metadata"]["order_id"]
            self.orders[environment] = self.order
        order = self.orders.get(environment, self.order)
        return (
            dict(
                object="checkout.session",
                id="cs_live_Synthetic123"
                if environment == "production"
                else "cs_test_Synthetic123",
                livemode=environment == "production",
                mode="payment",
                managed_payments={"enabled": True},
                metadata={"order_id": order},
                client_reference_id=order,
                amount_total=2999,
                currency="eur",
                status="complete" if self.status == "paid" else self.status,
                payment_status="paid" if self.status == "paid" else "unpaid",
                url="https://checkout.stripe.com/c/pay/cs_test_Synthetic123",
                invoice={
                    "id": "in_Synthetic",
                    "number": "STRIPE-123",
                    "hosted_invoice_url": "https://invoice.stripe.com/i/Synthetic",
                    "invoice_pdf": "https://invoice.stripe.com/i/Synthetic/pdf",
                },
                payment_intent={
                    "id": "pi_Synthetic123",
                    "status": "succeeded",
                    "latest_charge": {
                        "paid": True,
                        "amount": 2999,
                        "currency": "eur",
                        "amount_refunded": 0,
                        "disputed": False,
                    },
                },
            )
            | self.change
        )

    def unlock(self):
        return self.client.post(
            "/stripe/unlock", data={"password": "private-test-password"}
        )

    def form(self, *, sandbox=False):
        from flask import g

        with main.app.test_request_context():
            g.stripe_sandbox_checkout = sandbox
            digest = stripe.offer_digest()
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
        response = self.client.post("/stripe/checkout", data=self.form())
        self.assertEqual(response.status_code, 303)
        with main.app.app_context():
            row = StripeCheckout.query.one()
            return row.session_id

    def reconcile(self, identifier):
        with main.app.app_context():
            return stripe.process_order(identifier, force=True)

    def test_invalid_or_disabled_configuration_affects_only_stripe(self):
        for settings in (
            {"STRIPE_TEST_ENABLED": False},
            {"STRIPE_TEST_API_KEY": "live_forbidden"},
            {"STRIPE_ACCOUNT_ID": ""},
            {"STRIPE_TEST_PASSWORD_HASH": ""},
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
            row = StripeGrant.query.one()
            row.expires_at = (stripe.now() - timedelta(seconds=1)).isoformat()
            db.session.commit()
        self.assertEqual(
            self.client.post("/stripe/checkout", data=self.form()).status_code, 403
        )
        self.unlock()
        with patch.dict(
            main.app.config, STRIPE_TEST_PASSWORD_HASH=generate_password_hash("rotated")
        ):
            self.assertIn("Tester password", self.client.get("/stripe/test").text)
        self.assertEqual(self.client.post("/stripe/lock").status_code, 303)
        self.assertIn("Tester password", self.client.get("/stripe/test").text)
        self.api_mock.assert_not_called()

    def test_csrf_and_address_rate_limits(self):
        with patch.dict(main.app.config, WTF_CSRF_ENABLED=True):
            self.assertEqual(self.unlock().status_code, 400)
        limiter.enabled = True
        for _ in range(5):
            response = main.app.test_client().post(
                "/stripe/unlock", data={"password": "wrong"}
            )
            self.assertEqual(response.status_code, 403)
        self.assertEqual(
            main.app.test_client()
            .post("/stripe/unlock", data={"password": "wrong"})
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
                self.client.post("/stripe/checkout", data=form).status_code, (400, 409)
            )
        self.api_mock.assert_not_called()
        with main.app.app_context():
            self.assertEqual(Transaction.query.count(), 0)

    def test_country_mismatch_and_network_failure_fail_closed(self):
        self.unlock()
        self.assertEqual(
            self.client.post(
                "/stripe/checkout", data=dict(self.form(), country="FR")
            ).status_code,
            409,
        )
        self.mock_tor_lookup.return_value = "unavailable"
        self.assertEqual(
            self.client.post("/stripe/checkout", data=self.form()).status_code, 503
        )
        self.api_mock.assert_not_called()

    def test_retry_creates_one_order_and_price_is_server_controlled(self):
        self.unlock()
        form = dict(
            self.form(), amount="0.01", currency="USD", account_id="pfl_Attacker"
        )
        self.assertEqual(
            self.client.post("/stripe/checkout", data=form).status_code, 303
        )
        self.assertEqual(
            self.client.post("/stripe/checkout", data=form).status_code, 303
        )
        posts = [
            call for call in self.api_mock.call_args_list if call.args[0] == "POST"
        ]
        self.assertEqual(len(posts), 1)
        self.assertEqual(
            posts[0].kwargs["json"]["line_items"][0]["price_data"]["unit_amount"], 2999
        )
        self.assertNotIn("tester@example.com", json.dumps(posts[0].kwargs))
        payload = posts[0].kwargs["json"]
        self.assertEqual(payload["managed_payments"], {"enabled": True})
        price = payload["line_items"][0]["price_data"]
        self.assertEqual(price["tax_behavior"], "inclusive")
        self.assertEqual(price["product_data"]["tax_code"], "txcd_10202000")
        self.assertNotIn("payment_method_types", payload)
        self.assertNotIn("automatic_tax", payload)
        with main.app.app_context():
            self.assertEqual(Transaction.query.count(), 1)
            self.assertEqual(License.query.count(), 0)
            row = StripeCheckout.query.one()
            self.assertEqual(row.country_code, "DE")
            self.assertEqual(row.pricing_version, "lifetime-eur-managed-v1")

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
        invoice_response = self.client.get(
            "/download_invoice", query_string={"session_id": identifier}
        )
        self.assertEqual(invoice_response.status_code, 303)
        self.assertEqual(
            invoice_response.location, "https://invoice.stripe.com/i/Synthetic/pdf"
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
        self.assertIsNone(self.mail_mock.call_args.kwargs["invoice"])
        self.assertIsNone(self.mail_mock.call_args.kwargs["invoice"])
        self.assertEqual(
            self.mail_mock.call_args.kwargs["payment_environment"], "sandbox"
        )

    def test_managed_checkout_cannot_silently_become_an_unmanaged_payment(self):
        identifier = self.create()
        self.status = "paid"
        self.change = {"managed_payments": {"enabled": False}}
        self.assertFalse(self.reconcile(identifier))
        with main.app.app_context():
            self.assertEqual(License.query.count(), 0)

    def test_managed_invoice_delay_does_not_block_license_or_create_seller_invoice(
        self,
    ):
        from pf_server.invoice_service import load_invoice

        identifier = self.create()
        self.status = "paid"
        self.change = {"invoice": None}
        with patch(
            "pf_server.invoice_service.build_invoice",
            side_effect=AssertionError("Stripe issues the invoice"),
        ):
            self.assertTrue(self.reconcile(identifier))
        response = self.client.get(
            "/download_invoice", query_string={"session_id": identifier}
        )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.headers["Retry-After"], "30")
        with main.app.app_context():
            self.assertEqual(License.query.count(), 1)
            document = load_invoice(identifier)
            self.assertEqual(document["Document Type"], stripe.MANAGED_RECEIPT)
            self.assertNotIn("Tax Info", document)
            self.assertNotIn("VAT ID", document)
        self.assertIsNone(self.mail_mock.call_args.kwargs["invoice"])
        self.change = {}
        response = self.client.get(
            "/download_invoice", query_string={"session_id": identifier}
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            response.location, "https://invoice.stripe.com/i/Synthetic/pdf"
        )
        self.mail_mock.assert_called_once()

    def test_managed_invoice_links_cannot_redirect_to_untrusted_hosts(self):
        identifier = self.create()
        self.status = "paid"
        for url in (
            "https://evil.example/invoice",
            "https://invoice.stripe.com.evil.example/pdf",
            "https://invoice.stripe.com@evil.example/pdf",
            "http://invoice.stripe.com/pdf",
        ):
            self.change = {"invoice": {"invoice_pdf": url, "hosted_invoice_url": url}}
            self.assertTrue(self.reconcile(identifier))
            response = self.client.get(
                "/download_invoice", query_string={"session_id": identifier}
            )
            self.assertEqual(response.status_code, 503)
            self.assertNotIn("Location", response.headers)

    def test_legacy_stripe_order_keeps_its_original_invoice_flow(self):
        identifier = self.create()
        with main.app.app_context():
            row = db.session.get(StripeCheckout, identifier)
            payload = json.loads(row.payload)
            payload.pop("managed_payments")
            row.payload = json.dumps(payload)
            db.session.commit()
        self.status = "paid"
        self.change = {"managed_payments": {"enabled": False}}
        self.assertTrue(self.reconcile(identifier))
        response = self.client.get(
            "/download_invoice", query_string={"session_id": identifier}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/pdf")
        self.assertIsNotNone(self.mail_mock.call_args.kwargs["invoice"])

    def test_managed_terms_and_checkout_do_not_claim_small_business_invoice_exemption(
        self,
    ):
        self.unlock()
        for path in (
            "/stripe/test",
            "/terms?method=stripe",
            "/refund_policy?method=stripe",
        ):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertIn("Link", response.text)
            self.assertNotIn("payment through Mollie", response.text)
            self.assertNotIn("small-business tax exemption", response.text)
        with main.app.app_context():
            saved = json.loads(stripe.snapshot("DE", stripe.now().isoformat()))
            self.assertIn("merchant of record", saved["terms_en"])
            self.assertNotIn("small-business tax exemption", saved["product"])

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
                "/stripe/launch", query_string={"session_id": identifier}
            ).status_code,
            303,
        )
        with patch.dict(main.app.config, STRIPE_TEST_ENABLED=False):
            self.status = "paid"
            self.assertTrue(self.reconcile(identifier))
            self.assertEqual(
                self.client.get(
                    "/download_license", query_string={"session_id": identifier}
                ).status_code,
                200,
            )
            self.assertEqual(self.unlock().status_code, 404)

    def test_all_nonpaid_statuses_withhold_licenses(self):
        identifier = self.create()
        for state in ("open", "expired"):
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
            {"livemode": True},
            {"metadata": {"order_id": "wrong"}},
            {"amount_total": 1},
            {"currency": "usd"},
            {"id": "cs_test_Wrong123"},
            {"status": "unknown"},
            {"client_reference_id": "wrong"},
            {"mode": "subscription"},
            {"managed_payments": {"enabled": False}},
        )
        for change in changes:

            def corrupt(*args, **kwargs):
                return original_api(*args, **kwargs) | change

            self.api_mock.side_effect = corrupt
            self.assertFalse(self.reconcile(identifier))
            with main.app.app_context():
                self.assertEqual(License.query.count(), 0)
                self.assertEqual(
                    db.session.get(Transaction, identifier).status, "pending"
                )

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
            stripe.process_pending()
            self.assertEqual(License.query.count(), 1)
            self.assertEqual(
                db.session.get(CryptoLicenseDelivery, identifier).delivery_status,
                "sent",
            )

    def test_worker_lease_prevents_overlapping_processing(self):
        identifier = self.create()
        self.status = "paid"
        with main.app.app_context():
            row = db.session.get(StripeCheckout, identifier)
            row.lease_token = "other-worker"
            row.lease_expires_at = (stripe.now() + timedelta(minutes=1)).isoformat()
            db.session.commit()
        count = self.api_mock.call_count
        self.assertFalse(self.reconcile(identifier))
        self.assertEqual(self.api_mock.call_count, count)
        with main.app.app_context():
            self.assertEqual(License.query.count(), 0)

    def test_order_resumes_even_if_first_response_cookie_is_lost(self):
        self.unlock()
        with self.client.session_transaction() as browser:
            original_grant = browser["stripe_test_grant"]
        response = self.client.post("/stripe/checkout", data=self.form())
        self.assertEqual(response.status_code, 303)
        with self.client.session_transaction() as browser:
            browser.pop("checkout_recovery")
            browser["stripe_test_grant"] = original_grant
        self.assertEqual(self.client.post("/stripe/checkout", data={}).status_code, 303)
        self.assertEqual(self.client.get(response.location).status_code, 200)
        with main.app.app_context():
            self.assertEqual(Transaction.query.count(), 1)

    def test_nowpayments_paths_cannot_finish_a_stripe_order(self):
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
                            "payment_id": "cs_test_Synthetic123",
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

    def test_simultaneous_requests_consume_only_one_grant(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        from flask import session
        from pf_server.country_service import CheckoutCountryDecision

        self.unlock()
        with self.client.session_transaction() as browser:
            token = browser["stripe_test_grant"]
        barrier = Barrier(2)
        decision = CheckoutCountryDecision(
            status="verified",
            country_name="Germany",
            evidence_source="local",
            database_label="test",
        )

        def reserve():
            with main.app.test_request_context("/stripe/checkout"):
                session["stripe_test_grant"] = token
                access = stripe.grant()
                barrier.wait(timeout=5)
                return stripe.reserve(access, decision, "DE", "tester@example.com")

        with ThreadPoolExecutor(max_workers=2) as executor:
            identifiers = list(executor.map(lambda _: reserve(), range(2)))
        self.assertEqual(identifiers[0], identifiers[1])
        with main.app.app_context():
            self.assertEqual(StripeCheckout.query.count(), 1)
            self.assertEqual(Transaction.query.count(), 1)

    def test_live_checkout_is_public_primary_and_uses_production_documents(self):
        original = self.api
        self.api_mock.side_effect = lambda *a, **kw: (
            original(*a, **kw) | {"livemode": True}
        )
        with patch.dict(
            main.app.config,
            STRIPE_LIVE_ENABLED=True,
            STRIPE_LIVE_API_KEY="sk_live_synthetic",
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
                "/stripe/checkout", data=form, headers={"Accept": "application/json"}
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
                self.assertEqual(invoice["Document Type"], stripe.MANAGED_RECEIPT)
                self.assertEqual(invoice["Invoice Number"], "STRIPE-123")
            self.assertEqual(
                self.mail_mock.call_args.kwargs["payment_environment"], "production"
            )
            tracking = self.client.get(response.json["next"]).text
            self.assertNotIn("Stripe sandbox", tracking)
            self.assertNotIn("no money is charged", tracking.lower())
            for call in self.api_mock.call_args_list:
                self.assertEqual(call.kwargs["environment"], "production")

    def test_live_activation_requires_both_live_flag_and_live_key(self):
        for settings in (
            {"STRIPE_LIVE_ENABLED": True, "STRIPE_LIVE_API_KEY": "test_wrong"},
            {"STRIPE_LIVE_ENABLED": False, "STRIPE_LIVE_API_KEY": "sk_live_synthetic"},
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
            STRIPE_LIVE_ENABLED=True,
            STRIPE_LIVE_API_KEY="sk_live_synthetic",
        ):
            self.assertTrue(self.reconcile(identifier))
            self.assertEqual(self.api_mock.call_args.kwargs["environment"], "sandbox")
            self.assertEqual(
                self.mail_mock.call_args.kwargs["payment_environment"], "sandbox"
            )
            self.assertIn(
                "Stripe sandbox",
                self.client.get(
                    "/buy_success", query_string={"session_id": identifier}
                ).text,
            )

    def test_live_order_rejects_sandbox_response(self):
        self.change = {"livemode": False}
        with patch.dict(
            main.app.config,
            STRIPE_LIVE_ENABLED=True,
            STRIPE_LIVE_API_KEY="sk_live_synthetic",
        ):
            self.client.get("/porn_fetch")
            self.status = "paid"
            self.client.post("/stripe/checkout", data=self.form())
            with main.app.app_context():
                self.assertEqual(License.query.count(), 0)
                self.assertEqual(Transaction.query.one().status, "pending")

    def test_signed_webhook_only_queues_known_orders_and_checks_environment(self):
        import hashlib
        import hmac
        import time

        identifier = self.create()
        payload = dict(
            type="checkout.session.completed",
            livemode=False,
            data={"object": {"id": "cs_test_Synthetic123", "payment_status": "paid"}},
        )

        def notify(data, *, secret="whsec_test", timestamp=None, signature=None):
            raw = json.dumps(data).encode()
            timestamp = str(int(time.time()) if timestamp is None else timestamp)
            sig = hmac.new(
                secret.encode(), timestamp.encode() + b"." + raw, hashlib.sha256
            ).hexdigest()
            return self.client.post(
                "/stripe/webhook",
                data=raw,
                content_type="application/json",
                headers={"Stripe-Signature": signature or f"t={timestamp},v1={sig}"},
                base_url=main.app.config["API_DOMAIN"],
            )

        calls = self.api_mock.call_count
        self.assertEqual(notify(payload, secret="wrong").status_code, 400)
        self.assertEqual(notify(payload, timestamp=1).status_code, 400)
        self.assertEqual(notify(payload | {"livemode": True}).status_code, 400)
        self.assertEqual(notify(payload).status_code, 200)
        self.assertEqual(notify(payload).status_code, 200)
        unknown = payload | {"data": {"object": {"id": "cs_test_Unknown"}}}
        self.assertEqual(notify(unknown).status_code, 200)
        self.assertEqual(self.api_mock.call_count, calls)
        with main.app.app_context():
            self.assertEqual(License.query.count(), 0)
            stripe.process_pending()
            self.assertEqual(License.query.count(), 0)
        self.status = "paid"
        self.assertTrue(self.reconcile(identifier))
        with main.app.app_context():
            self.assertEqual(License.query.count(), 1)
        reversal = dict(
            type="charge.refunded",
            livemode=False,
            data={
                "object": {"id": "ch_Synthetic", "payment_intent": "pi_Synthetic123"}
            },
        )
        self.assertEqual(notify(reversal).status_code, 200)
        with main.app.app_context():
            row = db.session.get(StripeCheckout, identifier)
            self.assertGreater(
                row.notification_version, row.processed_notification_version
            )

    def test_creation_timeout_reuses_payload_and_idempotency_key(self):
        original = self.api
        posts = []

        def timeout(method, path, **kwargs):
            if method == "POST":
                posts.append(kwargs)
                raise httpx.ReadTimeout("synthetic timeout")
            return original(method, path, **kwargs)

        self.api_mock.side_effect = timeout
        identifier = self.create()
        self.assertFalse(self.reconcile(identifier))
        self.assertEqual(len(posts), 2)
        self.assertEqual(posts[0], posts[1])
        with main.app.app_context():
            row = db.session.get(StripeCheckout, identifier)
            row.first_attempt_at = (stripe.now() - timedelta(minutes=56)).isoformat()
            db.session.commit()
        self.assertFalse(self.reconcile(identifier))
        self.assertEqual(len(posts), 2)
        with main.app.app_context():
            self.assertEqual(db.session.get(StripeCheckout, identifier).state, "review")

    def test_refund_before_fulfillment_withholds_license(self):
        identifier = self.create()
        self.status = "paid"
        self.change = {
            "payment_intent": {
                "id": "pi_Synthetic123",
                "status": "succeeded",
                "latest_charge": {
                    "paid": True,
                    "amount": 2999,
                    "currency": "eur",
                    "amount_refunded": 2999,
                    "disputed": False,
                },
            }
        }
        self.assertTrue(self.reconcile(identifier))
        with main.app.app_context():
            self.assertEqual(License.query.count(), 0)
            self.assertEqual(
                db.session.get(StripeCheckout, identifier).refunded_amount, "29.99"
            )

    def test_http_adapter_pins_version_encodes_form_and_never_follows_redirects(self):
        response = httpx.Response(
            200, json={}, request=httpx.Request("POST", stripe.API)
        )
        with (
            main.app.app_context(),
            patch.object(stripe.httpx, "request", return_value=response) as request,
        ):
            REAL_REQUEST_API(
                "POST",
                "/checkout/sessions",
                json={"line_items": [{"quantity": 1}]},
                headers={"Idempotency-Key": "stable"},
            )
            self.assertEqual(
                request.call_args.kwargs["data"], {"line_items[0][quantity]": "1"}
            )
            self.assertEqual(
                request.call_args.kwargs["headers"]["Authorization"],
                "Bearer sk_test_synthetic",
            )
            self.assertEqual(
                request.call_args.kwargs["headers"]["Stripe-Version"],
                "2026-10-28.endive",
            )
            self.assertFalse(request.call_args.kwargs["follow_redirects"])

    def test_account_mismatch_blocks_session_creation(self):
        original = self.api
        self.api_mock.side_effect = lambda method, path, **kw: (
            {"id": "acct_Wrong"} if path == "/account" else original(method, path, **kw)
        )
        self.create()
        self.assertFalse(any(c.args[0] == "POST" for c in self.api_mock.call_args_list))

    def test_restricted_keys_authenticate_and_reject_the_wrong_environment(self):
        response = httpx.Response(
            200,
            json={"id": ACCOUNT},
            request=httpx.Request("GET", stripe.API + "/account"),
        )
        with (
            main.app.app_context(),
            patch.object(stripe.httpx, "request", return_value=response) as request,
        ):
            for environment, name, key in (
                ("sandbox", "STRIPE_TEST_API_KEY", "rk_test_synthetic"),
                ("production", "STRIPE_LIVE_API_KEY", "rk_live_synthetic"),
            ):
                with patch.dict(main.app.config, {name: key}):
                    self.assertTrue(stripe.configured(environment))
                    REAL_REQUEST_API("GET", "/account", environment=environment)
                    self.assertEqual(
                        request.call_args.kwargs["headers"]["Authorization"],
                        "Bearer " + key,
                    )
                with patch.dict(
                    main.app.config,
                    {
                        name: "rk_live_wrong"
                        if environment == "sandbox"
                        else "rk_test_wrong"
                    },
                ):
                    with self.assertRaisesRegex(ValueError, "credentials unavailable"):
                        REAL_REQUEST_API("GET", "/account", environment=environment)

    def test_separate_sandbox_and_live_accounts_fulfill_their_own_orders(self):
        original = self.api
        accounts = {"sandbox": "acct_Sandbox", "production": "acct_Live"}
        orders = {}

        def provider(method, path, **kwargs):
            environment = kwargs["environment"]
            if path == "/account":
                return {"id": accounts[environment]}
            result = original(method, path, **kwargs)
            if method == "POST":
                orders[environment] = result["client_reference_id"]
            return result | {
                "id": "cs_test_Sandbox"
                if environment == "sandbox"
                else "cs_live_Production",
                "livemode": environment == "production",
                "metadata": {"order_id": orders[environment]},
                "client_reference_id": orders[environment],
            }

        self.api_mock.side_effect = provider
        with patch.dict(
            main.app.config,
            STRIPE_TEST_ACCOUNT_ID=accounts["sandbox"],
            STRIPE_LIVE_ACCOUNT_ID=accounts["production"],
            STRIPE_TEST_API_KEY="rk_test_synthetic",
            STRIPE_LIVE_API_KEY="rk_live_synthetic",
        ):
            sandbox_order = self.create()
            with patch.dict(main.app.config, STRIPE_LIVE_ENABLED=True):
                self.assertEqual(self.client.get("/porn_fetch").status_code, 200)
                self.assertEqual(
                    self.client.post("/stripe/checkout", data=self.form()).status_code,
                    303,
                )
                self.status = "paid"
                self.assertTrue(self.reconcile(orders["production"]))
                self.assertTrue(self.reconcile(sandbox_order))
                with main.app.app_context():
                    self.assertEqual(License.query.count(), 2)
                    for environment, identifier in orders.items():
                        self.assertEqual(
                            db.session.get(StripeCheckout, identifier).account_id,
                            accounts[environment],
                        )
                        transaction = db.session.get(Transaction, identifier)
                        self.assertEqual(transaction.environment, environment)
                        self.assertEqual(transaction.status, "finished")

    def test_private_sandbox_does_not_change_public_live_checkout(self):
        with patch.dict(
            main.app.config,
            STRIPE_LIVE_ENABLED=True,
            STRIPE_LIVE_API_KEY="sk_live_synthetic",
        ):
            self.client.get("/porn_fetch")
            self.assertIn("Tester password", self.client.get("/stripe/test").text)
            self.assertEqual(self.unlock().status_code, 303)
            page = self.client.get("/stripe/test")
            self.assertIn('action="/stripe/test/checkout"', page.text)
            self.assertIn("No money is charged", page.text)
            missing_ack = self.form(sandbox=True)
            missing_ack.pop("test_acknowledged")
            self.assertEqual(
                self.client.post("/stripe/test/checkout", data=missing_ack).status_code,
                400,
            )
            self.assertEqual(
                self.client.post(
                    "/stripe/test/checkout", data=self.form(sandbox=True)
                ).status_code,
                303,
            )
            sandbox_id = self.order
            live_form = self.form() | {"environment": "sandbox", "test": "true"}
            live_form.pop("test_acknowledged")
            self.assertEqual(
                self.client.post(
                    "/stripe/checkout?test=true", data=live_form
                ).status_code,
                303,
            )
            live_id = self.order
            self.status = "paid"
            self.assertTrue(self.reconcile(sandbox_id))
            self.assertTrue(self.reconcile(live_id))
            with main.app.app_context():
                self.assertEqual(
                    db.session.get(Transaction, sandbox_id).environment, "sandbox"
                )
                self.assertEqual(
                    db.session.get(Transaction, live_id).environment, "production"
                )
                self.assertEqual(License.query.count(), 2)
            self.assertNotIn(
                'name="test_acknowledged"', self.client.get("/porn_fetch").text
            )
            self.assertEqual(self.client.post("/stripe/lock").status_code, 303)
            with self.client.session_transaction() as browser:
                self.assertIn("stripe_grant", browser)
                self.assertNotIn("stripe_test_grant", browser)

    def test_live_mode_does_not_bypass_disabled_sandbox_gate(self):
        with patch.dict(
            main.app.config,
            STRIPE_LIVE_ENABLED=True,
            STRIPE_LIVE_API_KEY="sk_live_synthetic",
            STRIPE_TEST_ENABLED=False,
        ):
            self.assertEqual(self.client.get("/porn_fetch").status_code, 200)
            self.assertEqual(self.client.get("/stripe/test").status_code, 404)
            self.assertEqual(self.unlock().status_code, 404)
            self.assertEqual(
                self.client.post(
                    "/stripe/test/checkout", data=self.form(sandbox=True)
                ).status_code,
                404,
            )
            self.api_mock.assert_not_called()

    def test_sandbox_grant_cannot_be_reused_for_live_payment(self):
        identifier = self.create()
        with self.client.session_transaction() as browser:
            browser["stripe_grant"] = browser["stripe_test_grant"]
        calls = self.api_mock.call_count
        with patch.dict(
            main.app.config,
            STRIPE_LIVE_ENABLED=True,
            STRIPE_LIVE_API_KEY="sk_live_synthetic",
        ):
            self.assertEqual(
                self.client.post("/stripe/checkout", data=self.form()).status_code, 403
            )
            self.assertEqual(self.api_mock.call_count, calls)
            with main.app.app_context():
                self.assertEqual(Transaction.query.count(), 1)
                self.assertEqual(
                    db.session.get(Transaction, identifier).environment, "sandbox"
                )

    def test_missing_live_webhook_secret_keeps_public_checkout_disabled(self):
        with patch.dict(
            main.app.config,
            STRIPE_LIVE_ENABLED=True,
            STRIPE_LIVE_API_KEY="sk_live_synthetic",
            STRIPE_LIVE_WEBHOOK_SECRET="",
        ):
            self.assertNotIn('id="premium-form"', self.client.get("/porn_fetch").text)
