"""Payment trust boundaries, consent, beta delivery and provider failures."""

import json
import tempfile
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx
from cryptography.fernet import Fernet

from _support import ServerTestCase, main
from pf_server import onramp_service as service
from pf_server.config import load_environment_config
from pf_server.extensions import db
from pf_server.models import License, OnrampCheckout, Transaction

BASE = "https://localhost"
HTTP_CLIENT = httpx.Client


class OnrampTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.settings = patch.dict(
            main.app.config,
            {
                "ONRAMP_ENABLED": True,
                "ONRAMP_POLYGON_USDC_VERIFIED": True,
                "ONRAMP_ENCRYPTION_KEY": Fernet.generate_key().decode(),
                "NOWPAYMENTS_SANDBOX": False,
                "NOWPAYMENTS_API_KEY": "test-api-key",
                "NOWPAYMENTS_API_URL": "https://api.nowpayments.io/v1",
            },
        )
        self.settings.start()
        self.addCleanup(self.settings.stop)
        self.requests = []
        self.provider = {
            "id": "banxa",
            "status": "active",
            "minimum_currency": "USD",
            "minimum_amount": 11,
        }
        self.wallet_error = False
        self.malformed_payment = False
        self.http_patch = patch.object(
            service.httpx,
            "Client",
            side_effect=lambda **kwargs: HTTP_CLIENT(
                transport=httpx.MockTransport(self.provider_request)
            ),
        )
        self.http_patch.start()
        self.addCleanup(self.http_patch.stop)

    def provider_request(self, request):
        self.requests.append(request)
        if request.url.path == "/control/provider-status":
            return httpx.Response(200, json={"providers": [self.provider]})
        if request.url.path == "/v1/payment":
            payload = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "payment_id": "payment-" + payload["order_id"],
                    "order_id": payload["order_id"],
                    "price_amount": 19.99,
                    "price_currency": "eur",
                    "pay_amount": "24",
                    "pay_currency": "usdc" if self.malformed_payment else "usdcmatic",
                    "network": "matic",
                    "pay_address": "0x" + "a" * 40,
                },
            )
        if request.url.path == "/v1/estimate":
            return httpx.Response(200, json={"estimated_amount": "1"})
        if request.url.path.startswith("/v1/payment/"):
            payment_id = request.url.path.rsplit("/", 1)[-1]
            return httpx.Response(200, json={"order_id": payment_id.removeprefix("payment-"), "payment_id": payment_id, "price_amount": 19.99, "price_currency": "eur", "pay_currency": "usdcmatic", "payment_status": "waiting"})
        if request.url.path == "/control/payment-status.php":
            return httpx.Response(200, json={"status": "waiting"})
        if request.url.path == "/control/wallet.php":
            if self.wallet_error:
                raise httpx.ReadTimeout("Ambiguous provider result")
            return httpx.Response(
                200,
                json={
                    "address_in": "encrypted+address&=",
                    "ipn_token": "tracking-token",
                },
            )
        raise AssertionError("Unexpected provider request")

    def acknowledge(self):
        response = self.client.post("/onramp-acknowledgment", json={}, base_url=BASE)
        self.assertEqual(response.status_code, 200)
        token = response.get_json()["acknowledgment_token"]
        with main.app.app_context():
            checkout = OnrampCheckout.query.order_by(
                OnrampCheckout.created_at.desc()
            ).first()
            session_id = checkout.session_id
        return token, session_id

    def form(self, token):
        return dict(
            acknowledgment_token=token,
            delivery_email="buyer@example.com",
            country="DE",
            age_confirmed=True,
            terms_accepted=True,
            withdrawal_accepted=True,
            annual_terms_acknowledged=True,
            kyc_acknowledged=True,
        )

    def age_consent(self, session_id):
        with main.app.app_context():
            row = db.session.get(OnrampCheckout, session_id)
            row.created_at = (service.now() - timedelta(seconds=6)).isoformat()
            db.session.commit()

    def create(self, **overrides):
        token, session_id = self.acknowledge()
        self.age_consent(session_id)
        data = self.form(token) | overrides
        response = self.client.post("/create-onramp-payment", json=data, base_url=BASE)
        return response, session_id, data

    def webhook(self, session_id, paid=24, **overrides):
        return (
            dict(
                order_id=session_id,
                payment_id="payment-" + session_id,
                payment_status="finished",
                price_amount=19.99,
                price_currency="eur",
                pay_currency="usdcmatic",
                pay_amount=24,
                actually_paid=paid,
            )
            | overrides
        )

    def post_ipn(self, payload, valid=True):
        return self.client.post(
            "/nowpayments-ipn",
            json=payload,
            headers={
                "x-nowpayments-sig": self.nowpayments_signature(payload)
                if valid
                else "0" * 128,
            },
            base_url="https://api.echteralsfake.me",
        )

    def test_disabled_and_sandbox_never_contact_providers(self):
        for settings in (
            {"ONRAMP_ENABLED": False},
            {"NOWPAYMENTS_SANDBOX": True},
            {"ONRAMP_POLYGON_USDC_VERIFIED": False},
        ):
            with patch.dict(main.app.config, settings):
                for endpoint in ("/onramp-acknowledgment", "/create-onramp-payment"):
                    response = self.client.post(endpoint, json={}, base_url=BASE)
                    self.assertEqual(response.status_code, 503)
        self.assertEqual(self.requests, [])

    def test_five_second_timer_and_browser_binding(self):
        token, session_id = self.acknowledge()
        response = self.client.post(
            "/create-onramp-payment", json=self.form(token), base_url=BASE
        )
        self.assertEqual(response.status_code, 409)
        self.age_consent(session_id)
        other = main.app.test_client()
        response = other.post(
            "/create-onramp-payment", json=self.form(token), base_url=BASE
        )
        self.assertEqual(response.status_code, 400)
        response = self.client.post(
            "/create-onramp-payment", json=self.form(token + "x"), base_url=BASE
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.requests, [])

    def test_all_confirmations_and_email_are_required(self):
        token, session_id = self.acknowledge()
        self.age_consent(session_id)
        for key in (
            "age_confirmed",
            "terms_accepted",
            "withdrawal_accepted",
            "annual_terms_acknowledged",
            "kyc_acknowledged",
        ):
            response = self.client.post(
                "/create-onramp-payment",
                json=self.form(token) | {key: False},
                base_url=BASE,
            )
            self.assertEqual(response.status_code, 400)
        for recipient in (
            None,
            "invalid",
            "x@example.com\r\nBcc:other@example.com",
            {},
        ):
            response = self.client.post(
                "/create-onramp-payment",
                json=self.form(token) | {"delivery_email": recipient},
                base_url=BASE,
            )
            self.assertEqual(response.status_code, 400)
        self.assertEqual(self.requests, [])

    def test_country_mismatch_is_rejected_before_provider_requests(self):
        response, _, _ = self.create(country="FR")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.requests, [])

    def test_address_handoff_fee_rounding_and_idempotent_creation(self):
        response, session_id, data = self.create()
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        query = parse_qs(urlsplit(result["checkout_url"]).query)
        self.assertEqual(query["provider"], ["banxa"])
        self.assertEqual(query["address"], ["encrypted+address&="])
        self.assertEqual(query["amount"], ["24.75"])
        self.assertNotIn("email", query)
        wallet = next(r for r in self.requests if r.url.path == "/control/wallet.php")
        self.assertEqual(wallet.url.params["address"], "0x" + "a" * 40)
        callback = wallet.url.params["callback"]
        self.assertTrue(
            callback.startswith(
                "https://api.echteralsfake.me/onramp-callback?reference="
            )
        )
        before = len(self.requests)
        repeated = self.client.post("/create-onramp-payment", json=data, base_url=BASE)
        self.assertEqual(repeated.status_code, 200)
        self.assertEqual(len(self.requests), before)
        with main.app.app_context():
            checkout = db.session.get(OnrampCheckout, session_id)
            self.assertNotIn("buyer@example.com", checkout.recipient_encrypted)
            self.assertEqual(
                service.decrypt(checkout.recipient_encrypted), "buyer@example.com"
            )
            self.assertEqual(checkout.stage, "ready")
            transaction = db.session.get(Transaction, session_id)
            self.assertEqual(transaction.provider_reference_type, "payment")
            self.assertEqual(transaction.expected_pay_currency, "usdcmatic")
            self.assertEqual(transaction.environment, "production")
        page = self.client.get(result["status_url"], base_url=BASE)
        self.assertIn(b'target="_blank"', page.data)
        self.assertNotIn(b"deleted at release", page.data)
        self.assertIn(b"One year of updates", page.data)
        self.assertFalse(result["beta"])
        self.assertEqual(result["payment_method"], "banxa")
        self.assertEqual(page.headers["Cache-Control"], "no-store")
        self.assertEqual(page.headers["Referrer-Policy"], "no-referrer")

    def test_inactive_provider_fails_without_creating_a_payment(self):
        self.provider["status"] = "inactive"
        response, _, _ = self.create()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(len(self.requests), 1)

    def test_below_minimum_or_wrong_asset_never_creates_onramp_wallet(self):
        for mode in ("minimum", "asset"):
            self.provider["minimum_amount"] = 100 if mode == "minimum" else 11
            self.malformed_payment = mode == "asset"
            self.requests.clear()
            response, _, _ = self.create()
            self.assertEqual(response.status_code, 503)
            self.assertFalse(
                any(r.url.path == "/control/wallet.php" for r in self.requests)
            )

    def test_ambiguous_wallet_failure_is_not_retried(self):
        self.wallet_error = True
        response, session_id, data = self.create()
        self.assertEqual(response.status_code, 503)
        repeated = self.client.post("/create-onramp-payment", json=data, base_url=BASE)
        self.assertEqual(repeated.status_code, 409)
        self.assertEqual(
            sum(r.url.path == "/control/wallet.php" for r in self.requests), 1
        )
        with main.app.app_context():
            checkout = db.session.get(OnrampCheckout, session_id)
            self.assertEqual(checkout.stage, "failed")
            self.assertIsNone(checkout.recipient_encrypted)

    def test_onramp_callback_cannot_fulfill_even_with_paid_fields(self):
        _, session_id, _ = self.create()
        wallet = next(r for r in self.requests if r.url.path == "/control/wallet.php")
        callback_url = (
            wallet.url.params["callback"] + "&status=paid&value_forwarded_coin=100"
        )
        response = self.client.get(callback_url)
        self.assertEqual(response.data, b"ok")
        with main.app.app_context():
            self.assertEqual(db.session.get(Transaction, session_id).status, "pending")
            self.assertIsNotNone(
                db.session.get(OnrampCheckout, session_id).callback_seen_at
            )
            self.assertEqual(License.query.count(), 0)

    def test_exact_95_percent_receipt_delivers_same_license_once(self):
        _, session_id, _ = self.create()
        payload = self.webhook(session_id, paid=22.8)
        with patch.object(service, "send_license_email") as send:
            self.assertEqual(self.post_ipn(payload).status_code, 200)
            self.assertEqual(self.post_ipn(payload).status_code, 200)
            self.assertEqual(send.call_count, 1)
            self.assertFalse(send.call_args.kwargs["beta"])
            emailed = send.call_args.args[1]
        downloaded = self.client.get(
            "/download_license", query_string={"session_id": session_id}
        )
        self.assertEqual(downloaded.data, emailed)
        status = self.client.get(
            "/check-payment-status", query_string={"session_id": session_id}
        ).get_json()
        self.assertEqual(status["delivery_status"], "sent")
        self.assertEqual(status["license_key"], json.loads(emailed)["license_key"])
        with main.app.app_context():
            self.assertEqual(License.query.count(), 1)
            self.assertIsNone(
                db.session.get(OnrampCheckout, session_id).recipient_encrypted
            )

    def test_underpayment_requires_review_and_later_valid_payment_can_finish(self):
        _, session_id, _ = self.create()
        with patch.object(service, "send_license_email") as send:
            self.assertEqual(
                self.post_ipn(self.webhook(session_id, paid=22.7999)).status_code, 200
            )
            self.assertEqual(send.call_count, 0)
            self.assertEqual(
                self.client.get(
                    "/check-payment-status", query_string={"session_id": session_id}
                ).get_json()["status"],
                "partially_paid",
            )
            with main.app.app_context():
                self.assertEqual(License.query.count(), 0)
            self.assertEqual(
                self.post_ipn(self.webhook(session_id, paid=24)).status_code, 200
            )
            self.assertEqual(send.call_count, 1)

    def test_overpayment_issues_only_one_license(self):
        _, session_id, _ = self.create()
        with patch.object(service, "send_license_email"):
            self.assertEqual(
                self.post_ipn(self.webhook(session_id, paid=50)).status_code, 200
            )
        with main.app.app_context():
            self.assertEqual(License.query.count(), 1)

    def test_forged_or_mismatched_ipn_never_issues(self):
        _, session_id, _ = self.create()
        self.assertEqual(
            self.post_ipn(self.webhook(session_id), valid=False).status_code, 403
        )
        for changes in (
            {"payment_id": "other"},
            {"pay_currency": "usdc"},
            {"price_amount": 1},
            {"price_currency": "usd"},
            {"parent_payment_id": "other"},
        ):
            self.assertEqual(
                self.post_ipn(self.webhook(session_id, **changes)).status_code, 200
            )
        with main.app.app_context():
            self.assertEqual(License.query.count(), 0)
            self.assertEqual(db.session.get(Transaction, session_id).status, "pending")

    def test_expiry_is_visible_and_stale_waiting_does_not_hide_it(self):
        _, session_id, _ = self.create()
        for state in ("expired", "waiting"):
            self.post_ipn(self.webhook(session_id, payment_status=state))
        status = self.client.get(
            "/check-payment-status", query_string={"session_id": session_id}
        )
        self.assertEqual(status.get_json()["status"], "expired")

    def test_keygen_failure_retries_without_duplicate_license(self):
        from pf_server.keygen_service import KeygenUnavailable

        _, session_id, _ = self.create()
        with patch(
            "pf_server.licensing.build_license_file", side_effect=KeygenUnavailable()
        ):
            self.assertEqual(self.post_ipn(self.webhook(session_id)).status_code, 503)
        with patch.object(service, "send_license_email"):
            self.assertEqual(self.post_ipn(self.webhook(session_id)).status_code, 200)
        with main.app.app_context():
            self.assertEqual(License.query.count(), 1)

    def test_smtp_failure_keeps_browser_delivery_and_timer_retries(self):
        _, session_id, _ = self.create()
        with patch.object(
            service, "send_license_email", side_effect=RuntimeError("SMTP down")
        ):
            self.assertEqual(self.post_ipn(self.webhook(session_id)).status_code, 200)
        self.assertEqual(
            self.client.get(
                "/download_license", query_string={"session_id": session_id}
            ).status_code,
            200,
        )
        with patch.object(service, "send_license_email") as send:
            result = main.app.test_cli_runner().invoke(args=["retry-onramp-deliveries"])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual(send.call_count, 1)
        with main.app.app_context():
            self.assertEqual(License.query.count(), 1)
            self.assertIsNone(
                db.session.get(OnrampCheckout, session_id).recipient_encrypted
            )

    def test_active_lease_prevents_concurrent_delivery(self):
        _, session_id, _ = self.create()
        with patch.object(
            service, "send_license_email", side_effect=RuntimeError("SMTP down")
        ):
            self.post_ipn(self.webhook(session_id))
        with main.app.app_context():
            checkout = db.session.get(OnrampCheckout, session_id)
            checkout.delivery_status = "sending"
            checkout.lease_token = "another-worker"
            checkout.lease_expires_at = (
                service.now() + timedelta(minutes=10)
            ).isoformat()
            db.session.commit()
            with patch.object(service, "send_license_email") as send:
                self.assertEqual(service.deliver_license(session_id), "busy")
                send.assert_not_called()
            checkout.lease_expires_at = (
                service.now() - timedelta(minutes=1)
            ).isoformat()
            db.session.commit()
            with patch.object(service, "send_license_email") as send:
                self.assertEqual(service.deliver_license(session_id), "sent")
                self.assertEqual(send.call_count, 1)

    def test_retention_clears_expired_recipient_and_tracking_secrets(self):
        _, session_id, _ = self.create()
        with main.app.app_context():
            checkout = db.session.get(OnrampCheckout, session_id)
            checkout.created_at = (service.now() - timedelta(days=8)).isoformat()
            db.session.commit()
            service.retry_deliveries()
            checkout = db.session.get(OnrampCheckout, session_id)
            self.assertIsNone(checkout.recipient_encrypted)
            self.assertIsNone(checkout.checkout_encrypted)
            self.assertIsNone(checkout.tracking_encrypted)
            self.assertIsNone(checkout.callback_digest)
            self.assertFalse(checkout.beta)
            self.assertEqual(checkout.consent_version, service.CONSENT_VERSION)

    def test_real_checkout_cannot_use_local_simulation(self):
        _, session_id, _ = self.create()
        with patch.dict(main.app.config, {"NOWPAYMENTS_SANDBOX": True}):
            response = self.client.post(
                "/simulate-payment-success", json={"session_id": session_id}
            )
        self.assertEqual(response.status_code, 400)

    def test_csrf_protects_consent_and_creation(self):
        with patch.dict(main.app.config, {"WTF_CSRF_ENABLED": True}):
            for endpoint in ("/onramp-acknowledgment", "/create-onramp-payment"):
                response = self.client.post(endpoint, json={}, base_url=BASE)
                self.assertEqual(response.status_code, 400)
        self.assertEqual(self.requests, [])

    def test_ui_contains_annual_offer_payment_conditions_and_kyc_disclosures(self):
        page = self.client.get("/porn_fetch")
        for text in (
            b"Recommended",
            b"Credit Card / Google Pay / Apple Pay",
            b"No automatic renewal",
        ):
            self.assertIn(text, page.data)
        card = self.client.get("/buy_card")
        for text in (
            b"Your payment route &amp; verification",
            b"date of birth",
            b"Tax identification",
            b"separate license-delivery email",
        ):
            self.assertIn(text, card.data)
        self.assertIn(b"kyc-continue", card.data)

    def test_browser_rate_limit_does_not_block_another_browser(self):
        from pf_server.extensions import limiter

        limiter.enabled = True
        try:
            for _ in range(20):
                response = self.client.post(
                    "/onramp-acknowledgment", json={}, base_url=BASE
                )
                self.assertEqual(response.status_code, 200)
            limited = self.client.post("/onramp-acknowledgment", json={}, base_url=BASE)
            self.assertEqual(limited.status_code, 429)
            other = main.app.test_client()
            self.assertEqual(
                other.post(
                    "/onramp-acknowledgment", json={}, base_url=BASE
                ).status_code,
                200,
            )
        finally:
            limiter.enabled = False

    def test_provider_redirects_only_allow_known_https_api_and_same_path(self):
        with HTTP_CLIENT(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    302, headers={"location": "https://attacker.example/wallet"}
                )
            )
        ) as client:
            with self.assertRaises(ValueError):
                service._get_json(client, service.API_BASE + "/control/wallet.php")


    def test_new_card_offer_is_annual_and_old_beta_consent_is_rejected(self):
        token, session_id = self.acknowledge()
        self.age_consent(session_id)
        with main.app.app_context():
            checkout = db.session.get(OnrampCheckout, session_id)
            self.assertFalse(checkout.beta)
            self.assertEqual(checkout.consent_version, 'banxa-annual-v1')
            checkout.consent_version = 'banxa-beta-v1'
            checkout.beta = True
            db.session.commit()
        response = self.client.post('/create-onramp-payment', json=self.form(token), base_url=BASE)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.requests, [])

    def test_historical_beta_keeps_its_notice_and_email_terms(self):
        response, session_id, _ = self.create()
        with main.app.app_context():
            checkout = db.session.get(OnrampCheckout, session_id)
            checkout.beta = True
            checkout.consent_version = 'banxa-beta-v1'
            db.session.commit()
        page = self.client.get(response.json['status_url'], base_url=BASE)
        self.assertIn(b'will be deleted at release', page.data)
        with patch.object(service, 'send_license_email') as send:
            self.assertEqual(self.post_ipn(self.webhook(session_id)).status_code, 200)
            self.assertTrue(send.call_args.kwargs['beta'])
        status = self.client.get('/check-payment-status', query_string={'session_id': session_id}).json
        self.assertTrue(status['beta'])
        self.assertEqual(status['payment_method'], 'banxa')


    def test_forwarded_onramp_funds_cannot_reopen_provider_checkout(self):
        from pf_server.models import PaymentProgress
        response, session_id, _ = self.create()
        with main.app.app_context():
            progress = db.session.get(PaymentProgress, session_id)
            progress.onramp_state = "forwarded"
            db.session.commit()
        self.assertEqual(self.client.get("/payment-preview/banxa?session_id=" + session_id, base_url=BASE).status_code, 404)
        page = self.client.get(response.json["status_url"], base_url=BASE).data
        self.assertNotIn(b"Open Banxa payment in a new tab", page)

    def test_generated_provider_link_requires_test_confirmation_and_cannot_reopen_paid_orders(self):
        response, session_id, _ = self.create()
        path = '/payment-preview/banxa?session_id=' + session_id
        before = len(self.requests)
        self.assertEqual(self.client.get(path, base_url=BASE).status_code, 200)
        self.assertEqual(self.client.post(path, data={}, base_url=BASE).status_code, 400)
        accepted = self.client.post(path, data={'confirm_no_payment': 'yes'}, base_url=BASE)
        self.assertEqual(accepted.status_code, 200)
        self.assertIn(b'checkout.onramp-pay.com/process-payment.php', accepted.data)
        self.assertIn(b'provider=banxa', accepted.data)
        self.assertEqual(len(self.requests), before)
        with patch.object(service, 'send_license_email'):
            self.post_ipn(self.webhook(session_id))
        self.assertEqual(self.client.get(path, base_url=BASE).status_code, 404)


class OnrampConfigTests(ServerTestCase):
    def test_enabled_checkout_requires_production_verified_asset_and_services(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = {"SECRET_KEY": "x", "ONRAMP_ENABLED": "true"}
            with self.assertRaisesRegex(ValueError, "production"):
                load_environment_config(directory, settings)
            settings |= {
                "NOWPAYMENTS_SANDBOX": "false",
                "NOWPAYMENTS_API_KEY": "x",
                "NOWPAYMENTS_IPN_SECRET": "x",
                "ONRAMP_POLYGON_USDC_VERIFIED": "true",
            }
            with self.assertRaisesRegex(ValueError, "ENCRYPTION_KEY"):
                load_environment_config(directory, settings)
            settings |= {
                "ONRAMP_ENCRYPTION_KEY": Fernet.generate_key().decode(),
                "LICENSE_SMTP_HOST": "smtp.example.com",
                "LICENSE_EMAIL_FROM": "sender@example.com",
            }
            with self.assertRaisesRegex(ValueError, "Keygen"):
                load_environment_config(directory, settings)
            settings |= {"KEYGEN_PRODUCT_TOKEN": "x", "KEYGEN_POLICY_ID": "x"}
            config = load_environment_config(directory, settings)
            self.assertTrue(config["ONRAMP_ENABLED"])

    def test_invalid_encryption_key_fails_fast(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "Fernet"):
                load_environment_config(
                    directory, {"SECRET_KEY": "x", "ONRAMP_ENCRYPTION_KEY": "invalid"}
                )

    def test_migration_preserves_existing_payments_and_downgrades_cleanly(self):
        from flask_migrate import downgrade, upgrade
        from sqlalchemy import inspect

        isolated = main.create_app(
            {"SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "TESTING": True}
        )
        with isolated.app_context():
            import sqlalchemy as sa
            upgrade(revision="2f3c6a91d4b8")
            upgrade(revision="34ddbc4909f1")
            db.session.execute(
                sa.text(
                    "INSERT INTO \"transaction\" (session_id, provider_payment_id, provider_reference_type, environment, expected_price_amount, expected_price_currency, customer_country, country_evidence, geolocation_database, status, created_at) "
                    "VALUES ('NP-existing', 'existing', 'invoice', 'production', '19.99', 'eur', 'Germany', 'local', 'test', 'pending', '2026-10-01T00:00:00+00:00')"
                )
            )
            db.session.commit()
            upgrade()
            self.assertEqual(
                {
                    column["name"]
                    for column in inspect(db.engine).get_columns("onramp_checkouts")
                },
                set(OnrampCheckout.__table__.columns.keys()),
            )
            self.assertEqual(
                db.session.get(Transaction, "NP-existing").provider_payment_id,
                "existing",
            )
            downgrade(revision="6a30f2b917c4")
            self.assertNotIn("onramp_checkouts", inspect(db.engine).get_table_names())
            self.assertIsNotNone(db.session.get(Transaction, "NP-existing"))

    def test_beta_email_contains_warning_in_both_languages(self):
        from unittest.mock import MagicMock
        from pf_server import licensing

        smtp = MagicMock()
        smtp.__enter__.return_value = smtp
        with (
            main.app.app_context(),
            patch.dict(
                main.app.config,
                {
                    "LICENSE_SMTP_HOST": "localhost",
                    "LICENSE_EMAIL_FROM": "sender@example.com",
                    "LICENSE_SMTP_STARTTLS": False,
                    "LICENSE_SMTP_SSL": False,
                    "LICENSE_SMTP_USERNAME": "",
                    "LICENSE_SMTP_PASSWORD": "",
                },
            ),
            patch.object(licensing.smtplib, "SMTP", return_value=smtp),
        ):
            licensing.send_license_email(
                "buyer@example.com", b"signed-beta-license", beta=True
            )
        message = smtp.send_message.call_args.args[0]
        body = message.get_body(preferencelist=("plain",)).get_content()
        self.assertIn("V3.9 BETA ONLY", body)
        self.assertIn("deleted at product release", body)
        self.assertIn("NUR V3.9-BETA", body)
        self.assertIn("gelöscht", body)
        attachment = list(message.iter_attachments())[0]
        self.assertEqual(attachment.get_payload(decode=True), b"signed-beta-license")
