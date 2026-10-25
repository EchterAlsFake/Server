"""Payment progress is informative, bound to known orders, and never fulfillment."""

import hashlib
import json
from datetime import timedelta
from unittest.mock import patch

import httpx
from cryptography.fernet import Fernet

from _support import ServerTestCase, main, drain_payment_receipts
from pf_server import payment_progress as service
from pf_server.onramp_service import encrypt
from pf_server.models import License, OnrampCheckout, PaymentProgress, Transaction

HTTP_CLIENT = httpx.Client


class PaymentProgressTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.config = patch.dict(
            main.app.config,
            {
                "NOWPAYMENTS_API_KEY": "synthetic-now-key",
                "NOWPAYMENTS_API_URL": "https://api.nowpayments.io/v1",
                "NOWPAYMENTS_SANDBOX": False,
                "ONRAMP_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            },
        )
        self.config.start()
        self.addCleanup(self.config.stop)
        self.requests = []
        self.now_state = "waiting"
        self.onramp_response = {"status": "waiting"}
        self.failure = False
        self.wrong_order = False
        self.http_patch = patch.object(
            service.httpx,
            "Client",
            side_effect=lambda **kwargs: HTTP_CLIENT(
                transport=httpx.MockTransport(self.provider)
            ),
        )
        self.http_patch.start()
        self.addCleanup(self.http_patch.stop)

    def provider(self, request):
        self.requests.append(request)
        if self.failure:
            return httpx.Response(503)
        if request.url.path == "/control/payment-status.php":
            self.assertEqual(request.url.params["ipn_token"], "private-tracking-token")
            return httpx.Response(200, json=self.onramp_response)
        if request.url.path == "/v1/payment/payment-test":
            self.assertEqual(request.headers["x-api-key"], "synthetic-now-key")
            payload = self.event("NP-test", self.now_state)
            if self.wrong_order:
                payload["order_id"] = "NP-another-customer"
            return httpx.Response(200, json=payload)
        raise AssertionError("Unexpected provider endpoint")

    def add(self, *, card=False, invoice=False):
        with main.app.app_context():
            main.db.session.add(
                Transaction(
                    session_id="NP-test",
                    provider_payment_id="invoice-test" if invoice else "payment-test",
                    provider_reference_type="invoice" if invoice else "payment",
                    expected_price_amount="19.99",
                    expected_price_currency="eur",
                    expected_pay_currency="usdcmatic" if card else None,
                    customer_country="Germany",
                    country_evidence="test",
                    geolocation_database="test",
                    status="pending",
                    created_at=service.now().isoformat(),
                )
            )
            if card:
                main.db.session.add(
                    OnrampCheckout(
                        session_id="NP-test",
                        consent_version="banxa-annual-v1",
                        beta=False,
                        stage="ready",
                        tracking_encrypted=encrypt("private-tracking-token"),
                        created_at=service.now().isoformat(),
                        callback_digest=hashlib.sha256(
                            b"private-callback-reference"
                        ).hexdigest(),
                    )
                )
            main.db.session.commit()

    @staticmethod
    def event(order_id="NP-test", state="confirming"):
        return dict(
            order_id=order_id,
            payment_id="payment-test",
            invoice_id="invoice-test",
            payment_status=state,
            price_amount=19.99,
            price_currency="eur",
            pay_currency="usdcmatic",
            pay_amount=24,
            actually_paid=24,
        )

    def ipn(self, payload, signed=True):
        response = self.client.post(
            "/nowpayments-ipn",
            data=json.dumps(payload),
            headers={
                "x-nowpayments-sig": self.nowpayments_signature(payload)
                if signed
                else "0" * 128
            },
            base_url="https://api.echteralsfake.me",
        )
        drain_payment_receipts()
        return response

    def status(self):
        return self.client.get("/check-payment-status?session_id=NP-test")

    def reset_poll(self):
        with main.app.app_context():
            record = main.db.session.get(PaymentProgress, "NP-test")
            record.checked_at = (service.now() - timedelta(minutes=2)).isoformat()
            main.db.session.commit()

    def test_combined_age_and_terms_form_requires_one_explicit_choice(self):
        data = dict(
            payment_method="crypto",
            country="DE",
            age_terms_accepted="yes",
            withdrawal_accepted="yes",
            test_acknowledged="yes",
        )
        self.assertEqual(
            self.client.post("/checkout/start", data=data).status_code, 303
        )
        with self.client.session_transaction() as state:
            self.assertIs(state["checkout_consent"]["age_confirmed"], True)
            self.assertIs(state["checkout_consent"]["terms_accepted"], True)
        data.pop("age_terms_accepted")
        self.assertEqual(
            self.client.post("/checkout/start", data=data).status_code, 400
        )
        page = self.client.get("/porn_fetch").data
        self.assertIn(b'id="chk-age-terms"', page)
        self.assertNotIn(b'id="chk-age"', page)
        self.assertNotIn(b'id="chk-terms"', page)
        self.assertNotIn(b"identity verification", page)

    def test_card_design_explains_route_requirements_and_price(self):
        page = self.client.get("/buy_card").data
        for text in (
            b"checkout-card",
            b"Email verification is mandatory",
            b"10 minutes or longer",
            b"EU residents need their Tax ID",
            b"Prefer Patreon?",
            b"NOWPayments",
            b"onramp-pay.com",
            "€19.99".encode(),
        ):
            self.assertIn(text, page)
        self.assertNotIn(b"crypto-checkout-grid", page)
        # Fees and verification remain visible before the collapsed FAQ.
        purchase = page.split(b'<section class="checkout-faq"')[0]
        for text in (
            b"Email verification is required",
            b"EU residents need their Tax ID",
            b"3% Onramp Pay fee",
            b"final quote in USD before payment",
            b"Payment processing fees are additional",
        ):
            self.assertIn(text, purchase)
        self.assertIn(b"/porn_fetch?method=patreon#method-heading", page)

    def test_hosted_crypto_invoice_keeps_recovery_page_and_safe_provider_link(self):
        response = httpx.Response(
            200,
            json={
                "id": "hosted-invoice",
                "invoice_url": "https://nowpayments.io/payment/?iid=hosted-invoice",
            },
            request=httpx.Request("POST", "https://api.nowpayments.io/v1/invoice"),
        )
        with patch.object(httpx, "post", return_value=response):
            result = self.client.post(
                "/create-crypto-payment",
                json={
                    "country": "DE",
                    "age_confirmed": True,
                    "terms_accepted": True,
                    "withdrawal_accepted": True,
                    "no_email_acknowledged": True,
                },
            )
        self.assertEqual(result.status_code, 200)
        self.assertTrue(result.json["status_url"].startswith("/buy_success?token="))
        self.assertNotIn(result.json["session_id"], result.json["status_url"])
        page = self.client.get(result.json["status_url"]).data
        self.assertIn(b"Open NOWPayments checkout", page)
        self.assertIn(b"https://nowpayments.io/payment/?iid=hosted-invoice", page)
        self.assertIn(b'target="_blank"', page)

    def test_untrusted_hosted_url_is_rejected_before_persisting_checkout(self):
        response = httpx.Response(
            200,
            json={
                "id": "bad-invoice",
                "invoice_url": "https://nowpayments.io.evil.invalid/checkout",
            },
            request=httpx.Request("POST", "https://api.nowpayments.io/v1/invoice"),
        )
        with patch.object(httpx, "post", return_value=response):
            result = self.client.post(
                "/create-crypto-payment",
                json={
                    "country": "DE",
                    "age_confirmed": True,
                    "terms_accepted": True,
                    "withdrawal_accepted": True,
                    "no_email_acknowledged": True,
                },
            )
        self.assertEqual(result.status_code, 500)
        with main.app.app_context():
            self.assertEqual(Transaction.query.count(), 0)

    def test_forwarding_requires_a_real_payout_transaction_reference(self):
        self.add(card=True)
        self.onramp_response = {
            "status": "paid",
            "value_coin": "24",
            "txid_out": "pending",
        }
        self.assertEqual(self.status().json["progress"]["stage"], "onramp")
        self.reset_poll()
        self.onramp_response = {
            "status": "paid",
            "value_coin": "0",
            "txid_out": "0x" + "c" * 64,
        }
        result = self.status().json
        self.assertEqual(result["progress"]["stage"], "onramp")
        self.assertTrue(result["progress"]["refresh_unavailable"])

    def test_onramp_received_and_forwarded_never_unlock_license(self):
        self.add(card=True)
        self.onramp_response = {
            "status": "paid",
            "value_coin": "24",
            "coin": "polygon_usdc",
        }
        result = self.status().json
        self.assertEqual(result["progress"]["stage"], "onramp")
        self.assertEqual(result["status"], "pending")
        self.reset_poll()
        self.onramp_response["txid_out"] = "0x" + "c" * 64
        result = self.status().json
        self.assertEqual(result["progress"]["stage"], "forwarding")
        self.assertIn("reports the outgoing transfer", result["progress"]["message"])
        with main.app.app_context():
            self.assertEqual(License.query.count(), 0)
            self.assertEqual(
                main.db.session.get(Transaction, "NP-test").status, "pending"
            )
        self.assertEqual(
            self.client.get("/download_license?session_id=NP-test").status_code, 402
        )
        self.assertNotIn("private-tracking-token", json.dumps(result))
        self.assertNotIn("synthetic-now-key", json.dumps(result))

    def test_nowpayments_api_tracks_chain_and_settlement_but_cannot_fulfill(self):
        self.add()
        for state, stage in [
            ("confirming", "blockchain"),
            ("confirmed", "settlement"),
            ("sending", "settlement"),
            ("finished", "license"),
        ]:
            self.now_state = state
            if self.requests:
                self.reset_poll()
            result = self.status().json
            self.assertEqual(result["progress"]["stage"], stage)
            self.assertEqual(result["status"], "pending")
        with main.app.app_context():
            self.assertEqual(License.query.count(), 0)
            self.assertEqual(
                main.db.session.get(Transaction, "NP-test").status, "pending"
            )
        self.assertEqual(self.ipn(self.event(state="finished")).status_code, 200)
        result = self.status().json
        self.assertEqual(result["status"], "finished")
        self.assertTrue(
            all(step["state"] == "done" for step in result["progress"]["steps"])
        )
        self.assertTrue(result["license_key"].startswith("key/"))

    def test_bound_signed_invoice_events_discover_payment_id_and_reject_stale_states(
        self,
    ):
        self.add(invoice=True)
        self.assertEqual(self.ipn(self.event(), signed=False).status_code, 403)
        with main.app.app_context():
            self.assertIsNone(main.db.session.get(PaymentProgress, "NP-test"))
        self.assertEqual(self.ipn(self.event()).status_code, 200)
        self.assertEqual(self.ipn(self.event(state="waiting")).status_code, 200)
        with main.app.app_context():
            record = main.db.session.get(PaymentProgress, "NP-test")
            self.assertEqual(record.nowpayments_state, "confirming")
            self.assertEqual(record.nowpayments_payment_id, "payment-test")
        self.now_state = "confirmed"
        self.assertEqual(self.status().json["progress"]["stage"], "settlement")

    def test_mismatched_api_or_signed_event_cannot_move_another_order(self):
        self.add(invoice=True)
        for changes in (
            {"invoice_id": "other-invoice"},
            {"price_amount": 20},
            {"order_id": "NP-unknown"},
            {"parent_payment_id": "earlier-payment"},
        ):
            payload = self.event()
            payload.update(changes)
            self.assertEqual(self.ipn(payload).status_code, 200)
        with main.app.app_context():
            self.assertIsNone(main.db.session.get(PaymentProgress, "NP-test"))
        self.ipn(self.event(state="waiting"))
        self.now_state = "finished"
        self.wrong_order = True
        result = self.status().json
        self.assertEqual(result["progress"]["stage"], "payment")
        self.assertTrue(result["progress"]["refresh_unavailable"])

    def test_unsigned_onramp_callback_cannot_claim_receipt_or_forwarding(self):
        self.add(card=True)
        response = self.client.get(
            "/onramp-callback?reference=private-callback-reference&value_coin=24&txid_out=0xfake",
            base_url="https://api.echteralsfake.me",
        )
        self.assertEqual(response.status_code, 200)
        result = self.status().json
        self.assertEqual(result["progress"]["stage"], "provider")
        self.assertEqual(result["status"], "pending")

    def test_polling_is_cached_across_tabs_and_respects_active_lease(self):
        self.add(card=True)
        self.assertEqual(self.status().status_code, 200)
        count = len(self.requests)
        self.assertEqual(count, 2)
        self.assertEqual(self.status().status_code, 200)
        self.assertEqual(len(self.requests), count)
        self.reset_poll()
        with main.app.app_context():
            record = main.db.session.get(PaymentProgress, "NP-test")
            record.poll_lease_until = (
                service.now() + timedelta(seconds=20)
            ).isoformat()
            main.db.session.commit()
        self.status()
        self.assertEqual(len(self.requests), count)

    def test_provider_outage_preserves_last_known_state_and_shows_retry_note(self):
        self.add()
        self.now_state = "confirming"
        self.status()
        self.reset_poll()
        self.failure = True
        result = self.status().json
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["progress"]["stage"], "blockchain")
        self.assertTrue(result["progress"]["refresh_unavailable"])
        self.assertNotIn("private-tracking-token", json.dumps(result))

    def test_partial_or_failed_payment_reports_support_without_false_success(self):
        for state in ("partially_paid", "failed", "expired", "wrong_asset_confirmed"):
            with self.subTest(state=state):
                self.add()
                self.now_state = state
                result = self.status().json
                self.assertEqual(result["status"], state)
                self.assertIn("Do not pay again", result["progress"]["message"])
                self.assertNotIn("license_key", result)
                with main.app.app_context():
                    main.db.session.execute(main.db.delete(PaymentProgress))
                    main.db.session.execute(main.db.delete(Transaction))
                    main.db.session.commit()
