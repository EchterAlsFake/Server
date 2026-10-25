"""Shared consent, optional delivery privacy, and signed-payment fulfillment."""

import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cryptography.fernet import Fernet
import httpx

from _support import ServerTestCase, main, drain_payment_receipts
from pf_server import crypto_delivery, nowpayments_service
from pf_server.checkout_consent import CONSENT_VERSION
from pf_server.models import CryptoLicenseDelivery, License, Transaction


class CheckoutRefreshTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.config = patch.dict(
            main.app.config,
            {
                "NOWPAYMENTS_API_KEY": "synthetic-test-key",
                "NOWPAYMENTS_SANDBOX": True,
                "LICENSE_DELIVERY_ENCRYPTION_KEY": Fernet.generate_key().decode(),
                "LICENSE_SMTP_HOST": "localhost",
                "LICENSE_EMAIL_FROM": "test@example.com",
            },
        )
        self.config.start()
        self.addCleanup(self.config.stop)

    @staticmethod
    def consent(method="crypto"):
        return dict(
            payment_method=method,
            country="DE",
            age_confirmed=True,
            terms_accepted=True,
            withdrawal_accepted=True,
            test_acknowledged=True,
        )

    @staticmethod
    def payment(**changes):
        value = dict(
            country="DE",
            age_confirmed=True,
            terms_accepted=True,
            withdrawal_accepted=True,
            test_acknowledged=True,
            no_email_acknowledged=True,
        )
        value.update(changes)
        return value

    def test_shared_confirmations_are_required_and_carried_to_all_routes(self):
        for field in self.consent():
            value = self.consent()
            del value[field]
            response = self.client.post("/checkout/start", json=value)
            self.assertEqual(response.status_code, 400, field)
        for method, target in [
            ("crypto", "/buy_license"),
            ("patreon", "/payment-preview/patreon"),
            ("card", "/payment-preview/card"),
        ]:
            response = self.client.post("/checkout/start", json=self.consent(method))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json["next"], target)
        with self.client.session_transaction() as state:
            self.assertEqual(state["checkout_consent"]["country"], "DE")
            self.assertEqual(state["checkout_consent"]["version"], CONSENT_VERSION)
        for route in ("/buy_license", "/buy_card"):
            page = self.client.get(route).data
            self.assertIn(b"confirmations", page)
            self.assertNotIn(b'id="checkout-country"', page)
            self.assertNotIn(b'id="chk-age"', page)

    def test_shared_confirmation_rejects_malformed_values(self):
        for field in ("country", "payment_method"):
            for value in ([], {}, 42, None):
                data = self.consent()
                data[field] = value
                self.assertEqual(
                    self.client.post("/checkout/start", json=data).status_code, 400
                )

    def test_card_tax_id_requirement_is_visible_for_the_selected_eu_country(self):
        for country, expected in (("DE", "Germany"), ("FR", "France"), ("CA", None)):
            with self.subTest(country=country):
                consent = dict(self.consent("card"), country=country)
                self.assertEqual(
                    self.client.post("/checkout/start", json=consent).status_code, 200
                )
                purchase = self.client.get("/buy_card").data.split(
                    b'<section class="checkout-faq"'
                )[0]
                if expected:
                    self.assertIn(
                        f"Banxa requires your Tax ID (TIN) for {expected}.".encode(),
                        purchase,
                    )
                else:
                    self.assertNotIn(b"checkout-tax-id", purchase)

    def test_no_js_confirmation_flow_and_expiration(self):
        response = self.client.post(
            "/checkout/start",
            data={
                key: ("yes" if value is True else value)
                for key, value in self.consent().items()
            },
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.location, "/buy_license")
        with self.client.session_transaction() as state:
            consent = state["checkout_consent"].copy()
            consent["accepted_at"] = time.time() - 3601
            state["checkout_consent"] = consent
        page = self.client.get("/buy_license").data
        self.assertIn(b'data-confirmed="false"', page)
        self.assertIn(b'id="pay-btn" class="nowpayments-btn" disabled', page)

    def test_shared_start_is_csrf_protected(self):
        with patch.dict(main.app.config, {"WTF_CSRF_ENABLED": True}):
            self.assertEqual(
                self.client.post("/checkout/start", json=self.consent()).status_code,
                400,
            )

    def test_crypto_rejects_missing_confirmations_bad_email_and_no_email_without_ack(
        self,
    ):
        with patch.object(nowpayments_service.httpx, "post") as provider:
            for changes in [
                dict(age_confirmed=False),
                dict(withdrawal_accepted=False),
                dict(delivery_email="bad-address"),
                dict(delivery_email="x@example.com\r\nBcc: y@example.com"),
                dict(no_email_acknowledged=False),
                dict(delivery_email=12),
            ]:
                response = self.client.post(
                    "/create-crypto-payment", json=self.payment(**changes)
                )
                self.assertEqual(response.status_code, 400, changes)
            provider.assert_not_called()

    def create_invoice(self, email=None):
        response = httpx.Response(
            200,
            json={
                "id": "invoice-test",
                "invoice_url": "https://sandbox.nowpayments.io/payment/invoice-test",
            },
            request=httpx.Request(
                "POST", "https://api-sandbox.nowpayments.io/v1/invoice"
            ),
        )
        with patch.object(
            nowpayments_service.httpx, "post", return_value=response
        ) as provider:
            result = self.client.post(
                "/create-crypto-payment",
                json=self.payment(
                    **({"delivery_email": email} if email is not None else {})
                ),
            )
        self.assertEqual(result.status_code, 200, result.json)
        self.assertNotIn("email", repr(provider.call_args.kwargs["json"]))
        return result.json["session_id"]

    def finish(self, session_id, *, signed=True):
        payload = dict(
            order_id=session_id,
            invoice_id="invoice-test",
            payment_id="payment-test",
            payment_status="finished",
            price_amount=19.99,
            price_currency="eur",
            pay_amount=0.01,
            actually_paid=0.01,
            pay_currency="btc",
        )
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

    def test_no_email_checkout_stores_no_recipient_and_shows_signed_license(self):
        session_id = self.create_invoice()
        with main.app.app_context():
            self.assertIsNone(main.db.session.get(CryptoLicenseDelivery, session_id))
        with patch.object(crypto_delivery, "send_license_email") as send:
            self.assertEqual(self.finish(session_id).status_code, 200)
            self.assertEqual(
                self.client.get(
                    "/check-payment-status", query_string={"session_id": session_id}
                ).json["status"],
                "finished",
            )
            status = self.client.get(
                "/check-payment-status", query_string={"session_id": session_id}
            ).json
            self.assertTrue(status["license_key"].startswith("key/"))
            self.assertNotIn("delivery_status", status)
            send.assert_not_called()

    def test_optional_email_is_encrypted_not_forwarded_and_sent_once_after_signed_payment(
        self,
    ):
        session_id = self.create_invoice("buyer@example.com")
        with main.app.app_context():
            record = main.db.session.get(CryptoLicenseDelivery, session_id)
            self.assertNotIn("buyer@example.com", record.recipient_encrypted)
            self.assertEqual(
                crypto_delivery.cipher()
                .decrypt(record.recipient_encrypted.encode())
                .decode(),
                "buyer@example.com",
            )
        with patch.object(crypto_delivery, "send_license_email") as send:
            self.assertEqual(self.finish(session_id, signed=False).status_code, 403)
            send.assert_not_called()
            self.assertEqual(self.finish(session_id).status_code, 200)
            self.assertEqual(self.finish(session_id).status_code, 200)
            send.assert_called_once()
            self.assertEqual(send.call_args.args[0], "buyer@example.com")
        with main.app.app_context():
            record = main.db.session.get(CryptoLicenseDelivery, session_id)
            self.assertEqual(record.delivery_status, "sent")
            self.assertIsNone(record.recipient_encrypted)
            self.assertEqual(License.query.count(), 1)

    def test_failed_smtp_does_not_undo_payment_and_retry_reuses_license(self):
        session_id = self.create_invoice("buyer@example.com")
        with patch.object(
            crypto_delivery,
            "send_license_email",
            side_effect=RuntimeError("SMTP failure"),
        ):
            self.assertEqual(self.finish(session_id).status_code, 200)
        with main.app.app_context():
            self.assertEqual(
                main.db.session.get(Transaction, session_id).status, "finished"
            )
            self.assertEqual(
                main.db.session.get(CryptoLicenseDelivery, session_id).delivery_status,
                "failed",
            )
            original_key = License.query.one().signed_key
            with patch.object(crypto_delivery, "send_license_email") as send:
                self.assertEqual(crypto_delivery.retry_crypto_deliveries(), 1)
                send.assert_called_once()
                self.assertEqual(
                    json.loads(send.call_args.args[1])["license_key"], original_key
                )
            self.assertEqual(License.query.count(), 1)

    def test_delivery_lease_excludes_concurrent_send_and_purges_expired_pii(self):
        session_id = self.create_invoice("buyer@example.com")
        with main.app.app_context():
            transaction = main.db.session.get(Transaction, session_id)
            transaction.status = "finished"
            record = main.db.session.get(CryptoLicenseDelivery, session_id)
            record.delivery_status = "sending"
            record.lease_expires_at = (
                datetime.now(timezone.utc) + timedelta(minutes=5)
            ).isoformat()
            main.db.session.commit()
            with patch.object(crypto_delivery, "send_license_email") as send:
                self.assertEqual(
                    crypto_delivery.deliver_crypto_license(session_id), "busy"
                )
                send.assert_not_called()
            record.created_at = (
                datetime.now(timezone.utc) - timedelta(days=8)
            ).isoformat()
            record.lease_expires_at = (
                datetime.now(timezone.utc) - timedelta(minutes=1)
            ).isoformat()
            main.db.session.commit()
            self.assertEqual(crypto_delivery.retry_crypto_deliveries(), 0)
            self.assertIsNone(record.recipient_encrypted)
            self.assertEqual(record.delivery_status, "expired")

    def test_late_payment_does_not_revive_expired_email(self):
        session_id = self.create_invoice("buyer@example.com")
        with main.app.app_context():
            record = main.db.session.get(CryptoLicenseDelivery, session_id)
            record.created_at = (
                datetime.now(timezone.utc) - timedelta(days=8)
            ).isoformat()
            main.db.session.commit()
        with patch.object(crypto_delivery, "send_license_email") as send:
            self.assertEqual(self.finish(session_id).status_code, 200)
            send.assert_not_called()
        with main.app.app_context():
            record = main.db.session.get(CryptoLicenseDelivery, session_id)
            self.assertIsNone(record.recipient_encrypted)
            self.assertEqual(record.delivery_status, "expired")
            self.assertEqual(
                main.db.session.get(Transaction, session_id).status, "finished"
            )

    def test_email_configuration_missing_fails_before_provider_creation(self):
        with (
            patch.dict(main.app.config, {"LICENSE_SMTP_HOST": ""}),
            patch.object(nowpayments_service.httpx, "post") as provider,
        ):
            response = self.client.post(
                "/create-crypto-payment",
                json=self.payment(delivery_email="buyer@example.com"),
            )
            self.assertEqual(response.status_code, 503)
            provider.assert_not_called()
