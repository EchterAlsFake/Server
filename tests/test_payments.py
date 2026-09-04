"""NOWPayments, invoice, and downloadable-license tests."""

import json
import os
import string
from unittest.mock import patch

from _support import ServerTestCase, main

import pf_server.licensing as licensing
import pf_server.nowpayments_service as nowpayments_service
from pf_server.models import License, Transaction


class PaymentTests(ServerTestCase):
    def add_transaction(
        self,
        session_id: str,
        provider_id: str,
        *,
        reference_type: str = "invoice",
        expected_pay_amount: str | None = None,
        expected_pay_currency: str | None = None,
        status: str = "pending",
        processing_started_at: str | None = None,
    ) -> None:
        with main.app.app_context():
            main.db.session.add(
                Transaction(
                    session_id=session_id,
                    provider_payment_id=provider_id,
                    provider_reference_type=reference_type,
                    expected_price_amount="30" if reference_type == "payment" else "19.99",
                    expected_price_currency="eur",
                    customer_country="Germany",
                    country_evidence="customer_declaration+local_ip_geolocation",
                    geolocation_database="DB-IP City Lite test fixture",
                    expected_pay_amount=expected_pay_amount,
                    expected_pay_currency=expected_pay_currency,
                    status=status,
                    processing_started_at=processing_started_at,
                    created_at="2026-01-01T00:00:00Z",
                )
            )
            main.db.session.commit()

    def post_nowpayments(self, payload: dict):
        return self.client.post(
            "/nowpayments-ipn",
            data=json.dumps(payload),
            headers={"x-nowpayments-sig": self.nowpayments_signature(payload)},
            base_url="https://api.echteralsfake.me",
        )

    def test_payment_webhooks_are_available_only_on_api_subdomain(self):
        wrong_host = self.post_patreon(
            self.eligible_patreon_payload(),
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
        response = self.client.post(
            "/nowpayments-ipn",
            data=json.dumps(payload),
            headers={"x-nowpayments-sig": self.nowpayments_signature(payload)},
            base_url="https://api.echteralsfake.me",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), "OK")

    def test_nowpayments_signature_is_checked_before_payload_schema(self):
        response = self.client.post(
            "/nowpayments-ipn",
            data=json.dumps({"order_id": 123, "payment_status": "waiting"}),
            headers={"x-nowpayments-sig": "0" * 128},
            base_url="https://api.echteralsfake.me",
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.get_data(as_text=True),
            "Invalid signature verification",
        )

    def test_nowpayments_payload_types_and_ranges_are_validated_without_coercion(self):
        for payload in (
            {"payment_status": "waiting"},
            {"order_id": 123, "payment_status": "waiting"},
            {"order_id": "../../main", "payment_status": "waiting"},
            {"order_id": "NP-test", "payment_id": True},
            {"order_id": "NP-test", "actually_paid": -1},
        ):
            with self.subTest(payload=payload):
                response = self.client.post(
                    "/nowpayments-ipn",
                    data=json.dumps(payload),
                    headers={"x-nowpayments-sig": self.nowpayments_signature(payload)},
                    base_url="https://api.echteralsfake.me",
                )

                self.assertEqual(response.status_code, 400)
                self.assertEqual(
                    response.get_json(),
                    {"error": "Invalid payload schema"},
                )

    def test_finished_invoice_is_validated_completed_and_idempotent(self):
        self.add_transaction("NP-finished-invoice", "invoice-123")
        payload = {
            "order_id": "NP-finished-invoice",
            "payment_id": "payment-456",
            "invoice_id": "invoice-123",
            "payment_status": "finished",
            "price_amount": 19.99,
            "price_currency": "EUR",
            "pay_amount": 0.01,
            "actually_paid": 0.01,
            "pay_currency": "btc",
        }

        first = self.post_nowpayments(payload)
        second = self.post_nowpayments(payload)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        with main.app.app_context():
            transaction = main.db.session.get(Transaction, "NP-finished-invoice")
            self.assertEqual(transaction.status, "finished")

    def test_finished_direct_payment_accepts_documented_string_or_integer_ids(self):
        for session_id, stored_id, callback_id in (
            ("NP-string-payment", "payment-string", "payment-string"),
            ("NP-integer-payment", "123456", 123456),
        ):
            with self.subTest(callback_id=callback_id):
                self.add_transaction(
                    session_id,
                    stored_id,
                    reference_type="payment",
                    expected_pay_amount="0.5",
                    expected_pay_currency="ltc",
                )
                response = self.post_nowpayments(
                    {
                        "order_id": session_id,
                        "payment_id": callback_id,
                        "payment_status": "finished",
                        "price_amount": 30,
                        "price_currency": "eur",
                        "pay_amount": 0.5,
                        "actually_paid": 0.5,
                        "pay_currency": "LTC",
                    }
                )
                self.assertEqual(response.status_code, 200)
                with main.app.app_context():
                    transaction = main.db.session.get(Transaction, session_id)
                    self.assertEqual(transaction.status, "finished")

    def test_finished_payment_mismatches_are_acknowledged_without_fulfillment(self):
        cases = {
            "reference": {"invoice_id": "wrong-invoice"},
            "amount": {"price_amount": 1},
            "price-currency": {"price_currency": "usd"},
        }
        for suffix, override in cases.items():
            with self.subTest(reason=suffix):
                session_id = f"NP-mismatch-{suffix}"
                self.add_transaction(session_id, f"invoice-{suffix}")
                payload = {
                    "order_id": session_id,
                    "payment_id": f"payment-{suffix}",
                    "invoice_id": f"invoice-{suffix}",
                    "payment_status": "finished",
                    "price_amount": 19.99,
                    "price_currency": "eur",
                    "actually_paid": 0.01,
                    "pay_currency": "btc",
                    **override,
                }
                response = self.post_nowpayments(payload)
                self.assertEqual(response.status_code, 200)
                with main.app.app_context():
                    transaction = main.db.session.get(Transaction, session_id)
                    self.assertEqual(transaction.status, "pending")

    def test_direct_payment_asset_and_actual_amount_are_verified(self):
        for suffix, pay_currency, actually_paid in (
            ("currency", "btc", 0.5),
            ("underpaid", "ltc", 0.49),
        ):
            with self.subTest(reason=suffix):
                session_id = f"NP-direct-{suffix}"
                self.add_transaction(
                    session_id,
                    f"payment-{suffix}",
                    reference_type="payment",
                    expected_pay_amount="0.5",
                    expected_pay_currency="ltc",
                )
                response = self.post_nowpayments(
                    {
                        "order_id": session_id,
                        "payment_id": f"payment-{suffix}",
                        "payment_status": "finished",
                        "price_amount": 30,
                        "price_currency": "eur",
                        "pay_amount": 0.5,
                        "actually_paid": actually_paid,
                        "pay_currency": pay_currency,
                    }
                )
                self.assertEqual(response.status_code, 200)
                with main.app.app_context():
                    transaction = main.db.session.get(Transaction, session_id)
                    self.assertEqual(transaction.status, "pending")

    def test_unknown_and_busy_finished_payments_request_provider_retry(self):
        payload = {
            "order_id": "NP-not-stored-yet",
            "payment_id": "payment-unknown",
            "invoice_id": "invoice-unknown",
            "payment_status": "finished",
            "price_amount": 19.99,
            "price_currency": "eur",
            "actually_paid": 0.01,
            "pay_currency": "btc",
        }
        unknown = self.post_nowpayments(payload)

        self.add_transaction(
            "NP-busy",
            "invoice-busy",
            status="processing",
            processing_started_at="2999-01-01T00:00:00+00:00",
        )
        busy_payload = {**payload, "order_id": "NP-busy", "invoice_id": "invoice-busy"}
        busy = self.post_nowpayments(busy_payload)

        for response in (unknown, busy):
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.headers["Retry-After"], "30")

    def test_stale_payment_processing_lease_is_recovered(self):
        self.add_transaction(
            "NP-stale",
            "invoice-stale",
            status="processing",
            processing_started_at="2000-01-01T00:00:00+00:00",
        )
        response = self.post_nowpayments(
            {
                "order_id": "NP-stale",
                "payment_id": "payment-stale",
                "invoice_id": "invoice-stale",
                "payment_status": "finished",
                "price_amount": 19.99,
                "price_currency": "eur",
                "actually_paid": 0.01,
                "pay_currency": "btc",
            }
        )

        self.assertEqual(response.status_code, 200)
        with main.app.app_context():
            transaction = main.db.session.get(Transaction, "NP-stale")
            self.assertEqual(transaction.status, "finished")
            self.assertIsNone(transaction.processing_started_at)

    def test_failed_payment_storage_releases_the_claim_for_retry(self):
        self.add_transaction("NP-storage-retry", "invoice-storage-retry")
        payload = {
            "order_id": "NP-storage-retry",
            "payment_id": "payment-storage-retry",
            "invoice_id": "invoice-storage-retry",
            "payment_status": "finished",
            "price_amount": 19.99,
            "price_currency": "eur",
            "actually_paid": 0.01,
            "pay_currency": "btc",
        }

        with patch.object(
            nowpayments_service,
            "save_invoice",
            side_effect=OSError("simulated storage failure"),
        ):
            failed = self.post_nowpayments(payload)
        with main.app.app_context():
            transaction = main.db.session.get(Transaction, "NP-storage-retry")
            self.assertEqual(transaction.status, "pending")
            self.assertIsNone(transaction.processing_started_at)

        retried = self.post_nowpayments(payload)

        self.assertEqual(failed.status_code, 503)
        self.assertEqual(failed.headers["Retry-After"], "30")
        self.assertEqual(retried.status_code, 200)
        with main.app.app_context():
            transaction = main.db.session.get(Transaction, "NP-storage-retry")
            self.assertEqual(transaction.status, "finished")

    def test_nonfinal_and_repeated_deposit_events_never_fulfill(self):
        for suffix, overrides in (
            ("paid", {"payment_status": "paid"}),
            ("repeated", {"payment_status": "finished", "parent_payment_id": 123}),
        ):
            with self.subTest(status=suffix):
                session_id = f"NP-nonfinal-{suffix}"
                self.add_transaction(session_id, f"invoice-{suffix}")
                payload = {
                    "order_id": session_id,
                    "payment_id": f"payment-{suffix}",
                    "invoice_id": f"invoice-{suffix}",
                    "price_amount": 19.99,
                    "price_currency": "eur",
                    "actually_paid": 0.01,
                    "pay_currency": "btc",
                    **overrides,
                }
                response = self.post_nowpayments(payload)
                self.assertEqual(response.status_code, 200)
                with main.app.app_context():
                    transaction = main.db.session.get(Transaction, session_id)
                    self.assertEqual(transaction.status, "pending")

    def test_new_crypto_invoices_receive_the_api_subdomain_callback(self):
        class FakeNowPaymentsResponse:
            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return {
                    "id": "invoice-123",
                    "invoice_url": "https://pay.example/invoice-123",
                }

        with (
            patch.dict(
                main.app.config,
                {
                    "NOWPAYMENTS_API_KEY": "test-api-key",
                    "APP_DOMAIN": "https://echteralsfake.me",
                },
            ),
            patch.object(
                nowpayments_service.httpx,
                "post",
                return_value=FakeNowPaymentsResponse(),
            ) as post,
        ):
            response = self.client.post(
                "/create-crypto-payment",
                json={"country": "DE"},
                base_url="https://attacker.invalid",
            )

        self.assertEqual(response.status_code, 200)
        request_payload = post.call_args.kwargs["json"]
        self.assertEqual(
            request_payload["ipn_callback_url"],
            "https://api.echteralsfake.me/nowpayments-ipn",
        )
        self.assertEqual(
            request_payload["success_url"],
            f"https://echteralsfake.me/buy_success?session_id={response.get_json()['session_id']}",
        )
        with main.app.app_context():
            transaction = main.db.session.get(
                Transaction, response.get_json()["session_id"]
            )
            self.assertEqual(transaction.provider_reference_type, "invoice")
            self.assertEqual(transaction.expected_price_amount, "19.99")
            self.assertEqual(transaction.expected_price_currency, "eur")
            self.assertIsNone(transaction.expected_pay_amount)
            self.assertEqual(transaction.customer_country, "Germany")
            self.assertEqual(
                transaction.country_evidence,
                "customer_declaration+local_ip_geolocation",
            )
            self.assertEqual(
                transaction.geolocation_database,
                "DB-IP City Lite test fixture",
            )

    def test_new_direct_payments_store_callback_validation_expectations(self):
        class FakeNowPaymentsResponse:
            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return {
                    "payment_id": "payment-direct-123",
                    "pay_address": "litecoin-address",
                    "pay_amount": 0.5,
                    "pay_currency": "ltc",
                }

        with (
            patch.dict(main.app.config, {"NOWPAYMENTS_API_KEY": "test-api-key"}),
            patch.object(
                nowpayments_service.httpx,
                "post",
                return_value=FakeNowPaymentsResponse(),
            ),
        ):
            response = self.client.post(
                "/create-fiat-payment",
                json={"email": "buyer@example.com", "country": "DE"},
            )

        self.assertEqual(response.status_code, 200)
        with main.app.app_context():
            transaction = main.db.session.get(
                Transaction, response.get_json()["session_id"]
            )
            self.assertEqual(transaction.provider_payment_id, "payment-direct-123")
            self.assertEqual(transaction.provider_reference_type, "payment")
            self.assertEqual(transaction.expected_price_amount, "30")
            self.assertEqual(transaction.expected_price_currency, "eur")
            self.assertEqual(transaction.expected_pay_amount, "0.5")
            self.assertEqual(transaction.expected_pay_currency, "ltc")
            self.assertFalse(hasattr(transaction, "email"))

    def test_email_translation_catalogs_have_matching_keys_and_placeholders(self):
        for language in ("de", "en"):
            catalog_path = os.path.join(
                os.path.dirname(main.__file__),
                "i18n",
                f"license_email_{language}.json",
            )
            with open(catalog_path, encoding="utf-8") as catalog_file:
                self.assertIs(json.load(catalog_file)["reviewed"], False)

        with main.app.app_context():
            catalogs = {
                language: licensing.load_license_email_catalog(language)
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

    def test_repeated_download_reuses_the_same_license(self):
        with main.app.app_context():
            main.db.session.add(
                Transaction(
                    session_id="NP-repeat-download",
                    provider_payment_id="invoice-repeat-download",
                    provider_reference_type="invoice",
                    expected_price_amount="19.99",
                    expected_price_currency="eur",
                    customer_country="Germany",
                    country_evidence="customer_declaration+local_ip_geolocation",
                    geolocation_database="DB-IP City Lite test fixture",
                    status="finished",
                    created_at="2026-01-01T00:00:00Z",
                )
            )
            main.db.session.commit()

        first = self.client.get("/download_license?session_id=NP-repeat-download")
        second = self.client.get("/download_license?session_id=NP-repeat-download")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.data, second.data)
        with main.app.app_context():
            licenses = License.query.filter_by(
                issuance_reference="invoice-repeat-download"
            ).all()
            self.assertEqual(len(licenses), 1)

    def test_payment_simulation_is_hidden_in_production(self):
        with patch.dict(main.app.config, {"NOWPAYMENTS_SANDBOX": False}):
            response = self.client.post("/simulate-payment-success", json={})

        self.assertEqual(response.status_code, 404)

    def test_payment_simulation_creates_a_downloadable_invoice(self):
        with main.app.app_context():
            main.db.session.add(
                Transaction(
                    session_id="NP-simulated-invoice",
                    provider_payment_id="mock-invoice",
                    provider_reference_type="invoice",
                    expected_price_amount="19.99",
                    expected_price_currency="eur",
                    customer_country="Germany",
                    country_evidence="customer_declaration+local_ip_geolocation",
                    geolocation_database="DB-IP City Lite test fixture",
                    status="pending",
                    created_at="2026-01-01T00:00:00Z",
                )
            )
            main.db.session.commit()

        simulated = self.client.post(
            "/simulate-payment-success",
            json={"session_id": "NP-simulated-invoice"},
        )
        invoice = self.client.get("/download_invoice?session_id=NP-simulated-invoice")

        self.assertEqual(simulated.status_code, 200)
        self.assertEqual(invoice.status_code, 200)
        self.assertEqual(invoice.mimetype, "application/pdf")
        self.assertTrue(invoice.data.startswith(b"%PDF"))
