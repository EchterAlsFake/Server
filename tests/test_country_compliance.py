"""Checkout country evidence, local geolocation, and restriction tests."""

from unittest.mock import Mock, patch

from _support import ServerTestCase, main

import pf_server.payment_routes as payment_routes
from pf_server.country_service import (
    CheckoutCountryMiddleware,
    CountryEvidence,
    LocalCountryResolver,
    checkout_country_decision,
)
from pf_server.models import Transaction
from pf_server.tax_service import country_transaction_summary


class CountryComplianceTests(ServerTestCase):
    def test_checkout_middleware_uses_ip_once_then_strips_forwarding_headers(self):
        resolver = Mock()
        resolver.lookup.return_value = CountryEvidence(
            status="found",
            country_code="DE",
            subdivision="Saxony-Anhalt",
            database_label="DB-IP fixture",
        )
        captured_environ = {}

        def application(environ, start_response):
            captured_environ.update(environ)
            start_response("200 OK", [])
            return [b"OK"]

        middleware = CheckoutCountryMiddleware(
            application, resolver, "X-Forwarded-For"
        )
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/create-crypto-payment",
            "HTTP_X_FORWARDED_FOR": "203.0.113.10",
            "REMOTE_ADDR": "127.0.0.1",
        }

        response = middleware(environ, lambda _status, _headers: None)

        self.assertEqual(response, [b"OK"])
        resolver.lookup.assert_called_once_with("203.0.113.10")
        self.assertNotIn("HTTP_X_FORWARDED_FOR", captured_environ)
        self.assertNotIn("REMOTE_ADDR", captured_environ)
        self.assertEqual(captured_environ["PF_COUNTRY_CODE"], "DE")
        self.assertNotIn("203.0.113.10", repr(captured_environ))

    def test_local_resolver_returns_only_country_and_subdivision(self):
        class FakeReader:
            @staticmethod
            def get(address):
                if address == "203.0.113.10":
                    return {
                        "country": {"iso_code": "UA"},
                        "subdivisions": [{"names": {"en": "Kyiv City"}}],
                    }
                return None

        resolver = LocalCountryResolver("unused.mmdb", "DB-IP fixture")
        resolver._reader = FakeReader()

        evidence = resolver.lookup("203.0.113.10")

        self.assertEqual(evidence.status, "found")
        self.assertEqual(evidence.country_code, "UA")
        self.assertEqual(evidence.subdivision, "Kyiv City")
        self.assertFalse(hasattr(evidence, "ip_address"))

    def test_country_decision_requires_matching_evidence(self):
        matched = checkout_country_decision(
            "DE",
            {
                "PF_COUNTRY_STATUS": "found",
                "PF_COUNTRY_CODE": "DE",
                "PF_COUNTRY_SUBDIVISION": "Saxony-Anhalt",
                "PF_COUNTRY_DATABASE": "DB-IP fixture",
            },
        )
        mismatch = checkout_country_decision(
            "DE",
            {
                "PF_COUNTRY_STATUS": "found",
                "PF_COUNTRY_CODE": "FR",
                "PF_COUNTRY_DATABASE": "DB-IP fixture",
            },
        )

        self.assertEqual(matched.status, "verified")
        self.assertEqual(matched.country_name, "Germany")
        self.assertEqual(mismatch.status, "mismatch")

    def test_requested_country_and_ukraine_region_policies_are_fail_closed(self):
        base = {
            "PF_COUNTRY_STATUS": "found",
            "PF_COUNTRY_DATABASE": "DB-IP fixture",
        }
        cases = (
            ("KP", {**base, "PF_COUNTRY_CODE": "DE"}, "restricted"),
            ("SY", {**base, "PF_COUNTRY_CODE": "SY"}, "restricted"),
            (
                "UA",
                {
                    **base,
                    "PF_COUNTRY_CODE": "UA",
                    "PF_COUNTRY_SUBDIVISION": "Donetsk Oblast",
                },
                "restricted",
            ),
            ("UA", {**base, "PF_COUNTRY_CODE": "UA"}, "restricted"),
            (
                "UA",
                {
                    **base,
                    "PF_COUNTRY_CODE": "UA",
                    "PF_COUNTRY_SUBDIVISION": "Kyiv City",
                },
                "verified",
            ),
        )
        for declared, evidence, expected in cases:
            with self.subTest(declared=declared, evidence=evidence):
                self.assertEqual(
                    checkout_country_decision(declared, evidence).status,
                    expected,
                )

    def test_checkout_blocks_restricted_mismatched_and_unverifiable_locations(self):
        with patch.dict(main.app.config, {"NOWPAYMENTS_API_KEY": "test-api-key"}):
            restricted = self.client.post(
                "/create-crypto-payment", json={"country": "KP"}
            )
            self.mock_country_lookup.return_value = CountryEvidence(
                status="found",
                country_code="FR",
                subdivision="Île-de-France",
                database_label="DB-IP fixture",
            )
            mismatch = self.client.post(
                "/create-crypto-payment", json={"country": "DE"}
            )
            self.mock_country_lookup.return_value = CountryEvidence(
                status="database_unavailable"
            )
            unavailable = self.client.post(
                "/create-crypto-payment", json={"country": "DE"}
            )

        self.assertEqual(restricted.status_code, 451)
        self.assertEqual(mismatch.status_code, 409)
        self.assertEqual(unavailable.status_code, 503)
        with main.app.app_context():
            self.assertEqual(Transaction.query.count(), 0)

    def test_verified_country_is_passed_to_storage_without_the_ip_address(self):
        with (
            patch.dict(main.app.config, {"NOWPAYMENTS_API_KEY": "test-api-key"}),
            patch.object(
                payment_routes,
                "create_crypto_invoice",
                return_value={
                    "session_id": "NP-country-record",
                    "invoice_url": "https://pay.example/invoice",
                },
            ) as create_invoice,
        ):
            response = self.client.post(
                "/create-crypto-payment",
                json={"country": "DE"},
                headers={"X-Forwarded-For": "203.0.113.10"},
            )

        self.assertEqual(response.status_code, 200)
        create_invoice.assert_called_once_with(
            "Germany",
            "customer_declaration+local_ip_geolocation",
            "DB-IP City Lite test fixture",
        )
        self.assertNotIn("203.0.113.10", repr(create_invoice.call_args))

    def test_tax_summary_aggregates_country_totals_without_identifiers(self):
        with main.app.app_context():
            for suffix, country, amount in (
                ("fr-one", "France", "19.99"),
                ("fr-two", "France", "30"),
                ("de", "Germany", "19.99"),
            ):
                main.db.session.add(
                    Transaction(
                        session_id=f"NP-tax-{suffix}",
                        provider_payment_id=f"provider-tax-{suffix}",
                        provider_reference_type="invoice",
                        expected_price_amount=amount,
                        expected_price_currency="eur",
                        customer_country=country,
                        country_evidence=(
                            "customer_declaration+local_ip_geolocation"
                        ),
                        geolocation_database="DB-IP fixture",
                        status="finished",
                        finished_at="2026-09-01T10:00:00+00:00",
                        created_at="2026-09-01T09:00:00+00:00",
                    )
                )
            main.db.session.commit()

            summary = country_transaction_summary(2026)

        self.assertEqual(
            summary["eu_cross_border_configured_price_total_eur"], "49.99"
        )
        self.assertEqual(len(summary["rows"]), 2)
        self.assertNotIn("NP-tax", repr(summary))
        self.assertNotIn("provider-tax", repr(summary))
