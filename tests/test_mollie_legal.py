"""Payment-method-specific legal disclosure and immutable acceptance evidence."""

import json
from unittest.mock import patch
from _support import ServerTestCase, main
from pf_server import contracts, mollie_service


class MollieLegalTests(ServerTestCase):
    def test_public_policies_cover_mollie_without_forcing_crypto_refunds(self):
        privacy = self.client.get("/privacy_policy").text
        self.assertIn("Card and bank checkout through Mollie", privacy)
        self.assertIn("Karten- und Bank-Checkout über Mollie", privacy)
        self.assertIn("independent controllers", privacy)
        self.assertIn("Keizersgracht 126", privacy)
        self.assertIn("not persist them in full", privacy)
        self.assertIn("no automatic seven-day deletion rule", privacy)
        for route in ("/terms", "/refund_policy"):
            page = self.client.get(route).text
            self.assertIn("Mollie card and bank payments", page)
            self.assertIn("original payment method", page)
            self.assertIn("does not apply to Mollie", page)
            self.assertIn("do not deduct my Mollie", page)
            self.assertIn("14 days", page)
            self.assertNotIn(
                "For declined card payments or pending authorizations, contact Banxa.",
                page,
            )

    def test_mollie_acceptance_includes_refund_rules_without_alternative_method_consent(
        self,
    ):
        with (
            main.app.app_context(),
            patch.dict(
                main.app.config,
                MOLLIE_LIVE_ENABLED=True,
                MOLLIE_LIVE_API_KEY="live_synthetic",
                MOLLIE_PROFILE_ID="pfl_QGqZL2B4xY",
            ),
        ):
            snapshot = json.loads(
                mollie_service.snapshot("DE", "2026-11-15T00:00:00+00:00")
            )
            self.assertIn("2026-11-15", snapshot["version"])
            self.assertIn("original payment method", snapshot["terms_en"])
            self.assertIn("Mollie card and bank payments", snapshot["terms_en"])
            self.assertIn("do not deduct my Mollie", snapshot["terms_en"])
            self.assertIn("Mollie payments I use the original", snapshot["withdrawal"])
            self.assertEqual(snapshot["refund_terms"], "")
            self.assertFalse(snapshot["refund_method_accepted"])
            self.assertFalse(snapshot["test_acknowledged"])
            self.assertIn("Payment alone is insufficient", snapshot["withdrawal"])

    def test_mollie_digest_changes_if_refund_wording_changes(self):
        with main.app.app_context():
            before = mollie_service.offer_digest()
            original = contracts.terms_snapshot

            def revised():
                data = original()
                data["terms_en"] += "\nChanged refund terms."
                return data

            with patch.object(contracts, "terms_snapshot", side_effect=revised):
                self.assertNotEqual(before, mollie_service.offer_digest())

    def test_existing_confirmation_uses_saved_terms_not_new_public_policy(self):
        from pf_server.extensions import db
        from pf_server.models import Transaction

        with main.app.app_context():
            old = contracts.terms_snapshot()
            old["terms_en"] = "Accepted historical wording. No new provider rules."
            old.update(
                payment_method="mollie",
                accepted_at="2026-11-14T00:00:00+00:00",
                age_confirmed=True,
                terms_accepted=True,
                immediate_supply_consent=True,
                withdrawal_acknowledged=True,
                refund_method_accepted=False,
            )
            transaction = Transaction(
                session_id="ML-historical-legal",
                provider="mollie",
                provider_payment_id="tr_HistoricalLegal",
                provider_reference_type="payment",
                environment="production",
                expected_price_amount="29.99",
                expected_price_currency="EUR",
                customer_country="Germany",
                country_evidence="local",
                geolocation_database="test",
                status="finished",
                created_at="2026-11-14T00:00:00+00:00",
                contract_snapshot=json.dumps(old),
            )
            db.session.add(transaction)
            db.session.commit()
            with patch.object(
                contracts, "render_pdf", wraps=contracts.render_pdf
            ) as render:
                first = contracts.confirmation(transaction)
            text = render.call_args.args[0]
            self.assertIn(old["terms_en"], text)
            self.assertNotIn("Mollie card and bank payments", text)
            with patch.object(
                contracts,
                "render_pdf",
                side_effect=AssertionError("must reuse saved confirmation"),
            ):
                self.assertEqual(first, contracts.confirmation(transaction))
