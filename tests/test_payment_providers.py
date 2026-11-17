"""Regression coverage for the supported purchase providers."""
from unittest.mock import patch
from _support import ServerTestCase, main


class PaymentProviderTests(ServerTestCase):
    def test_patreon_default_even_with_obsolete_stripe_flags(self):
        with patch.dict(main.app.config, {
            "PATREON_SHOP_ENABLED": True,
            "NOWPAYMENTS_SANDBOX": False,
            "STRIPE_LIVE_ENABLED": True,
            "STRIPE_TEST_ENABLED": True,
        }):
            response = self.client.get('/porn_fetch')
        self.assertEqual(response.status_code, 200)
        self.assertRegex(response.text, r'id="method-patreon"[^>]* checked')
        self.assertIn('id="method-crypto"', response.text)
        self.assertNotIn('Stripe', response.text)
        self.assertFalse(any(rule.rule.startswith('/stripe') for rule in main.app.url_map.iter_rules()))
        self.assertNotIn('process-stripe-payments', main.app.cli.commands)

    def test_legal_pages_have_no_stripe_copy(self):
        for path in ('/privacy_policy', '/terms?method=stripe', '/refund_policy?method=stripe'):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertNotIn(b'Stripe', response.data, path)
