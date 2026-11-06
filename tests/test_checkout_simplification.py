"""Patreon Shop instructions and the two-option payment picker."""
from unittest.mock import patch
from _support import ServerTestCase, main

class CheckoutSimplificationTests(ServerTestCase):
    def test_card_is_not_offered_even_with_old_preference(self):
        page = self.client.get('/porn_fetch?method=card').text
        self.assertIn('id="method-crypto"', page)
        self.assertIn('id="method-patreon"', page)
        self.assertNotIn('id="method-card"', page)
        self.assertNotIn('Through Onramp Pay', page)
        self.assertIn('free Patreon account required', page)
        self.assertNotIn('recurring membership until cancelled', page)

    def test_no_script_handoff_explains_shop_and_requires_confirmation(self):
        self.accept_checkout('patreon')
        page = self.client.get('/payment-preview/patreon')
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'https://pornfetch.to/activate', page.data)
        self.assertIn(b'up to 10 minutes', page.data)
        self.assertIn(b'one-time purchase', page.data)
        self.assertEqual(self.client.post('/payment-preview/patreon', data={}).status_code, 400)
        accepted = self.client.post('/payment-preview/patreon', data={'confirm_no_payment':'yes'})
        self.assertIn(b'https://www.patreon.com/c/echteralsfake/shop', accepted.data)

    def test_homepage_links_to_enabled_shop_claim_form(self):
        with patch.dict(main.app.config, PATREON_SHOP_ENABLED=True):
            self.assertIn(b'Already bought on Patreon? Get your license', self.client.get('/').data)
            self.assertEqual(self.client.get('/activate').status_code, 200)
