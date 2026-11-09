"""Live checkout availability, production wording and Patreon configuration."""

from html import unescape
import re
import tempfile
from unittest.mock import patch

from _support import ServerTestCase, main
from pf_server.config import load_environment_config

PRODUCT_URL = "https://www.patreon.com/EchterAlsFake/posts/porn-fetch-174679355?utm_medium=clipboard_copy&utm_source=copyLink&utm_campaign=postshare_creator&utm_content=join_link"


class LiveCheckoutTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        settings = patch.dict(main.app.config, NOWPAYMENTS_SANDBOX=False, PATREON_SHOP_ENABLED=True,
                              PATREON_SHOP_PRODUCT_URL=PRODUCT_URL)
        settings.start()
        self.addCleanup(settings.stop)

    def test_fresh_browser_sees_public_and_checkout_pages_without_testing_warning(self):
        for path in ("/", "/download", "/download/android", "/guides/download-xvideos-videos",
                     "/privacy_policy", "/porn_fetch", "/buy_license"):
            page = self.client.get(path)
            self.assertEqual(page.status_code, 200, path)
            self.assertNotIn('payment-testing-overlay', page.text, path)
            self.assertNotIn('payment-testing-pending', page.text, path)
            self.assertNotIn('Please do not buy anything!', page.text, path)

    def test_age_confirmation_remains_required_for_checkout(self):
        page = self.client.get('/porn_fetch')
        self.assertIn('id="age-overlay"', page.text)
        self.assertIn('inert aria-hidden="true"', page.text)
        self.assertIn('no-store', page.headers['Cache-Control'])
        self.client.post('/', data={'adult_confirmed': 'yes'})
        self.assertNotIn('id="age-overlay"', self.client.get('/porn_fetch').text)
        self.client.get('/leave')
        self.assertIn('id="age-overlay"', self.client.get('/porn_fetch').text)

    def test_checkout_reaches_validation_without_warning_acknowledgment(self):
        with patch('pf_server.nowpayments_service.httpx.post') as provider:
            self.assertEqual(self.client.post('/checkout/start', json={}).status_code, 400)
            provider.assert_not_called()

    def test_live_checkout_has_actual_payment_notices_and_exact_patreon_url(self):
        for path in ('/', '/porn_fetch', '/buy_license', '/buy_card', '/privacy_policy'):
            page = unescape(re.sub(r'<[^>]+>', ' ', self.client.get(path).text)).lower()
            for stale in ('test site', 'test preview', 'sandbox', 'no real purchases'):
                self.assertNotIn(stale, page, path)
        self.assertIn('Real cryptocurrency payment.', self.client.get('/buy_license').text)
        self.assertIn('Real card or wallet payment.', self.client.get('/buy_card').text)
        self.accept_checkout('patreon')
        page = self.client.get('/payment-preview/patreon')
        self.assertIn(PRODUCT_URL, unescape(page.text))
        self.assertIn('Real payment:', page.text)

    def test_patreon_is_first_recommended_and_selected_but_preferences_are_kept(self):
        page = self.client.get('/porn_fetch').text
        self.assertLess(page.index('for="method-patreon"'), page.index('for="method-crypto"'))
        self.assertRegex(page, r'id="method-patreon"[^>]*checked')
        self.assertRegex(page, r'for="method-patreon".*?Recommended')
        self.assertNotRegex(page, r'for="method-crypto".*?Recommended')
        self.assertRegex(self.client.get('/porn_fetch?method=crypto').text, r'id="method-crypto"[^>]*checked')
        with patch.dict(main.app.config, PATREON_SHOP_ENABLED=False):
            unavailable = self.client.get('/porn_fetch').text
            self.assertRegex(unavailable, r'id="method-patreon"[^>]*disabled')
            self.assertRegex(unavailable, r'id="method-crypto"[^>]*checked')

    def test_machine_health_and_updates_are_not_html_gated(self):
        self.assertEqual(self.client.get('/ping').text, 'Success')
        self.assertNotIn('payment-testing-overlay', self.client.get('/robots.txt').text)

    def test_onion_is_accessible_without_warning_and_keeps_purchase_posts_disabled(self):
        origin = main.app.config['ONION_ORIGIN']
        for path in ('/', '/download'):
            page = self.client.get(path, base_url=origin)
            self.assertEqual(page.status_code, 200)
            self.assertNotIn('payment-testing-overlay', page.text)
        self.assertEqual(self.client.post('/create-crypto-payment', base_url=origin, json={}).status_code, 404)


class PatreonPurchasePostConfigurationTests(ServerTestCase):
    def test_supplied_post_is_accepted_and_homepage_still_rejected(self):
        # Validate the URL before unrelated mandatory live-shop credentials.
        with tempfile.TemporaryDirectory() as directory:
            for url, accepted in ((PRODUCT_URL, True),
                                  ('https://www.patreon.com/c/echteralsfake/shop/premium-123', True),
                                  ('https://www.patreon.com/c/echteralsfake/shop', False),
                                  ('https://www.patreon.com/EchterAlsFake/posts/', False)):
                settings = dict(SECRET_KEY='test', NOWPAYMENTS_SANDBOX='false',
                                NOWPAYMENTS_API_KEY='test', NOWPAYMENTS_IPN_SECRET='test',
                                PATREON_SHOP_ENABLED='true', PATREON_SHOP_PRODUCT_URL=url)
                with self.assertRaises(ValueError) as failure:
                    load_environment_config(directory, settings)
                if accepted:
                    self.assertNotIn('specific Shop product or purchase post', str(failure.exception))
                else:
                    self.assertIn('specific Shop product or purchase post', str(failure.exception))
