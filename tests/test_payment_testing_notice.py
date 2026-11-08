"""Temporary live-payment notice: browser gate, consent and production wording."""

from html import unescape
import re
import tempfile
from unittest.mock import patch

from _support import ServerTestCase, main
from pf_server.config import load_environment_config
from pf_server.payment_testing_notice import PURCHASE_POST_PATHS

PRODUCT_URL = "https://www.patreon.com/EchterAlsFake/posts/porn-fetch-174679355?utm_medium=clipboard_copy&utm_source=copyLink&utm_campaign=postshare_creator&utm_content=join_link"


class PaymentTestingNoticeTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        settings = patch.dict(main.app.config, PAYMENT_TESTING_NOTICE_ENABLED=True,
                              NOWPAYMENTS_SANDBOX=False, PATREON_SHOP_ENABLED=True,
                              PATREON_SHOP_PRODUCT_URL=PRODUCT_URL)
        settings.start()
        self.addCleanup(settings.stop)

    def acknowledge(self, target="/"):
        return self.client.post("/payment-testing/acknowledge", data={
            "payment_testing_acknowledged": "yes", "next": target,
        })

    def test_every_fresh_browser_sees_warning_on_public_and_checkout_pages(self):
        for path in ("/", "/download", "/download/android", "/guides/download-xvideos-videos",
                     "/privacy_policy", "/porn_fetch", "/buy_license", "/payment-preview/patreon"):
            page = self.client.get(path)
            self.assertEqual(page.status_code, 200, path)
            self.assertIn('id="payment-testing-overlay"', page.text, path)
            self.assertIn('inert aria-hidden="true"', page.text)
            self.assertIn('Please do not buy anything!', page.text)
            self.assertIn('I explicitly agree not to buy any product, as I will be refunded and loose my license', page.text)
            self.assertNotIn('id="age-overlay"', page.text)
            self.assertIn('no-store', page.headers['Cache-Control'])

    def test_explicit_checkbox_is_required_then_age_gate_remains_independent(self):
        denied = self.client.post('/payment-testing/acknowledge', data={})
        self.assertEqual(denied.status_code, 400)
        self.assertIn('Tick the agreement', denied.text)
        accepted = self.acknowledge('/porn_fetch')
        self.assertEqual(accepted.status_code, 303)
        self.assertEqual(accepted.location, '/porn_fetch')
        self.assertIn('HttpOnly', accepted.headers['Set-Cookie'])
        page = self.client.get('/porn_fetch')
        self.assertNotIn('id="payment-testing-overlay"', page.text)
        self.assertIn('id="age-overlay"', page.text)
        self.assertIn('id="payment-testing-overlay"', main.app.test_client().get('/').text)
        self.client.get('/leave')
        self.assertIn('id="payment-testing-overlay"', self.client.get('/').text)

    def test_purchase_posts_cannot_skip_the_warning(self):
        with patch('pf_server.nowpayments_service.httpx.post') as provider:
            for path in PURCHASE_POST_PATHS:
                self.assertEqual(self.client.post(path, json={}).status_code, 423, path)
            provider.assert_not_called()
        self.acknowledge()
        self.assertEqual(self.client.post('/checkout/start', json={}).status_code, 400)

    def test_notice_form_preserves_local_destination_and_rejects_external_redirects(self):
        for target, expected in (("/download/android?channel=beta", "/download/android?channel=beta"),
                                 ("https://example.com", "/"), ("//example.com/", "/"),
                                 ("/\\example.com", "/")):
            self.assertEqual(self.acknowledge(target).location, expected)

    def test_notice_post_requires_csrf_when_protection_is_enabled(self):
        with patch.dict(main.app.config, WTF_CSRF_ENABLED=True):
            self.assertEqual(self.acknowledge().status_code, 400)

    def test_live_checkout_has_actual_payment_notices_and_exact_patreon_url(self):
        self.acknowledge()
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
        self.acknowledge()
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

    def test_onion_can_acknowledge_without_enabling_purchase_posts(self):
        origin = main.app.config['ONION_ORIGIN']
        self.assertIn('id="payment-testing-overlay"', self.client.get('/', base_url=origin).text)
        accepted = self.client.post('/payment-testing/acknowledge', base_url=origin,
                                    data={'payment_testing_acknowledged': 'yes', 'next': '/download'})
        self.assertEqual(accepted.status_code, 303)
        self.assertIn('HttpOnly', accepted.headers['Set-Cookie'])
        self.assertNotIn('Secure;', accepted.headers['Set-Cookie'])
        self.assertNotIn('id="payment-testing-overlay"', self.client.get('/download', base_url=origin).text)
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
