"""Behavioral regressions for marketing, age sessions and release selection."""

from unittest.mock import patch


from _support import ServerTestCase, main
from pf_server import product_catalog


class MarketingTests(ServerTestCase):
    def test_confirmation_reveals_pages_for_only_that_browser_and_can_be_cleared(self):
        for path in ('/porn_fetch', '/buy_license', '/buy_card'):
            self.assertIn(b'id="age-overlay"', self.client.get(path).data)
        response = self.client.post('/', data={'adult_confirmed': 'yes'}, headers={'Accept': 'application/json'})
        self.assertEqual(response.json, {'confirmed': True})
        cookie = response.headers['Set-Cookie']
        self.assertIn('Secure', cookie)
        self.assertIn('HttpOnly', cookie)
        self.assertNotIn('Expires=', cookie)
        for path in ('/porn_fetch', '/buy_license', '/buy_card'):
            page = self.client.get(path)
            self.assertNotIn(b'id="age-overlay"', page.data)
            self.assertIn('no-store', page.headers['Cache-Control'])
        self.assertIn(b'id="age-overlay"', main.app.test_client().get('/porn_fetch').data)
        neutral = self.client.get('/leave')
        self.assertNotIn(b'Porn Fetch', neutral.data)
        self.assertIn(b'id="age-overlay"', self.client.get('/porn_fetch').data)

    def test_confirmation_preserves_local_destination_without_open_redirect(self):
        for target, expected in [('/buy_license', '/buy_license'), ('/buy_success?session_id=demo', '/buy_success?session_id=demo'), ('https://example.com', '/'), ('//example.com/', '/')]:
            with self.subTest(target=target):
                response = self.client.post('/', data={'adult_confirmed': 'yes', 'next': target})
                self.assertEqual(response.status_code, 303)
                self.assertEqual(response.headers['Location'], expected)

    def test_bilingual_documents_are_complete_and_accessible_before_confirmation(self):
        for path in ('/impress', '/privacy_policy', '/terms'):
            page = self.client.get(path)
            self.assertEqual(page.status_code, 200)
            self.assertNotIn(b'id="age-overlay"', page.data)
            self.assertLess(page.data.index(b'id="en"'), page.data.index(b'id="de"'))
            self.assertIn(b'href="#de"', page.data)
        self.assertEqual(self.client.get('/datenschutz').headers['Location'], '/privacy_policy#de')
        privacy = self.client.get('/privacy_policy').data
        self.assertIn(b'first-party session cookie', privacy)
        self.assertNotIn(b'uses <strong>no cookies</strong>', privacy)
        self.assertIn('Sitzungscookie'.encode(), privacy)

    def test_homepage_lists_all_fifteen_providers_and_factual_controls(self):
        page = self.client.get('/').data
        for website in product_catalog.WEBSITES:
            self.assertIn(f'<th scope="row"><a href="/guides/download-{website[0].lower()}-videos">{website[0]}</a></th>'.encode(), page)
        self.assertEqual(page.count(b'<th scope="row">'), 15)
        self.assertIn(b'not affiliated with', page)
        self.assertIn(b'Introducing v3.9', page)
        self.assertIn(b'Arch Linux', page)
        self.assertIn(b'preload="none"', page)
        self.assertIn(b'data-src="/static/media/porn-fetch-promo.mp4"', page)

    def test_public_download_catalog_and_guides_need_no_github(self):
        with patch('httpx.get', side_effect=AssertionError('No website network lookup')):
            page = self.client.get('/download')
            self.assertEqual(page.status_code, 200)
            self.assertIn(b'first website-hosted release', page.data)
            self.assertNotIn(b'id="age-overlay"', page.data)
            for platform in ('windows', 'linux', 'macos', 'android', 'ios', 'cli'):
                self.assertEqual(self.client.get('/download/' + platform).status_code, 200)
        self.assertIn(b'xz-kitty Python build', self.client.get('/download/ios').data)

    def test_media_range_requests_support_seekable_video(self):
        response = self.client.get('/static/media/porn-fetch-promo.mp4', headers={'Range': 'bytes=0-99'})
        self.assertEqual(response.status_code, 206)
        self.assertEqual(len(response.data), 100)
        self.assertEqual(response.mimetype, 'video/mp4')

    def test_source_android_gui_and_payment_choices_are_explicit(self):
        home = self.client.get('/').data
        self.assertIn(b'App source', home)
        self.assertIn(b'Installable Android GUI app', home)
        self.assertIn(b'https://github.com/EchterAlsFake/Server', home)
        self.assertIn(b'No IP logs. No viewing-history logs.', home)
        self.assertEqual(home.count(b'See source code'), 2)
        self.assertIn(b'class="github-nav"', home)
        options = self.client.get('/porn_fetch').data
        self.assertIn(b'No automatic renewal', options)
        self.assertIn(b'recurring membership until cancelled', options)
        self.assertIn(b'Test preview', options)
        self.assertNotIn(b'deleted at release', options)
        self.assertNotIn(b'service fee: 1%', options)
        self.assertNotRegex(options, rb'type="radio"[^>]*checked')

    def test_every_payment_method_can_be_selected_without_repeated_detail_panels(self):
        page = self.client.get('/porn_fetch').data
        for method in ('crypto', 'patreon', 'card'):
            self.assertNotIn(f'id="details-{method}"'.encode(), page)
            self.assertIn(f'id="method-{method}"'.encode(), page)
            self.assertNotRegex(page, f'id="method-{method}"[^>]*disabled'.encode())
        self.assertIn(b'Credit Card / Google Pay / Apple Pay', page)
        self.assertIn(b'350+', page)
        for brand in ('bitcoin', 'ethereum', 'solana', 'litecoin', 'nowpayments', 'patreon', 'google-pay', 'apple-pay'):
            self.assertIn(f'/static/media/payments/{brand}.'.encode(), page)

    def test_external_preview_requires_explicit_confirmation(self):
        page = self.client.get('/payment-preview/patreon')
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'Do not send money', page.data)
        self.assertEqual(self.client.post('/payment-preview/patreon', data={}).status_code, 400)
        accepted = self.client.post('/payment-preview/patreon', data={'confirm_no_payment': 'yes'})
        self.assertEqual(accepted.status_code, 200)
        self.assertIn(b'id="provider-launch"', accepted.data)
        self.assertIn(b'https://www.patreon.com/', accepted.data)
        card = self.client.post('/payment-preview/card', data={'confirm_no_payment': 'yes'})
        self.assertEqual(card.headers['Location'], '/buy_card')
        self.assertEqual(self.client.get('/payment-preview/unknown').status_code, 404)
