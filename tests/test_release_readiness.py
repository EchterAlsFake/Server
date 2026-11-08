"""Commercial checkout boundaries and receipt-authenticated browser recovery."""
import json
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import httpx

from _support import ServerTestCase, main
from pf_server import patreon_shop as shop
from pf_server.models import PatreonShopLookup as Lookup, PatreonShopPurchase as Purchase, License
from pf_server.tor_checkout import TorExitResolver


class TorCheckoutTests(ServerTestCase):
    def test_tor_blocks_all_crypto_paths_before_provider_calls(self):
        self.mock_tor_lookup.return_value = 'tor'
        with patch('pf_server.nowpayments_service.httpx.post') as provider:
            for path in ('/create-crypto-payment', '/create-onramp-payment', '/checkout/crypto-confirm'):
                self.assertEqual(self.client.post(path, json={}).status_code, 403, path)
            self.assertEqual(self.client.post('/checkout/start', json={'payment_method': 'crypto'}).status_code, 403)
            for path in ('/buy_license', '/buy_card', '/donation', '/payment-preview/banxa'):
                self.assertEqual(self.client.get(path).status_code, 403, path)
            provider.assert_not_called()
        page = self.client.get('/porn_fetch').text
        self.assertIn('Unavailable over Tor.', page)
        self.assertIn('value="crypto" required disabled', page)
        self.assertEqual(self.client.get('/download').status_code, 200)
        self.assertEqual(self.accept_checkout('patreon').status_code, 200)

    def test_unavailable_list_blocks_payment_and_does_not_trust_browser_hints(self):
        self.mock_tor_lookup.return_value = 'unavailable'
        response = self.client.post('/create-crypto-payment', json={}, headers={'X-Tor': 'false'})
        self.assertEqual(response.status_code, 503)
        self.assertIn('no-store', response.headers['Cache-Control'])
        self.assertEqual(self.client.post('/checkout/start', json={'payment_method': 'crypto'}).status_code, 503)

    def test_local_ipv4_ipv6_and_stale_list_with_no_retained_address(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'exits.json'
            resolver = TorExitResolver(path)
            self.assertEqual(resolver.lookup('8.8.4.4'), 'unavailable')
            path.write_text(json.dumps({'published_at': time.time(), 'addresses': ['8.8.8.8', '2606:4700:4700::1111']}))
            self.assertEqual(resolver.lookup('8.8.8.8'), 'tor')
            self.assertEqual(resolver.lookup('::ffff:8.8.8.8'), 'tor')
            self.assertEqual(resolver.lookup('2606:4700:4700::1111'), 'tor')
            self.assertEqual(resolver.lookup('8.8.4.4'), 'clear')
            for value in (None, '127.0.0.1', '8.8.4.4, 8.8.8.8'):
                self.assertEqual(resolver.lookup(value), 'unavailable')
            path.write_text(json.dumps({'published_at': time.time()-86401, 'addresses': ['8.8.8.8']}))
            self.assertEqual(resolver.lookup('8.8.4.4'), 'unavailable')
        self.client.post('/checkout/start', json={'payment_method': 'crypto'}, headers={'X-Forwarded-For': '8.8.8.8'})
        self.mock_tor_lookup.assert_called_with('8.8.8.8')
        with self.client.session_transaction() as state:
            self.assertNotIn('8.8.8.8', repr(dict(state)))


class LiveCheckoutTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        settings = patch.dict(main.app.config, NOWPAYMENTS_SANDBOX=False,
            LICENSE_SMTP_HOST='localhost', LICENSE_EMAIL_FROM='test@example.com',
            NOWPAYMENTS_LOCAL_SIMULATION_ENABLED=False, NOWPAYMENTS_API_KEY='synthetic-live-key',
            NOWPAYMENTS_API_URL='https://api.nowpayments.io/v1', PATREON_SHOP_ENABLED=True,
            PATREON_SHOP_PRODUCT_URL='https://www.patreon.com/c/echteralsfake/shop/premium-123456')
        settings.start()
        self.addCleanup(settings.stop)

    def selection(self, method='crypto'):
        return dict(payment_method=method, age_terms_accepted='yes',
            refund_method_accepted='yes', offer_digest=self.offer_digest())

    def test_live_checkout_requires_legal_declarations_without_test_ack(self):
        for field in ('age_terms_accepted', 'refund_method_accepted'):
            data = self.selection()
            del data[field]
            self.assertEqual(self.client.post('/checkout/start', json=data).status_code, 400)
        self.assertEqual(self.client.post('/checkout/start', json=self.selection()).status_code, 200)
        self.assertEqual(self.client.post('/checkout/crypto-confirm', json=dict(country='DE', withdrawal_accepted=True, offer_digest=self.offer_digest())).status_code, 200)
        response = httpx.Response(200, json={'id': 'live-invoice', 'invoice_url': 'https://nowpayments.io/payment/?iid=live-invoice'}, request=httpx.Request('POST', 'https://api.nowpayments.io/v1/invoice'))
        with patch('pf_server.nowpayments_service.httpx.post', return_value=response) as provider:
            result = self.client.post('/create-crypto-payment', json=dict(country='DE', age_confirmed=True, terms_accepted=True, withdrawal_accepted=True, delivery_email='buyer@example.com'))
        self.assertEqual(result.status_code, 200, result.json)
        self.assertEqual(provider.call_args.kwargs['json']['price_amount'], 29.99)
        self.assertEqual(provider.call_args.args[0], 'https://api.nowpayments.io/v1/invoice')
        page = self.client.get('/buy_license').text
        self.assertIn('Buy lifetime Premium for €29.99', page)
        self.assertNotIn('TEST PREVIEW', page)
        self.assertNotIn('chk-test-site', self.client.get('/porn_fetch').text)
        self.assertEqual(self.client.post('/simulate-payment-success', json={}).status_code, 404)

    def test_changed_contract_cannot_be_used_to_create_a_payment(self):
        self.accept_checkout()
        with patch('pf_server.contracts.terms_snapshot', return_value={'version': 'changed'}), patch('pf_server.nowpayments_service.httpx.post') as provider:
            result = self.client.post('/create-crypto-payment', json=dict(country='DE', age_confirmed=True, terms_accepted=True, withdrawal_accepted=True, delivery_email='buyer@example.com'))
            self.assertEqual(result.status_code, 409)
            provider.assert_not_called()

    def test_unavailable_licensing_policy_blocks_new_payment(self):
        from pf_server.keygen_service import KeygenUnavailable
        self.accept_checkout()
        with patch('pf_server.nowpayments_service.verify_lifetime_policy', side_effect=KeygenUnavailable()), patch('pf_server.nowpayments_service.httpx.post') as provider:
            result = self.client.post('/create-crypto-payment', json=dict(country='DE', age_confirmed=True, terms_accepted=True, withdrawal_accepted=True, delivery_email='buyer@example.com'))
            self.assertEqual(result.status_code, 503)
            provider.assert_not_called()

    def test_patreon_live_handoff_uses_configured_product_and_keeps_consent(self):
        self.assertEqual(self.client.get('/payment-preview/patreon').status_code, 303)
        response = self.client.post('/checkout/start', json=self.selection('patreon'))
        self.assertTrue(response.json['live'])
        page = self.client.get(response.json['next'])
        self.assertEqual(page.status_code, 200)
        self.assertIn(main.app.config['PATREON_SHOP_PRODUCT_URL'], page.text)
        self.assertNotIn('test preview', page.text.lower())
        self.assertNotIn('confirm_no_payment', page.text)
        self.assertIn('Patreon order ID', page.text)
        self.assertIn('agreement', page.text)


class BrowserLicenseTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        settings = patch.dict(main.app.config, PATREON_SHOP_ENABLED=True,
            PATREON_SHOP_LOOKUP_KEY='s'*32, PATREON_SHOP_PRODUCT_VARIANT_ID='5808702')
        settings.start()
        self.addCleanup(settings.stop)
        self.email, self.receipt = 'buyer@example.com', 'RECEIPT-PRIVATE-1234'
        self.sales = [('internal-456', self.email, time.time()-60, True, self.receipt)]

    def claim(self, **changes):
        return self.client.post('/activate', data=dict(action='lookup', email=self.email, order_id=self.receipt, **changes))

    def process(self, sales=None):
        with main.app.app_context(), patch.object(shop, 'snapshot', return_value=self.sales if sales is None else sales):
            return shop.process_claims()

    def test_exact_receipt_pair_reveals_and_downloads_one_reusable_license(self):
        self.assertEqual(self.claim().status_code, 303)
        self.assertEqual(self.client.get('/activate/status').json, {'status': 'pending'})
        self.process()
        result = self.client.get('/activate/status')
        self.assertEqual(result.json['status'], 'ready')
        key = result.json['license_key']
        self.assertIn('no-store', result.headers['Cache-Control'])
        self.assertEqual(result.headers['Referrer-Policy'], 'no-referrer')
        page = self.client.get('/activate')
        self.assertIn(key, page.text)
        self.assertNotIn(self.email, page.text)
        self.assertNotIn(self.receipt, page.text)
        download = self.client.post('/activate/download')
        self.assertEqual(json.loads(download.data), {'schema': 2, 'product': 'porn-fetch', 'license_key': key})
        self.assertIn('attachment;', download.headers['Content-Disposition'])
        self.claim()
        self.process()
        self.assertEqual(self.client.get('/activate/status').json['license_key'], key)
        with main.app.app_context():
            self.assertEqual(License.query.count(), 1)
            self.assertEqual(Purchase.query.count(), 1)
            row = Lookup.query.first()
            self.assertNotIn(self.email, repr(row.__dict__))
            self.assertNotIn(self.receipt, repr(row.__dict__))

    def test_wrong_email_wrong_id_internal_id_and_refunds_never_disclose(self):
        attempts = [
            (self.email, 'wrong-id', self.sales),
            ('other@example.com', self.receipt, self.sales),
            (self.email, 'internal-456', self.sales),
            (self.email, self.receipt, [('internal-456', self.email, time.time(), False, self.receipt)]),
        ]
        for email, order_id, sales in attempts:
            self.client.post('/activate', data=dict(action='lookup', email=email, order_id=order_id))
            self.process(sales)
            self.assertEqual(self.client.get('/activate/status').json, {'status': 'not_found'})
            self.assertEqual(self.client.post('/activate/download').status_code, 404)
        with main.app.app_context():
            self.assertEqual(License.query.count(), 0)

    def test_verification_outage_and_keygen_failure_retry_without_disclosure(self):
        self.claim()
        with main.app.app_context(), patch.object(shop, 'snapshot', return_value=None):
            shop.process_claims()
            self.assertEqual(License.query.count(), 0)
        self.assertEqual(self.client.get('/activate/status').json, {'status': 'pending'})
        with patch.object(shop, 'build_license_file', side_effect=RuntimeError('unavailable')):
            self.process()
        self.assertEqual(self.client.get('/activate/status').json, {'status': 'pending'})
        self.process()
        self.assertEqual(self.client.get('/activate/status').json['status'], 'ready')
        with main.app.app_context():
            self.assertEqual(License.query.count(), 1)

    def test_browser_session_isolation_expiry_and_cleanup(self):
        self.claim()
        self.process()
        stranger = main.app.test_client()
        self.assertEqual(stranger.get('/activate/status').json, {'status': 'expired'})
        self.assertEqual(stranger.post('/activate/download').status_code, 404)
        with main.app.app_context():
            Lookup.query.first().created_at = time.time()-901
            main.db.session.commit()
        self.assertEqual(self.client.get('/activate/status').json, {'status': 'expired'})
        self.assertEqual(self.client.post('/activate/download').status_code, 404)
        self.process()
        with main.app.app_context():
            self.assertEqual(Lookup.query.count(), 0)

    def test_lookup_and_download_require_csrf(self):
        self.claim()
        self.process()
        with patch.dict(main.app.config, WTF_CSRF_ENABLED=True):
            self.assertEqual(self.claim().status_code, 400)
            self.assertEqual(self.client.post('/activate/download').status_code, 400)

    def test_sales_parser_retains_receipt_id_without_using_internal_id(self):
        from test_patreon_shop import ShopTests
        payload = ShopTests.page()
        payload['data'][0]['attributes']['public_order_id'] = self.receipt
        self.assertEqual(shop.parse_page(payload, '5808702')[0][4], self.receipt)

