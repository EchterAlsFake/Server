"""Receipt-authenticated browser license recovery boundaries."""
import json
import time
from unittest.mock import patch

from _support import ServerTestCase, main
from pf_server import patreon_shop as shop
from pf_server.models import PatreonShopLookup as Lookup, PatreonShopPurchase as Purchase, License


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
