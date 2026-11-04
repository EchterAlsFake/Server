"""Shop activation, durable delivery and fail-open purchase policy."""
import time
from unittest.mock import patch
from _support import ServerTestCase, main
from pf_server import patreon_shop as shop
from pf_server.models import PatreonShopCustomer as Customer, PatreonShopPurchase as Purchase, License
from pf_server.extensions import limiter


class ShopTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.config = patch.dict(main.app.config, PATREON_SHOP_ENABLED=True,
            PATREON_SHOP_LOOKUP_KEY='x' * 32, PATREON_SHOP_PRODUCT_VARIANT_ID='5808702')
        self.config.start()
        self.addCleanup(self.config.stop)
        self.email = 'john@example.com'

    def queue(self):
        row = Customer.query.first()
        if row:
            row.requested_at = time.time() - 901
            main.db.session.commit()
        shop.enqueue(self.email)

    def run_worker(self, sales):
        with patch.object(shop, 'snapshot', return_value=sales), patch.object(shop, 'send_license_email') as mail:
            shop.process_claims()
            return mail.call_args[0][1] if mail.called else None

    def test_new_purchase_resend_and_next_year_new_license(self):
        with main.app.app_context():
            sales = [('A', self.email, time.time() - 100, True)]
            self.queue()
            first = self.run_worker(sales)
            self.queue()
            self.assertEqual(first, self.run_worker(sales))
            sales.append(('B', self.email, time.time(), True))
            self.queue()
            self.assertNotEqual(first, self.run_worker(sales))
            self.assertEqual(License.query.count(), 2)
            self.assertEqual(Purchase.query.count(), 2)

    def test_fallback_deduplicates_reconciles_and_preserves_future_purchase(self):
        with main.app.app_context():
            self.queue()
            fallback = self.run_worker(None)
            self.queue()
            self.assertEqual(fallback, self.run_worker(None))
            prior = time.time() - 100
            self.queue()
            self.assertEqual(fallback, self.run_worker([('A', self.email, prior, True)]))
            self.assertIsNone(Customer.query.first().fallback_key)
            self.queue()
            later = [('A', self.email, prior, True), ('B', self.email, time.time() + 1, True)]
            self.assertNotEqual(fallback, self.run_worker(later))
            self.assertEqual(License.query.count(), 2)

    def test_negative_results_do_not_issue(self):
        with main.app.app_context():
            for sales in ([], [('A', self.email, time.time(), False)], None):
                self.queue()
                self.assertIsNone(self.run_worker(sales))
            self.assertEqual(License.query.count(), 0)

    def test_smtp_failure_reuses_selected_license_and_recipient(self):
        with main.app.app_context():
            self.queue()
            sales = [('A', self.email, time.time(), True)]
            with patch.object(shop, 'snapshot', return_value=sales), patch.object(shop, 'send_license_email', side_effect=RuntimeError()):
                shop.process_claims()
            row = Customer.query.first()
            key = row.delivery_key
            self.assertTrue(row.pending)
            row.next_attempt_at = 0
            main.db.session.commit()
            self.assertIsNotNone(self.run_worker(None))
            self.assertEqual(Customer.query.first().last_key, key)
            self.assertEqual(License.query.count(), 1)

    def test_queue_dedup_and_cooldown(self):
        with main.app.app_context():
            shop.enqueue(self.email)
            shop.enqueue(self.email)
            self.run_worker([])
            shop.enqueue(self.email)
            self.assertFalse(Customer.query.first().pending)
            self.assertEqual(Customer.query.count(), 1)
            self.assertNotIn(self.email, Customer.query.first().recipient_encrypted)

    def test_browser_generic_email_only_and_csrf(self):
        response = self.client.post('/activate', data={'email': self.email}, base_url='https://echteralsfake.me')
        self.assertEqual(response.status_code, 202)
        self.assertNotIn(self.email.encode(), response.data)
        self.assertNotIn(b'license_key', response.data)
        self.assertIn('no-store', response.headers['Cache-Control'])
        self.assertEqual(response.headers['X-Robots-Tag'], 'noindex, nofollow')
        with patch.dict(main.app.config, WTF_CSRF_ENABLED=True):
            self.assertEqual(self.client.post('/activate', data={'email': self.email}, base_url='https://echteralsfake.me').status_code, 400)

    def test_rate_limits_and_disabled_flag(self):
        limiter.enabled = True
        responses = [self.client.post('/activate', data={'email': self.email}, base_url='https://echteralsfake.me') for _ in range(6)]
        self.assertEqual([r.status_code for r in responses], [202]*5+[429])
        limiter.enabled = False
        with patch.dict(main.app.config, PATREON_SHOP_ENABLED=False):
            self.assertEqual(self.client.get('/activate', base_url='https://echteralsfake.me').status_code, 404)

    def test_schema_and_incomplete_relationships_are_unavailable(self):
        for payload in ({}, {'data': [{}]}, {'data': 'bad'}, {'data': [{'type': 'order', 'id': 'A', 'attributes': {}}]}):
            with self.assertRaises(shop.VerificationUnavailable):
                shop.parse_page(payload, '5808702')

    def test_circuit_breaker_avoids_repeat_requests(self):
        with main.app.app_context(), patch.object(shop, 'fetch_sales', side_effect=shop.VerificationUnavailable('cookies')) as fetch:
            self.assertIsNone(shop.snapshot())
            self.assertIsNone(shop.snapshot())
            self.assertEqual(fetch.call_count, 1)

    @staticmethod
    def page(count=1, total=None):
        orders, included = [], []
        for i in range(count):
            orders.append({'type': 'order', 'id': str(i), 'attributes': {
                'buyer_email': 'john@example.com', 'date_purchased': '2026-01-01T12:00:00Z',
                'status': 'fulfilled'}, 'relationships': {'order_items': {'data': [{'type': 'order_item', 'id': str(i)}]}}})
            included.append({'type': 'order_item', 'id': str(i), 'attributes': {'refunded_at': None},
                'relationships': {'product_variant': {'data': {'type': 'product-variant', 'id': '5808702'}}}})
        return {'data': orders, 'included': included, 'meta': {'pagination': {'total': count if total is None else total}}}

    def test_sales_transport_and_pagination(self):
        import tempfile
        import os
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'cookies.txt')
            with open(path, 'w') as source:
                source.write('# Netscape HTTP Cookie File\n.patreon.com\tTRUE\t/\tTRUE\t0\tsession_id\ttest-only\n')
            os.chmod(path, 0o600)
            response = MagicMock(status_code=200)
            session = MagicMock()
            session.get.return_value = response
            with main.app.app_context(), patch.dict(main.app.config, PATREON_SHOP_COOKIE_FILE=path), patch('curl_cffi.requests.Session') as factory:
                factory.return_value.__enter__.return_value = session
                response.json.return_value = self.page()
                self.assertEqual(len(shop.fetch_sales()), 1)
                self.assertFalse(session.get.call_args.kwargs['allow_redirects'])
                self.assertFalse(factory.call_args.kwargs['trust_env'])
                for payload in (self.page(1, 2), self.page(50, 100), {'data': []}):
                    response.json.return_value = payload
                    with self.assertRaises(shop.VerificationUnavailable):
                        shop.fetch_sales()
                for status in (302, 401, 403, 429, 500):
                    response.status_code = status
                    response.headers = {'Retry-After': '600'}
                    with self.assertRaises(shop.VerificationUnavailable) as error:
                        shop.fetch_sales()
                    if status == 429:
                        self.assertEqual(error.exception.delay, 600)
                response.status_code = 200
                response.json.side_effect = ValueError()
                with self.assertRaises(shop.VerificationUnavailable):
                    shop.fetch_sales()
                response.json.side_effect = None
                session.get.side_effect = TimeoutError()
                with self.assertRaises(shop.VerificationUnavailable):
                    shop.fetch_sales()
                os.chmod(path, 0o644)
                session.get.reset_mock()
                with self.assertRaises(shop.VerificationUnavailable):
                    shop.fetch_sales()
                session.get.assert_not_called()

    def test_item_refund_and_product_matching(self):
        payload = self.page()
        self.assertTrue(shop.parse_page(payload, '5808702')[0][3])
        self.assertFalse(shop.parse_page(payload, 'wrong')[0][3])
        payload['included'][0]['attributes']['refunded_at'] = '2026-02-01T00:00:00Z'
        self.assertFalse(shop.parse_page(payload, '5808702')[0][3])
        del payload['included'][0]['attributes']['refunded_at']
        with self.assertRaises(shop.VerificationUnavailable):
            shop.parse_page(payload, '5808702')

    def test_keygen_outage_and_worker_lock(self):
        import fcntl
        from pathlib import Path
        with main.app.app_context():
            self.queue()
            with open(Path(main.app.config['DATA_DIR']) / 'patreon-shop.lock', 'a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertEqual(shop.process_claims(), 0)
            sales = [('A', self.email, time.time(), True)]
            with patch.object(shop, 'snapshot', return_value=sales), patch.object(shop, 'build_license_file', side_effect=RuntimeError()), patch.object(shop, 'send_license_email') as mail:
                shop.process_claims()
                mail.assert_not_called()
            row = Customer.query.first()
            key = row.delivery_key
            self.assertTrue(row.pending)
            self.assertIsNone(row.fallback_key)
            row.next_attempt_at = 0
            main.db.session.commit()
            self.assertIsNotNone(self.run_worker(None))
            self.assertEqual(Customer.query.first().last_key, key)

    def test_known_purchase_recovery_and_confirmed_refund(self):
        with main.app.app_context():
            self.queue()
            first = self.run_worker([('A', self.email, time.time(), True)])
            self.queue()
            self.assertEqual(first, self.run_worker(None))
            self.queue()
            self.assertIsNone(self.run_worker([('A', self.email, time.time(), False)]))
            self.queue()
            self.assertIsNone(self.run_worker(None))
            self.assertEqual(License.query.count(), 1)

    def test_cleanup_runs_with_empty_queue(self):
        with main.app.app_context():
            self.queue()
            self.run_worker([])
            row = Customer.query.first()
            row.completed_at = time.time() - 31 * 86400
            main.db.session.commit()
            self.run_worker([])
            self.assertIsNone(Customer.query.first().completed_at)
            self.assertIsNone(Customer.query.first().reason)
            self.assertTrue(Customer.query.first().recipient_encrypted)

    def test_feature_configuration_requires_shared_limits_and_secrets(self):
        import tempfile
        from pf_server.config import load_environment_config
        with tempfile.TemporaryDirectory() as directory:
            source = {'SECRET_KEY': 'test', 'PATREON_SHOP_ENABLED': 'true'}
            with self.assertRaisesRegex(ValueError, 'Redis'):
                load_environment_config(directory, source)
            source['RATELIMIT_STORAGE_URI'] = 'redis://localhost:6379/0'
            with self.assertRaisesRegex(ValueError, 'LOOKUP_KEY'):
                load_environment_config(directory, source)
            source['PATREON_SHOP_LOOKUP_KEY'] = 'x' * 32
            with self.assertRaisesRegex(ValueError, 'ENCRYPTION_KEY'):
                load_environment_config(directory, source)
