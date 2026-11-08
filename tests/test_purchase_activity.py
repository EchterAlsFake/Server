"""Backend milestones reflect real work and preserve purchase proof boundaries."""
import time
from unittest.mock import patch

from _support import ServerTestCase, main
from pf_server import patreon_shop as shop
from pf_server.models import PatreonShopLookup as Lookup


class PatreonActivityTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        config = patch.dict(main.app.config, PATREON_SHOP_ENABLED=True,
                            PATREON_SHOP_LOOKUP_KEY='p' * 32)
        config.start()
        self.addCleanup(config.stop)
        self.email, self.receipt = 'progress@example.com', 'RECEIPT-PROGRESS'
        self.sales = [('order-progress', self.email, time.time() - 60, True, self.receipt)]

    def status(self, action='lookup'):
        return self.client.get('/activate/status', query_string={'progress': '1', 'action': action}).json

    def test_browser_milestones_are_committed_before_fetch_and_license_work(self):
        self.client.post('/activate', data={'action': 'lookup', 'email': self.email, 'order_id': self.receipt})
        self.assertEqual(self.status()['progress']['stage'], 'queued')

        def fetch():
            self.assertEqual(self.status()['progress']['stage'], 'fetching')
            return self.sales

        original = shop.build_license_file

        def build(*args):
            self.assertEqual(self.status()['progress']['stage'], 'license')
            return original(*args)

        with main.app.app_context(), patch.object(shop, 'snapshot', side_effect=fetch), patch.object(shop, 'build_license_file', side_effect=build):
            shop.process_claims()
        result = self.status()
        self.assertEqual(result['status'], 'ready')
        self.assertEqual(result['progress']['activity'], 'complete')
        self.assertTrue(result['license_key'].startswith('key/'))

    def test_email_progress_is_generic_and_private_even_after_completion(self):
        result = self.client.post('/activate', data={'email': self.email})
        self.assertEqual(result.status_code, 202)
        self.assertIn(b'patreon-email-progress', result.data)
        self.assertEqual(self.status('email')['progress']['stage'], 'queued')
        stranger = main.app.test_client()
        self.assertEqual(stranger.get('/activate/status?action=email').json, {'status': 'expired'})

        def send(*args):
            self.assertEqual(self.status('email')['progress']['stage'], 'delivery')

        with main.app.app_context(), patch.object(shop, 'snapshot', return_value=self.sales), patch.object(shop, 'send_license_email', side_effect=send):
            shop.process_claims()
        verified = self.status('email')
        self.assertEqual(verified['status'], 'complete')
        self.assertNotIn('license_key', verified)
        self.assertNotIn(self.email, str(verified))
        self.assertIn('If an eligible purchase was found', verified['progress']['message'])
        self.client.post('/activate', data={'email': 'no-purchase@example.com'})
        with main.app.app_context(), patch.object(shop, 'snapshot', return_value=[]):
            shop.process_claims()
        # The public completion wording does not reveal whether a purchase exists.
        self.assertEqual(self.status('email')['progress']['message'], verified['progress']['message'])

    def test_outage_retry_and_status_expiry(self):
        self.client.post('/activate', data={'action': 'lookup', 'email': self.email, 'order_id': self.receipt})
        with main.app.app_context(), patch.object(shop, 'snapshot', return_value=None):
            shop.process_claims()
        result = self.status()
        self.assertEqual(result['status'], 'pending')
        self.assertEqual(result['progress']['stage'], 'retry')
        self.assertEqual(result['progress']['activity'], 'waiting')
        self.assertNotIn('license_key', result)
        with main.app.app_context():
            Lookup.query.first().created_at = time.time() - 901
            main.db.session.commit()
        self.assertEqual(self.status(), {'status': 'expired'})
