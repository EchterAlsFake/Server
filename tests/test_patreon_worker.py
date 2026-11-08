"""Immediate purchase intake, shared-worker handoff and retry boundaries."""
import fcntl
import threading
import time
from pathlib import Path
from unittest.mock import patch

from _support import ServerTestCase, main
from pf_server import patreon_shop as shop, patreon_worker as worker
from pf_server.models import PatreonShopCustomer as Customer, PatreonShopHealth as Health, PatreonShopLookup as Lookup


class ImmediatePatreonWorkerTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        settings = patch.dict(main.app.config, PATREON_SHOP_ENABLED=True,
                              PATREON_SHOP_LOOKUP_KEY='w' * 32)
        settings.start()
        self.addCleanup(settings.stop)
        self.email, self.receipt = 'instant@example.com', 'INSTANT-RECEIPT'
        self.sales = [('instant-order', self.email, time.time() - 60, True, self.receipt)]
        self.gates = []
        self.addCleanup(self.finish_worker)

    def finish_worker(self):
        for gate in self.gates:
            gate.set()
        state = main.app.extensions.get('patreon_shop_worker')
        if state and state.thread:
            state.thread.join(10)
            self.assertIsNone(state.thread, 'Background worker did not finish')

    def unblock_when_finished(self):
        gate = threading.Event()
        self.gates.append(gate)
        return gate

    def join_worker(self):
        state = main.app.extensions['patreon_shop_worker']
        thread = state.thread
        if thread:
            thread.join(10)
            self.assertFalse(thread.is_alive(), 'Background worker did not finish')

    def submit(self, *, email_only=False, client=None):
        form = {'email': self.email}
        if not email_only:
            form.update(action='lookup', order_id=self.receipt)
        return (client or self.client).post('/activate', data=form)

    def test_both_forms_begin_scraping_without_timer_or_blocking_the_request(self):
        for email_only in (False, True):
            with self.subTest(email_only=email_only):
                self.email = f'instant-{email_only}@example.com'
                self.sales = [(f'instant-{email_only}', self.email, time.time() - 60, True, self.receipt)]
                entered, release = threading.Event(), self.unblock_when_finished()

                def fetch():
                    entered.set()
                    if not release.wait(10):
                        raise AssertionError('HTTP request blocked on scraping')
                    return self.sales

                self.patreon_wakeup.stop()
                with patch.object(shop, 'fetch_sales', side_effect=fetch), patch.object(shop, 'send_license_email') as send:
                    result = self.submit(email_only=email_only)
                    self.assertEqual(result.status_code, 202 if email_only else 303)
                    self.assertTrue(entered.wait(2), 'Scraping waited for a scheduled worker')
                    self.assertFalse(release.is_set())
                    action = 'email' if email_only else 'lookup'
                    progress = self.client.get('/activate/status', query_string={'action': action, 'progress': '1'}).json
                    self.assertEqual(progress['progress']['stage'], 'fetching')
                    release.set()
                    self.join_worker()
                    result = self.client.get('/activate/status', query_string={'action': action}).json
                    self.assertEqual(result['status'], 'complete' if email_only else 'ready')
                    self.assertEqual(send.call_count, int(email_only))
                self.patreon_wakeup.start()

    def test_lookup_submissions_during_scraping_share_the_active_batch(self):
        entered, release = threading.Event(), self.unblock_when_finished()

        def fetch():
            entered.set()
            self.assertTrue(release.wait(10))
            return self.sales

        self.patreon_wakeup.stop()
        with patch.object(shop, 'fetch_sales', side_effect=fetch) as fetcher:
            self.submit()
            self.assertTrue(entered.wait(2))
            state = main.app.extensions['patreon_shop_worker']
            original_thread = state.thread
            for _ in range(5):
                self.assertEqual(self.submit(client=main.app.test_client()).status_code, 303)
            self.assertIs(state.thread, original_thread)
            release.set()
            self.join_worker()
            self.assertEqual(fetcher.call_count, 1)
        with main.app.app_context():
            self.assertEqual(Lookup.query.filter_by(status='ready').count(), 6)

    def test_intake_while_the_scheduled_worker_holds_the_lock_is_not_lost(self):
        self.patreon_wakeup.stop()
        with main.app.app_context():
            lock_path = Path(main.app.config['DATA_DIR']) / 'patreon-shop.lock'
        with open(lock_path, 'a') as lock, patch.object(shop, 'fetch_sales', return_value=self.sales) as fetcher:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.assertEqual(self.submit().status_code, 303)
            # A request must return while the immediate worker waits for the
            # other process. Releasing that lock must start work without a tick.
            fetcher.assert_not_called()
            fcntl.flock(lock, fcntl.LOCK_UN)
            self.join_worker()
            fetcher.assert_called_once()
        self.assertEqual(self.client.get('/activate/status').json['status'], 'ready')

    def test_a_full_new_lookup_batch_does_not_displace_the_active_request(self):
        entered, release = threading.Event(), self.unblock_when_finished()

        def fetch():
            entered.set()
            self.assertTrue(release.wait(10))
            return self.sales

        self.patreon_wakeup.stop()
        with patch.object(shop, 'fetch_sales', side_effect=fetch):
            self.submit()
            self.assertTrue(entered.wait(2))
            with main.app.app_context():
                for index in range(100):
                    main.db.session.add(Lookup(id=f'new-{index}', email_digest=shop.digest_email(self.email),
                        order_digest=shop.digest_order(self.receipt), created_at=time.time(),
                        status='pending', progress_stage='queued'))
                main.db.session.commit()
                worker.wake()
            release.set()
            self.join_worker()
        self.assertEqual(self.client.get('/activate/status').json['status'], 'ready')
        with main.app.app_context():
            self.assertEqual(Lookup.query.filter_by(status='ready').count(), 101)

    def test_email_arriving_after_batch_selection_is_drained_immediately(self):
        entered, release = threading.Event(), self.unblock_when_finished()

        def fetch():
            entered.set()
            self.assertTrue(release.wait(10))
            return self.sales

        self.patreon_wakeup.stop()
        with patch.object(shop, 'fetch_sales', side_effect=fetch), patch.object(shop, 'send_license_email') as send:
            self.submit()
            self.assertTrue(entered.wait(2))
            self.submit(email_only=True)
            release.set()
            self.join_worker()
            send.assert_called_once()
        self.assertEqual(self.client.get('/activate/status?action=email').json['status'], 'complete')

    def test_provider_backoff_is_not_bypassed_by_immediate_wakeups(self):
        with main.app.app_context():
            main.db.session.add(Health(id=1, retry_at=time.time() + 600, reason='rate_limit'))
            main.db.session.commit()
        self.patreon_wakeup.stop()
        with patch.object(shop, 'fetch_sales') as fetcher:
            self.submit()
            self.join_worker()
            fetcher.assert_not_called()
        result = self.client.get('/activate/status?progress=1').json
        self.assertEqual(result['status'], 'pending')
        self.assertEqual(result['progress']['stage'], 'retry')

    def test_deferred_lookup_batch_cannot_starve_new_intake_or_spin_forever(self):
        with main.app.app_context():
            for index in range(100):
                main.db.session.add(Lookup(id=f'old-{index}', email_digest=shop.digest_email(self.email),
                    order_digest=shop.digest_order(self.receipt), created_at=time.time() - 120,
                    status='pending', progress_stage='retry'))
            main.db.session.commit()
        self.patreon_wakeup.stop()
        with patch.object(shop, 'snapshot', side_effect=[None, RuntimeError('unexpected repeated scrape')]) as fetcher:
            self.submit()
            self.join_worker()
            fetcher.assert_called_once()
        self.assertEqual(self.client.get('/activate/status?progress=1').json['progress']['stage'], 'retry')

    def test_email_cooldown_does_not_trigger_a_second_scrape_or_delivery(self):
        self.patreon_wakeup.stop()
        with patch.object(shop, 'fetch_sales', return_value=self.sales) as fetcher, patch.object(shop, 'send_license_email') as send:
            self.submit(email_only=True)
            self.join_worker()
            self.submit(email_only=True)
            self.join_worker()
            fetcher.assert_called_once()
            send.assert_called_once()

    def test_worker_start_failure_leaves_a_durable_job_for_scheduled_retry(self):
        self.patreon_wakeup.stop()
        with patch.object(worker.Thread, 'start', side_effect=RuntimeError('unavailable')):
            self.assertEqual(self.submit(email_only=True).status_code, 202)
        with main.app.app_context(), patch.object(shop, 'snapshot', return_value=self.sales), patch.object(shop, 'send_license_email') as send:
            self.assertTrue(Customer.query.first().pending)
            shop.process_claims()
            send.assert_called_once()
            self.assertFalse(Customer.query.first().pending)

    def test_failed_background_batch_can_be_woken_again(self):
        self.patreon_wakeup.stop()
        with patch.object(worker, 'process_claims', side_effect=RuntimeError('unavailable')):
            self.submit()
            self.join_worker()
        with main.app.app_context(), patch.object(shop, 'fetch_sales', return_value=self.sales):
            worker.wake()
            self.join_worker()
        self.assertEqual(self.client.get('/activate/status').json['status'], 'ready')

    def test_invalid_or_unsaved_intake_does_not_wake_a_worker(self):
        self.assertEqual(self.client.post('/activate', data={'email': 'invalid'}).status_code, 400)
        self.mock_patreon_wakeup.assert_not_called()
        from sqlalchemy.exc import SQLAlchemyError
        with patch.object(shop, 'enqueue', side_effect=SQLAlchemyError()):
            self.assertEqual(self.submit(email_only=True).status_code, 503)
        self.mock_patreon_wakeup.assert_not_called()
