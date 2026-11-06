"""Security regressions and isolation from business transactions."""
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import httpx
from redis.exceptions import ConnectionError
from _support import ServerTestCase, main
from license_fixtures import POLICY, issuance
from pf_server import keygen_service, licensing
from pf_server.statistics import RequestStatistics


class SecurityHardeningTests(ServerTestCase):
    def test_hosts_reject_before_flask_and_forwarded_host_cannot_override(self):
        self.assertEqual(self.client.get('/ping', headers={'Host': 'attacker.invalid'}).status_code, 400)
        self.assertEqual(self.client.get('/ping', headers={'X-Forwarded-Host': 'attacker.invalid', 'X-Forwarded-Prefix': '/evil'}).status_code, 200)

    def test_ci_query_credentials_are_rejected_and_unicode_is_safe(self):
        with patch.dict(main.app.config, CI_TOKEN='secret'):
            self.assertEqual(self.client.post('/ci/synthetic?token=secret', json={'status': 'pass'}).status_code, 401)
            self.assertEqual(self.client.post('/ci/synthetic', headers={'X-CI-TOKEN': '\u00e9'}, json={'status': 'pass'}).status_code, 401)

    def test_csp_only_authorizes_nonces_and_local_scripts(self):
        response = self.client.get('/checklist')
        policy = response.headers['Content-Security-Policy']
        script_policy = next(p for p in policy.split(';') if p.strip().startswith('script-src'))
        self.assertNotIn('unsafe-inline', script_policy)
        self.assertNotIn('cdn.tailwindcss.com', policy)
        self.assertIn("'nonce-", script_policy)

    def test_ping_statistics_do_not_commit_or_query_business_storage(self):
        with patch.object(main.db.session, 'commit', side_effect=AssertionError('business commit')), patch.object(main.db.session, 'execute', side_effect=AssertionError('business query')):
            self.assertEqual(self.client.get('/ping').status_code, 200)

    def test_process_statistics_are_thread_safe(self):
        counters = RequestStatistics(main.app)
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _: counters.increment(1, 2, 3), range(1000)))
        self.assertEqual(counters.snapshot()['total_requests'], 1000)
        self.assertEqual(counters.snapshot()['total_bytes_out'], 3000)

    def test_redis_failure_does_not_break_requests(self):
        counters = RequestStatistics(main.app)
        with patch.object(counters, 'redis') as redis:
            redis.pipeline.side_effect = ConnectionError('unavailable')
            redis.hgetall.side_effect = ConnectionError('unavailable')
            counters.increment(1, 2, 3)
            self.assertEqual(counters.snapshot()['total_requests'], 0)

    def test_keygen_mismatched_identity_and_policy_fail_closed(self):
        with main.app.app_context(), patch.dict(main.app.config, KEYGEN_POLICY_ID=POLICY):
            for field in ('id', 'policy', 'scheme', 'key'):
                payload = issuance('synthetic-id')
                if field == 'id': payload['id'] = 'other'
                elif field == 'policy': payload['relationships']['policy']['data']['id'] = 'other'
                else: payload['attributes'][field] = 'invalid'
                with self.subTest(field=field), patch.object(keygen_service, 'request', return_value=httpx.Response(200, json={'data': payload})):
                    with self.assertRaises(keygen_service.KeygenUnavailable):
                        keygen_service.ensure_license('synthetic-id')

    def test_concurrent_issuance_reuses_persisted_identity(self):
        def issue(_):
            with main.app.app_context():
                record = licensing.get_or_create_license('concurrent-synthetic-payment')
                return record.license_key
        with ThreadPoolExecutor(max_workers=4) as pool:
            identities = list(pool.map(issue, range(8)))
        self.assertEqual(len(set(identities)), 1)
