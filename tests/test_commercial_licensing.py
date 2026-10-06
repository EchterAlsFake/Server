import hashlib
import json
import tempfile
from unittest.mock import patch
import httpx
from _support import ServerTestCase, main
from license_fixtures import ACCOUNT, PRODUCT, POLICY, PUBLIC, LICENSE, NOW, iso, signed_key, permit, issuance
from license_client import LicenseClient, LicenseError
from pf_server import keygen_service
from pf_server.models import LicenseRenewal


class CommercialTests(ServerTestCase):
    def test_renewal_retry_and_target_binding(self):
        calls = []
        def remote(method, path, **kwargs):
            calls.append(kwargs['headers']['Idempotency-Key'])
            body = issuance(LICENSE)
            body['attributes']['metadata'] = {'pfRenewals': [calls[-1]]}
            return httpx.Response(200, json={'data': body})
        with main.app.app_context(), patch.dict(main.app.config, {'KEYGEN_POLICY_ID': POLICY}), patch.object(keygen_service, 'request', side_effect=remote):
            for _ in range(2):
                keygen_service.renew_verified_payment('nowpayments', 'sandbox', 'settled-123', LICENSE)
            self.assertEqual(calls[0], calls[1])
            self.assertEqual(LicenseRenewal.query.count(), 1)
            with self.assertRaises(ValueError):
                keygen_service.renew_verified_payment('nowpayments', 'sandbox', 'settled-123', ACCOUNT)
            self.assertEqual(len(calls), 2)

    def test_timeout_keeps_durable_renewal_identity(self):
        with main.app.app_context(), patch.object(keygen_service, 'request', side_effect=keygen_service.KeygenUnavailable('timeout')):
            with self.assertRaises(keygen_service.KeygenUnavailable):
                keygen_service.renew_verified_payment('patreon', 'production', 'charge-123', LICENSE)
            binding = LicenseRenewal.query.one()
            self.assertEqual(binding.keygen_id, LICENSE)
            self.assertFalse(binding.completed)

    def test_patreon_remains_disabled_without_explicit_enable(self):
        with patch.dict(main.app.config, {'PATREON_PAYMENTS_ENABLED': False}):
            response = self.post_patreon(self.eligible_patreon_payload())
            self.assertEqual(response.status_code, 503)

    def test_patreon_commercial_tier_and_price_are_required(self):
        payload = self.eligible_patreon_payload()
        with patch.dict(main.app.config, {'PATREON_LICENSE_TIER_IDS': frozenset()}):
            self.assertEqual(self.post_patreon(payload).get_json()['status'], 'not_eligible')
        payload['data']['attributes']['currently_entitled_amount_cents'] = 500
        self.assertEqual(self.post_patreon(payload).get_json()['status'], 'not_eligible')

    def test_fallback_uses_build_date_and_separate_offline_deadline(self):
        for release_time, expected in [(NOW - 1, True), (NOW, True), (NOW + 1, False)]:
            with tempfile.TemporaryDirectory() as directory:
                client = LicenseClient(directory, public_key=PUBLIC, account_id=ACCOUNT,
                    product_id=PRODUCT, policy_id=POLICY, build_release_date=iso(release_time),
                    clock=lambda: NOW+100, monotonic=lambda: 1,
                    transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError('offline'))))
                try:
                    key = signed_key(duration=31556952)
                    self.assertEqual(client.verify_key(key)['license']['expiry'], None)
                    with client._state() as state:
                        state['active'] = LICENSE
                        state['licenses'][LICENSE] = {'key': key, 'activated': True,
                            'permit': permit(state['installation_id'], now=NOW+10, updates_end=NOW),
                            'first_import': NOW, 'renewed': NOW+10}
                    result = client.check()
                    self.assertEqual(result.allowed, expected)
                    if not expected:
                        self.assertEqual(result.state, 'renewal_required')
                    client.clock = lambda: NOW + 604811
                    self.assertFalse(client.check(force=True).allowed)
                finally:
                    client.close()

    def test_commercial_key_requires_immutable_build_date(self):
        with tempfile.TemporaryDirectory() as directory:
            client = LicenseClient(directory, public_key=PUBLIC, account_id=ACCOUNT,
                                   product_id=PRODUCT, policy_id=POLICY)
            try:
                with self.assertRaises(LicenseError):
                    client.verify_key(signed_key(duration=31556952))
            finally:
                client.close()
