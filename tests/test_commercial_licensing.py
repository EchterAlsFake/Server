"""Lifetime entitlement, separate offline deadlines, and retired renewal checkout."""
import tempfile
from unittest.mock import patch
import httpx
from _support import ServerTestCase, main
from license_fixtures import ACCOUNT, PRODUCT, POLICY, PUBLIC, LICENSE, NOW, iso, signed_key, permit
from license_client import LicenseClient, LicenseError


class CommercialTests(ServerTestCase):
    def test_lifetime_allows_future_builds_and_years_but_permits_still_expire(self):
        for years in (0, 1, 25):
            now = NOW + years * 365 * 86400
            with self.subTest(years=years), tempfile.TemporaryDirectory() as directory:
                client = LicenseClient(directory, public_key=PUBLIC, account_id=ACCOUNT,
                    product_id=PRODUCT, policy_id=POLICY, build_release_date=iso(now + 86400),
                    clock=lambda: now, monotonic=lambda: 1,
                    transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError('offline'))))
                try:
                    key = signed_key()
                    self.assertIsNone(client.verify_key(key)['license']['expiry'])
                    with client._state() as state:
                        state['active'] = LICENSE
                        state['licenses'][LICENSE] = {'key': key, 'activated': True,
                            'permit': permit(state['installation_id'], now=now - 10),
                            'first_import': NOW, 'renewed': now - 10}
                    self.assertTrue(client.check().allowed)
                    client.clock = lambda: now + 604800
                    self.assertFalse(client.check(force=True).allowed)
                finally:
                    client.close()

    def test_lifetime_rejects_annual_key_and_permit_cutoffs(self):
        with tempfile.TemporaryDirectory() as directory:
            client = LicenseClient(directory, public_key=PUBLIC, account_id=ACCOUNT,
                                   product_id=PRODUCT, policy_id=POLICY)
            try:
                with self.assertRaises(LicenseError):
                    client.verify_key(signed_key(duration=31556952))
                with self.assertRaises(LicenseError):
                    client.verify_permit(permit('installation', updates_end=NOW),
                        license_id=LICENSE, installation_id='installation', now=NOW)
            finally:
                client.close()

    def test_renewal_inputs_are_rejected_before_provider_requests(self):
        with patch.dict(main.app.config, NOWPAYMENTS_API_KEY='test'), \
             patch('pf_server.nowpayments_service.httpx.post') as provider:
            for field in ('renewal_license_key', 'renewal_license_id'):
                for value in (signed_key(), '', None):
                    response = self.client.post('/create-crypto-payment', json={
                        'terms_accepted': True, 'test_acknowledged': True, field: value})
                    self.assertEqual(response.status_code, 400)
                    self.assertIn('does not require renewal', response.json['error'])
            provider.assert_not_called()
