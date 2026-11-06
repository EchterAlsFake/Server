"""Shared declarations and crypto-only tax/early-supply confirmation."""
import json
import time
from unittest.mock import patch
from _support import ServerTestCase, main
from pf_server.models import CheckoutAgreement

class CheckoutStageTests(ServerTestCase):
    def selection(self, method='crypto'):
        return dict(payment_method=method, age_terms_accepted='yes',
                    refund_method_accepted='yes', test_acknowledged='yes',
                    offer_digest=self.offer_digest())

    def test_main_page_has_only_three_shared_confirmations(self):
        page = self.client.get('/porn_fetch').text
        form = page.split('id="payment-choice-form"')[1].split('</form>')[0]
        self.assertEqual(form.count('type="checkbox"'), 3)
        self.assertNotIn('Country for tax purposes', form)
        self.assertNotIn('DB-IP', form)
        self.assertNotIn('withdrawal_accepted', form)
        crypto = self.client.get('/buy_license').text
        self.assertIn('Country for tax purposes', crypto)
        self.assertIn('id="crypto-withdrawal"', crypto)

    def test_patreon_neither_requires_nor_records_country(self):
        data = dict(self.selection('patreon'), country='DE')
        self.assertEqual(self.client.post('/checkout/start', json=data).status_code, 200)
        with self.client.session_transaction() as state:
            self.assertIsNone(state['checkout_consent']['country'])
        with main.app.app_context():
            snapshot = json.loads(CheckoutAgreement.query.one().snapshot)
            self.assertIsNone(snapshot['country'])
            self.assertFalse(snapshot['immediate_supply_consent'])
        page = self.client.get('/payment-preview/patreon').text
        self.assertIn('https://pornfetch.to/activate', page)
        self.assertNotIn('/checkout/agreement', page)
        self.assertNotIn('Use <a', page)

    def test_pending_crypto_is_not_payment_authorization(self):
        self.assertEqual(self.client.post('/checkout/start', json=self.selection()).status_code, 200)
        with main.app.app_context():
            self.assertEqual(CheckoutAgreement.query.count(), 0)
        with self.client.session_transaction() as state:
            self.assertNotIn('checkout_consent', state)
        with patch.dict(main.app.config, NOWPAYMENTS_API_KEY='test'), patch('pf_server.payment_routes.encrypt_recipient', return_value='encrypted'), patch('pf_server.nowpayments_service.httpx.post') as provider:
            response = self.client.post('/create-crypto-payment', json=dict(country='DE',
                age_confirmed=True, terms_accepted=True, withdrawal_accepted=True,
                test_acknowledged=True, delivery_email='buyer@example.com'))
            self.assertEqual(response.status_code, 409)
            provider.assert_not_called()

    def test_crypto_completion_requires_country_and_explicit_supply_consent(self):
        self.client.post('/checkout/start', json=self.selection())
        valid = dict(country='DE', withdrawal_accepted=True, offer_digest=self.offer_digest())
        for changes in ({'country': ''}, {'country': {}}, {'withdrawal_accepted': False}, {'withdrawal_accepted': 'true'}):
            self.assertEqual(self.client.post('/checkout/crypto-confirm', json=dict(valid, **changes)).status_code, 400)
        self.assertEqual(self.client.post('/checkout/crypto-confirm', json=valid).status_code, 200)
        with main.app.app_context():
            snapshot = json.loads(CheckoutAgreement.query.one().snapshot)
            self.assertEqual(snapshot['country'], 'DE')
            self.assertTrue(snapshot['immediate_supply_consent'])
            self.assertTrue(snapshot['refund_method_accepted'])

    def test_expired_selection_or_changed_offer_cannot_complete(self):
        self.client.post('/checkout/start', json=self.selection())
        data = dict(country='DE', withdrawal_accepted=True, offer_digest='stale')
        self.assertEqual(self.client.post('/checkout/crypto-confirm', json=data).status_code, 409)
        with self.client.session_transaction() as state:
            state['checkout_selection'] = dict(state['checkout_selection'], accepted_at=time.time()-3601)
        self.assertEqual(self.client.post('/checkout/crypto-confirm', json=data).status_code, 409)

    def test_patreon_confirmation_does_not_unlock_the_crypto_page(self):
        self.client.post('/checkout/start', json=self.selection('patreon'))
        page = self.client.get('/buy_license').text
        self.assertIn('data-confirmed="false"', page)
        self.assertIn('Start with the', page)

    def test_crypto_confirmation_is_csrf_protected(self):
        self.client.post('/checkout/start', json=self.selection())
        with patch.dict(main.app.config, WTF_CSRF_ENABLED=True):
            self.assertEqual(self.client.post('/checkout/crypto-confirm', json=dict(
                country='DE', withdrawal_accepted=True, offer_digest=self.offer_digest())).status_code, 400)
