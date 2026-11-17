"""PayWarp trust boundaries, retry safety and checkout integration."""
import hashlib
import hmac
import json
import time
from unittest.mock import patch

from _support import ServerTestCase, main
from pf_server import paywarp_service as service
from pf_server.extensions import db
from pf_server.models import Transaction, License


class PaywarpTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        config = patch.dict(main.app.config, PAYWARP_ENABLED=True, PAYWARP_API_KEY='test-secret',
            PAYWARP_WEBHOOK_SECRET='webhook-test', LICENSE_SMTP_HOST='localhost', LICENSE_EMAIL_FROM='test@example.com')
        config.start()
        self.addCleanup(config.stop)
        policy = patch('pf_server.keygen_service.verify_lifetime_policy')
        policy.start()
        self.addCleanup(policy.stop)

    def select(self):
        from pf_server.contracts import offer_digest
        with main.app.app_context():
            digest = offer_digest()
        response = self.client.post('/checkout/start', json=dict(payment_method='paywarp',
            age_terms_accepted=True, refund_method_accepted=True, test_acknowledged=True, offer_digest=digest))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['next'], '/buy_paywarp')

    def create(self):
        self.select()
        def response(method, path, **kw):
            p = kw['json']
            return dict(id='pl_test', checkout_url='https://paywarp.app/pay/test', amount=p['amount_minor'],
                currency=p['currency'], reference=p['reference'], status='pending')
        with patch.object(service, 'api', side_effect=response) as api:
            r = self.client.post('/create-paywarp-payment', data=dict(delivery_email='buyer@example.com', withdrawal_accepted='yes'))
            self.assertEqual(r.status_code, 303, r.data)
            payload = api.call_args.kwargs['json']
            self.assertEqual(payload['amount_minor'], 2999)
            self.assertEqual(payload['currency'], 'EUR')
            with main.app.app_context():
                transaction = db.session.get(Transaction, payload['reference'])
                self.assertEqual(transaction.customer_country, 'Germany')
                self.assertEqual(transaction.country_evidence, 'local_ip_geolocation')
        return payload, r.location

    def status(self, payload, **changes):
        return dict(dict(id='tx_test', link_id='pl_test', reference=payload['reference'],
            amount=2999, amount_paid=3100, currency='EUR', status='completed'), **changes)

    def signed(self, payload, event_id='event-1', timestamp=None):
        raw = json.dumps(dict(event='payment.completed', payment_id='pl_test', reference=payload['reference'])).encode()
        stamp = str(int(time.time()) if timestamp is None else timestamp)
        sig = hmac.new(b'webhook-test', stamp.encode()+b'.'+event_id.encode()+b'.'+raw, hashlib.sha256).hexdigest()
        return self.client.post('/paywarp-webhook', base_url='https://' + main.app.config['API_PUBLIC_HOST'], data=raw,
            headers={'X-Paywarp-Event': 'payment.completed', 'X-Paywarp-Event-Id': event_id,
                'X-Paywarp-Timestamp': stamp, 'X-Paywarp-Signature': sig}, content_type='application/json')

    def test_signed_webhook_confirms_with_api_and_duplicate_does_not_issue_twice(self):
        payload, url = self.create()
        with patch.object(service, 'api', return_value=self.status(payload)) as api:
            self.assertEqual(self.signed(payload).status_code, 200)
            self.assertEqual(self.signed(payload).status_code, 200)
            self.assertEqual(api.call_count, 1)
        with main.app.app_context():
            self.assertEqual(db.session.get(Transaction, payload['reference']).status, 'finished')
            self.assertEqual(License.query.count(), 1)
        page = self.client.get(url)
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'PayWarp', page.data)
        self.assertNotIn(b'NOWPayments cryptocurrency checkout', page.data)

    def test_bad_signature_and_old_and_future_timestamp_never_query_provider(self):
        payload, _ = self.create()
        with patch.object(service, 'api') as api:
            for stamp in (int(time.time())-301, int(time.time())+301):
                self.assertEqual(self.signed(payload, timestamp=stamp).status_code, 400)
            r = self.client.post('/paywarp-webhook', base_url='https://' + main.app.config['API_PUBLIC_HOST'], data=b'{}')
            self.assertEqual(r.status_code, 400)
            api.assert_not_called()

    def test_mismatched_api_payment_never_fulfills_and_can_retry(self):
        payload, _ = self.create()
        for changes in ({'amount': 1}, {'currency': 'USD'}, {'reference': 'other'}, {'link_id': 'pl_other'}, {'amount_paid': 1}, {'amount': True}):
            with self.subTest(changes=changes), patch.object(service, 'api', return_value=self.status(payload, **changes)):
                self.assertEqual(self.signed(payload).status_code, 503)
        with main.app.app_context():
            self.assertEqual(License.query.count(), 0)
            self.assertEqual(db.session.get(Transaction, payload['reference']).status, 'pending')
        with patch.object(service, 'api', return_value=self.status(payload)):
            self.assertEqual(self.signed(payload).status_code, 200)

    def test_provider_failure_retry_keeps_reference_and_idempotency_key(self):
        self.select()
        data = dict(delivery_email='buyer@example.com', withdrawal_accepted='yes')
        with patch.object(service, 'api', side_effect=service.PaymentProviderError('offline')) as api:
            self.assertEqual(self.client.post('/create-paywarp-payment', data=data).status_code, 503)
            first = api.call_args
            self.assertEqual(self.client.post('/create-paywarp-payment', data=data).status_code, 503)
            self.assertEqual(api.call_args.kwargs, first.kwargs)
        with main.app.app_context():
            self.assertEqual(Transaction.query.count(), 1)

    def test_return_does_not_fulfill_and_status_poll_verifies_payment(self):
        payload, url = self.create()
        self.assertEqual(self.client.get(url).status_code, 200)
        with main.app.app_context():
            self.assertEqual(License.query.count(), 0)
        with patch.object(service, 'api', return_value=self.status(payload)):
            result = self.client.get(url.replace('/buy_success?', '/check-payment-status?'))
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.json['status'], 'finished')

    def test_delivery_email_and_supply_consent_remain_required(self):
        self.select()
        with patch.object(service, 'api') as api:
            for data in ({'withdrawal_accepted': 'yes'}, {'delivery_email': 'buyer@example.com'}):
                self.assertEqual(self.client.post('/create-paywarp-payment', data=data).status_code, 400)
            api.assert_not_called()

    def test_country_is_automatic_and_untrusted_form_country_cannot_bypass_it(self):
        from pf_server.country_service import CountryEvidence
        self.select()
        self.mock_country_lookup.return_value = CountryEvidence(status='found', country_code='GB', database_label='test')
        with patch.object(service, 'api') as api:
            response = self.client.post('/create-paywarp-payment', data=dict(country='DE',
                delivery_email='buyer@example.com', withdrawal_accepted='yes'))
            self.assertEqual(response.status_code, 400)
            api.assert_not_called()
        self.mock_country_lookup.return_value = CountryEvidence(status='not_found')
        with patch.object(service, 'api') as api:
            response = self.client.post('/create-paywarp-payment', data=dict(
                delivery_email='buyer@example.com', withdrawal_accepted='yes'))
            self.assertEqual(response.status_code, 503)
            api.assert_not_called()

    def test_simplified_form_has_no_country_or_redundant_verification_checkbox(self):
        self.select()
        response = self.client.get('/buy_paywarp')
        self.assertNotIn('name="country"', response.text)
        self.assertNotIn('name="verification_acknowledged"', response.text)
        self.assertNotIn('Real credit card payment', response.text)
        self.assertIn('name="delivery_email"', response.text)
        self.assertIn('name="withdrawal_accepted"', response.text)
        self.assertIn('EU: Tax ID required.', response.text)

    def test_untrusted_checkout_urls_are_rejected(self):
        for url in ('https://paywarp.app.evil/pay/a', 'http://paywarp.app/pay/a', 'https://evil@paywarp.app/pay/a', 'https://paywarp.app:999/pay/a'):
            self.assertIsNone(service.checkout_url(url))

    def test_http_errors_are_rejected_before_success_payload_is_read(self):
        import httpx
        for code in (401, 409, 422, 503):
            response = httpx.Response(code, json={'ok': True, 'data': {'status': 'completed'}},
                request=httpx.Request('GET', 'https://paywarp.app/api/v1/payments/pl_test'))
            with self.subTest(code=code), main.app.app_context(), patch.object(service.httpx, 'Client') as client:
                client.return_value.__enter__.return_value.request.return_value = response
                with self.assertRaises(service.PaymentProviderError):
                    service.api('GET', '/payments/pl_test')

    def test_license_failure_leaves_retryable_order(self):
        from pf_server.keygen_service import KeygenUnavailable
        payload, _ = self.create()
        with patch.object(service, 'api', return_value=self.status(payload)), \
             patch('pf_server.licensing.fulfill_transaction_license', side_effect=KeygenUnavailable('unavailable')):
            self.assertEqual(self.signed(payload).status_code, 503)
        with main.app.app_context():
            self.assertEqual(db.session.get(Transaction, payload['reference']).status, 'pending')
        with patch.object(service, 'api', return_value=self.status(payload)):
            self.assertEqual(self.signed(payload).status_code, 200)
        with main.app.app_context():
            self.assertEqual(License.query.count(), 1)

    def test_every_api_call_sends_registered_site_header_and_preserves_idempotency(self):
        import httpx
        for site_url in (None, 'https://registered.example'):
            for method, path in (('GET', '/payments/pl_test'), ('POST', '/payments')):
                with self.subTest(site_url=site_url, method=method), main.app.app_context(), \
                     patch.dict(main.app.config, APP_DOMAIN='https://store.example', PAYWARP_SITE_URL=site_url), \
                     patch.object(service.httpx, 'Client') as client:
                    transport = client.return_value.__enter__.return_value
                    transport.request.return_value = httpx.Response(200,
                        json={'ok': True, 'data': {'status': 'pending'}},
                        request=httpx.Request(method, service.BASE + path))
                    result = service.api(method, path, headers={'Idempotency-Key': 'order-test'})
                    self.assertEqual(result['status'], 'pending')
                    headers = transport.request.call_args.kwargs['headers']
                    self.assertEqual(headers['X-Paywarp-Site-Url'], site_url or 'https://store.example')
                    self.assertEqual(headers['Authorization'], 'Bearer test-secret')
                    self.assertEqual(headers['Idempotency-Key'], 'order-test')
