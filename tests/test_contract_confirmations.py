"""Checkout evidence, durable confirmation delivery and legacy boundaries."""
import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from _support import ServerTestCase, main
import test_checkout_refresh as checkout_helpers
from pf_server import contracts, crypto_delivery, licensing
from pf_server.models import CheckoutAgreement, CryptoLicenseDelivery, Transaction


class ContractConfirmationTests(ServerTestCase):
    payment = staticmethod(checkout_helpers.CheckoutRefreshTests.payment)
    create_invoice = checkout_helpers.CheckoutRefreshTests.create_invoice
    finish = checkout_helpers.CheckoutRefreshTests.finish

    def setUp(self):
        super().setUp()
        settings = patch.dict(main.app.config, NOWPAYMENTS_API_KEY="synthetic-key",
            NOWPAYMENTS_SANDBOX=True, LICENSE_SMTP_HOST="localhost",
            LICENSE_EMAIL_FROM="support@example.com", LICENSE_SMTP_SSL=False,
            LICENSE_SMTP_STARTTLS=False, LICENSE_SMTP_USERNAME="")
        settings.start()
        self.addCleanup(settings.stop)

    def test_api_booleans_cannot_replace_missing_or_expired_checkout_evidence(self):
        with patch('pf_server.nowpayments_service.httpx.post') as provider:
            self.assertEqual(self.client.post('/create-crypto-payment', json=self.payment()).status_code, 409)
            self.accept_checkout()
            with self.client.session_transaction() as state:
                state['checkout_consent'] = dict(state['checkout_consent'], accepted_at=time.time() - 3601)
            self.assertEqual(self.client.post('/create-crypto-payment', json=self.payment()).status_code, 409)
            provider.assert_not_called()

    def test_wrong_payment_route_and_missing_database_evidence_are_rejected(self):
        self.accept_checkout('card')
        self.assertEqual(self.client.post('/create-crypto-payment', json=self.payment()).status_code, 409)
        self.accept_checkout()
        with main.app.app_context():
            main.db.session.execute(main.db.delete(CheckoutAgreement))
            main.db.session.commit()
        self.assertEqual(self.client.post('/create-crypto-payment', json=self.payment()).status_code, 409)

    def test_changed_offer_cannot_be_accepted_with_a_stale_digest(self):
        data = dict(self.payment(), payment_method='crypto', offer_digest='old-offer')
        self.assertEqual(self.client.post('/checkout/start', json=data).status_code, 409)
        with main.app.app_context():
            self.assertEqual(CheckoutAgreement.query.count(), 0)

    def test_order_keeps_accepted_text_and_original_pdf_despite_later_text_changes(self):
        self.accept_checkout()
        with main.app.app_context():
            accepted = json.loads(CheckoutAgreement.query.one().snapshot)
        with patch.object(contracts, 'terms_snapshot', return_value={'version': 'changed'}):
            order = self.create_invoice('buyer@example.com')
        with patch.object(crypto_delivery, 'send_license_email') as send, \
             patch.object(contracts, 'render_pdf', wraps=contracts.render_pdf) as render:
            self.finish(order)
        body = render.call_args.args[0]
        for field in ('product', 'terms_en', 'withdrawal', 'refund_terms'):
            self.assertEqual(body.count(accepted[field]), 1, field)
        self.assertIn('English is authoritative', body)
        self.assertNotIn('Vertragsbestätigung', body)
        document = send.call_args.kwargs['confirmation_pdf']
        self.assertTrue(document.startswith(b'%PDF'))
        self.assertNotIn(b'buyer@example.com', send.call_args.args[1])
        with main.app.app_context(), patch.object(contracts, 'render_pdf', side_effect=AssertionError('must reuse PDF')):
            tx = main.db.session.get(Transaction, order)
            self.assertEqual(json.loads(tx.contract_snapshot), accepted)
            self.assertEqual(contracts.confirmation(tx), document)
            self.assertIn('Model withdrawal form', accepted['withdrawal'])
            self.assertEqual(accepted['language'], 'en')
            self.assertEqual(accepted['terms_de'], '')
            self.assertTrue(accepted['immediate_supply_consent'])
            self.assertTrue(accepted['withdrawal_acknowledged'])
            self.assertTrue(accepted['refund_method_accepted'])
            self.assertEqual(accepted['refund_en'], contracts.REFUND_EN)
            self.assertIn('90 days', accepted['refund_terms'])
        response = self.client.get('/download_contract', query_string={'session_id': order})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, document)
        self.assertIn('no-store', response.headers['Cache-Control'])
        outsider = main.app.test_client()
        self.assertNotEqual(outsider.get('/download_contract', query_string={'session_id': order}).status_code, 200)

    def test_new_paid_order_retries_after_eight_days_with_identical_confirmation(self):
        self.accept_checkout()
        order = self.create_invoice('buyer@example.com')
        with patch.object(crypto_delivery, 'send_license_email', side_effect=RuntimeError('SMTP unavailable')) as send:
            self.finish(order)
        original = send.call_args.kwargs['confirmation_pdf']
        with main.app.app_context():
            delivery = main.db.session.get(CryptoLicenseDelivery, order)
            delivery.created_at = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
            main.db.session.commit()
            with patch.object(crypto_delivery, 'send_license_email') as retry:
                self.assertEqual(crypto_delivery.retry_crypto_deliveries(), 1)
            self.assertEqual(retry.call_args.kwargs['confirmation_pdf'], original)
            self.assertEqual(delivery.delivery_status, 'sent')
            self.assertIsNone(delivery.recipient_encrypted)
            self.assertIsNotNone(main.db.session.get(Transaction, order).customer_email_encrypted)

    def test_pending_older_order_keeps_its_accepted_bilingual_text(self):
        self.accept_checkout()
        order = self.create_invoice('buyer@example.com')
        with main.app.app_context():
            tx = main.db.session.get(Transaction, order)
            data = json.loads(tx.contract_snapshot)
            data.pop('language')
            data.update(version='historical-version', terms_de='Historische deutsche Bedingungen.',
                        terms_en='Historically accepted English terms.',
                        immediate_de='Historische Zustimmung.', refund_de='Historischer Erstattungsweg.')
            tx.contract_snapshot = json.dumps(data)
            main.db.session.commit()
        with patch.object(contracts, 'render_pdf', wraps=contracts.render_pdf) as render, \
             patch.object(crypto_delivery, 'send_license_email'):
            self.finish(order)
        body = render.call_args.args[0]
        for field in ('terms_de', 'terms_en', 'immediate_de', 'refund_de'):
            self.assertIn(data[field], body)
        self.assertNotIn('English is authoritative', body)

    def test_late_verified_payment_restores_unpaid_expired_outbox(self):
        self.accept_checkout()
        order = self.create_invoice('buyer@example.com')
        with main.app.app_context():
            delivery = main.db.session.get(CryptoLicenseDelivery, order)
            delivery.created_at = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
            main.db.session.commit()
            crypto_delivery.retry_crypto_deliveries()
            self.assertIsNone(delivery.recipient_encrypted)
            self.assertEqual(delivery.delivery_status, 'expired')
        with patch.object(crypto_delivery, 'send_license_email') as send:
            self.finish(order)
        self.assertEqual(send.call_count, 1)
        self.assertTrue(send.call_args.kwargs['confirmation_pdf'].startswith(b'%PDF'))

    def test_legacy_orders_do_not_gain_fabricated_consent(self):
        with main.app.app_context():
            tx = Transaction(session_id='legacy', status='finished', provider_payment_id='legacy-payment', provider_reference_type='invoice', expected_price_amount='19.99', expected_price_currency='eur', customer_country='Germany', country_evidence='test', geolocation_database='fixture', created_at=datetime.now(timezone.utc).isoformat())
            main.db.session.add(tx)
            main.db.session.commit()
            self.assertIsNone(contracts.confirmation(tx))
        self.assertEqual(self.client.get('/download_contract?session_id=legacy').status_code, 404)

    def test_patreon_requires_no_withdrawal_acknowledgment(self):
        self.accept_checkout('patreon')
        with main.app.app_context():
            data = json.loads(CheckoutAgreement.query.one().snapshot)
            self.assertFalse(data['immediate_supply_consent'])
            self.assertFalse(data['withdrawal_acknowledged'])
            self.assertTrue(data['refund_method_accepted'])

    def test_refund_consent_is_separate_and_required_for_every_method(self):
        for method in ('crypto', 'card', 'patreon'):
            for value in (None, False, 'true', 1):
                with self.subTest(method=method, value=value):
                    data = dict(self.payment(), payment_method=method,
                                offer_digest=self.offer_digest())
                    if value is None:
                        data.pop('refund_method_accepted')
                    else:
                        data['refund_method_accepted'] = value
                    self.assertEqual(self.client.post('/checkout/start', json=data).status_code, 400)
        with main.app.app_context():
            self.assertEqual(CheckoutAgreement.query.count(), 0)

    def test_receipt_uses_accepted_text_and_is_private_to_current_session(self):
        self.accept_checkout('patreon')
        with main.app.app_context():
            row = CheckoutAgreement.query.one()
            reference = row.id
            accepted = json.loads(row.snapshot)
        with patch.object(contracts, 'terms_snapshot', side_effect=AssertionError('must use original text')), \
             patch.object(contracts, 'render_pdf', wraps=contracts.render_pdf) as render:
            response = self.client.get('/checkout/agreement')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data.startswith(b'%PDF'))
        self.assertIn('no-store', response.headers['Cache-Control'])
        self.assertIn('attachment', response.headers['Content-Disposition'])
        body = render.call_args.args[0]
        self.assertIn(reference, body)
        self.assertIn(accepted['refund_en'], body)
        self.assertIn(accepted['refund_terms'], body)
        self.assertIn('Not automatically linked to a Patreon Shop purchase.', body)
        self.assertNotIn(accepted['immediate_en'], body)
        outsider = main.app.test_client()
        self.assertEqual(outsider.get('/checkout/agreement', query_string={'id': reference}).status_code, 404)
        with self.client.session_transaction() as state:
            state['checkout_consent'] = dict(state['checkout_consent'], accepted_at=time.time() - 3601)
        self.assertEqual(self.client.get('/checkout/agreement').status_code, 404)

    def test_patreon_launch_requires_current_attributable_browser_evidence(self):
        for method in ('get', 'post'):
            response = getattr(self.client, method)('/payment-preview/patreon', data={'confirm_no_payment': 'yes'})
            self.assertEqual(response.status_code, 303)
            self.assertIn('/porn_fetch?method=patreon', response.location)
        self.accept_checkout('patreon')
        self.assertNotIn(b'/checkout/agreement', self.client.get('/payment-preview/patreon').data)
        with main.app.app_context():
            main.db.session.execute(main.db.delete(CheckoutAgreement))
            main.db.session.commit()
        self.assertEqual(self.client.post('/payment-preview/patreon', data={'confirm_no_payment': 'yes'}).status_code, 409)

    def test_old_checkout_version_cannot_start_a_new_payment(self):
        self.accept_checkout()
        with self.client.session_transaction() as state:
            state['checkout_consent'] = dict(state['checkout_consent'], version='checkout-v3')
        with patch('pf_server.nowpayments_service.httpx.post') as provider:
            self.assertEqual(self.client.post('/create-crypto-payment', json=self.payment()).status_code, 409)
            provider.assert_not_called()

    def test_old_order_snapshot_does_not_gain_refund_consent(self):
        self.accept_checkout()
        order = self.create_invoice('buyer@example.com')
        with main.app.app_context():
            tx = main.db.session.get(Transaction, order)
            data = json.loads(tx.contract_snapshot)
            for field in ('refund_method_accepted', 'refund_de', 'refund_en', 'refund_terms'):
                data.pop(field, None)
            tx.contract_snapshot = json.dumps(data)
            main.db.session.commit()
        with patch.object(contracts, 'render_pdf', wraps=contracts.render_pdf) as render, \
             patch.object(crypto_delivery, 'send_license_email'):
            self.finish(order)
        self.assertNotIn('Refund method separately accepted:', render.call_args.args[0])


    def test_smtp_contains_original_confirmation_attachment_and_stable_identity(self):
        with main.app.app_context(), patch.object(licensing.smtplib, 'SMTP') as smtp:
            for _ in range(2):
                licensing.send_license_email('buyer@example.com', b'{"license_key":"signed"}', confirmation_pdf=b'%PDF-original')
            messages = [call.args[0] for call in smtp.return_value.send_message.call_args_list]
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0]['Message-ID'], messages[1]['Message-ID'])
        attachments = {part.get_filename(): part.get_payload(decode=True) for part in messages[0].iter_attachments()}
        self.assertEqual(attachments['confirmation.pdf'], b'%PDF-original')
        self.assertNotIn(b'buyer@example.com', attachments['porn_fetch.license'])

    def test_expired_unassigned_evidence_cleanup_preserves_order_snapshot(self):
        self.accept_checkout()
        order = self.create_invoice('buyer@example.com')
        with main.app.app_context():
            row = CheckoutAgreement.query.one()
            row.created_at = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
            original = main.db.session.get(Transaction, order).contract_snapshot
            main.db.session.commit()
            contracts.purge_checkout_agreements()
            self.assertEqual(CheckoutAgreement.query.count(), 0)
            self.assertEqual(main.db.session.get(Transaction, order).contract_snapshot, original)
