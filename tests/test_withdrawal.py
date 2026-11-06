"""Electronic withdrawal: durable receipt, no purchase gate, independent delivery."""
import json
import re
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from sqlalchemy.exc import OperationalError

from _support import ServerTestCase, main
from pf_server import withdrawal_service as service
from pf_server.extensions import db
from pf_server.models import WithdrawalRequest, WithdrawalDelivery, Transaction, License


class WithdrawalTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        config = patch.dict(main.app.config, LICENSE_EMAIL_FROM='support@example.com')
        config.start()
        self.addCleanup(config.stop)
        self.sender = patch.object(service, 'send_email_message')
        self.send = self.sender.start()
        self.addCleanup(self.sender.stop)
        self.values = dict(name='Erika Musterfrau', email='erika@example.com',
            contract='Teilwiderruf: Zusatzleistung aus Kauf vom 01.01.2020; keine Bestellnummer vorhanden.')

    @staticmethod
    def field(response, name):
        return re.search(r'name="' + name + r'" value="([^"]+)"', response.get_data(as_text=True)).group(1)

    def draft(self, **changes):
        response = self.client.post('/withdrawal/preview', data=self.values | changes)
        self.assertEqual(response.status_code, 200, response.data[:500])
        return self.field(response, 'draft')

    def confirm(self, token):
        return self.client.post('/withdrawal/confirm', data=dict(draft=token, confirm='withdraw'))

    def test_public_link_visible_before_age_check_and_without_checkout(self):
        for path in ('/', '/porn_fetch', '/withdrawal'):
            page = self.client.get(path)
            self.assertEqual(page.status_code, 200)
            self.assertIn('Withdraw from contract', page.get_data(as_text=True))
        page = self.client.get('/withdrawal')
        self.assertNotIn(b'id="age-overlay"', page.data)
        self.assertNotIn(b'<details class="site-menu" open>', page.data)
        self.assertNotIn(b'type="checkbox"', page.data.split(b'<main', 1)[1].split(b'</main>', 1)[0])
        self.assertIn('no-store', page.headers['Cache-Control'])
        with main.app.app_context():
            self.assertEqual(WithdrawalRequest.query.count(), 0)

    def test_existing_referral_block_does_not_block_withdrawal_or_privacy(self):
        host = main.app.config['APP_DOMAIN']
        blocked = self.client.get('/', base_url=host,
            headers={'Referer': 'https://vplan.echteralsfake.me/school/plan'})
        self.assertEqual(blocked.status_code, 403)
        self.assertIn('Withdraw from contract', blocked.get_data(as_text=True))
        for path in ('/withdrawal', '/privacy_policy', '/impress', '/static/withdrawal.css'):
            response = self.client.get(path, base_url=host)
            self.assertEqual(response.status_code, 200)
            response.close()
        preview = self.client.post('/withdrawal/preview', base_url=host, data=self.values)
        self.assertEqual(preview.status_code, 200)
        token = self.field(preview, 'draft')
        received = self.client.post('/withdrawal/confirm', base_url=host,
            data=dict(draft=token, confirm='withdraw'))
        self.assertEqual(received.status_code, 200)
        self.assertEqual(self.client.get('/porn_fetch', base_url=host).status_code, 403)

    def test_preview_is_not_submission_and_keeps_pii_out_of_cookie(self):
        response = self.client.post('/withdrawal/preview', data=self.values)
        self.assertIn('Confirm withdrawal', response.get_data(as_text=True))
        self.assertIn('Not submitted yet', response.get_data(as_text=True))
        self.assertNotIn(self.values['email'], response.headers.get('Set-Cookie', ''))
        token = self.field(response, 'draft')
        self.assertNotIn(self.values['name'], token)
        with main.app.app_context():
            self.assertEqual(WithdrawalRequest.query.count(), 0)
            self.assertEqual(service.read_draft(token)['details'], self.values)
        self.send.assert_not_called()

    def test_edit_preserves_details_and_requires_final_confirmation(self):
        token = self.draft()
        response = self.client.post('/withdrawal/edit', data={'draft': token})
        self.assertIn(self.values['email'], response.get_data(as_text=True))
        self.assertEqual(self.client.post('/withdrawal/confirm', data={'draft': token}).status_code, 400)
        self.send.assert_not_called()
        with main.app.app_context():
            self.assertEqual(WithdrawalRequest.query.count(), 0)

    def test_invalid_inputs_or_tampered_draft_do_not_submit(self):
        for field, value in [('name', ''), ('name', 'x' * 201), ('email', 'bad'),
                             ('email', 'x@example.com\r\nBcc: y@example.com'),
                             ('contract', ''), ('contract', 'x' * 2001)]:
            self.assertEqual(self.client.post('/withdrawal/preview', data=self.values | {field: value}).status_code, 400)
        token = self.draft()
        self.assertEqual(self.confirm(token[:-5] + 'ABCDE').status_code, 400)
        self.assertEqual(self.confirm('arbitrary-order-id').status_code, 400)
        self.send.assert_not_called()
        with main.app.app_context():
            self.assertEqual(WithdrawalRequest.query.count(), 0)

    def test_receipt_contains_full_declaration_and_actual_received_timestamp(self):
        token = self.draft()
        received = datetime(2026, 10, 31, 12, 34, 56, tzinfo=timezone.utc)
        with patch.object(service, 'now', return_value=received):
            response = self.confirm(token)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.send.call_count, 2)
        self.assertEqual([call.args[0]['To'] for call in self.send.call_args_list],
                         ['erika@example.com', 'support@echteralsfake.me'])
        with main.app.app_context():
            row = WithdrawalRequest.query.one()
            self.assertEqual(row.received_at, received.isoformat())
            self.assertNotIn(self.values['email'], row.details_encrypted)
            self.assertNotIn(self.values['contract'], row.receipt_encrypted)
            text = service.decrypt_receipt(row)
            self.assertIn('2026-10-31T13:34:56+01:00', text)
            self.assertIn('2026-10-31T12:34:56+00:00', text)
            self.assertIn(service.STATEMENT, text)
            for value in self.values.values():
                self.assertIn(value, text)
            self.assertEqual(Transaction.query.count(), 0)
            self.assertEqual(License.query.count(), 0)
        consumer = self.send.call_args_list[0].args[0]
        self.assertEqual(consumer.get_body().get_content().strip(), text.strip())
        self.assertEqual(list(consumer.iter_attachments())[0].get_payload(decode=True), text.encode())

    def test_receipt_download_requires_secret_and_returns_original_utf8_text(self):
        token = self.draft(name='李雷 Änne')
        response = self.confirm(token)
        self.assertIn('李雷', response.get_data(as_text=True))
        download = self.client.post('/withdrawal/receipt', data={'draft': token})
        self.assertEqual(download.status_code, 200)
        self.assertIn('no-store', download.headers['Cache-Control'])
        self.assertIn(b'attachment', download.headers['Content-Disposition'].encode())
        self.assertIn('李雷', download.data.decode())
        with main.app.app_context():
            row = WithdrawalRequest.query.one()
            reference = row.id
            self.assertEqual(download.data.decode(), service.decrypt_receipt(row))
        self.assertEqual(self.client.post('/withdrawal/receipt', data={'draft': reference}).status_code, 404)
        self.assertEqual(self.client.get('/withdrawal/receipt?draft=' + token).status_code, 405)

    def test_mail_failure_does_not_change_receipt_and_timer_retries(self):
        token = self.draft()
        self.send.side_effect = RuntimeError('SMTP outage')
        response = self.confirm(token)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Your declaration has been received', response.get_data(as_text=True))
        first = self.send.call_args_list[0].args[0]
        with main.app.app_context():
            row = WithdrawalRequest.query.one()
            original_time = row.received_at
            original_receipt = row.receipt_encrypted
            for item in WithdrawalDelivery.query.all():
                self.assertEqual(item.status, 'failed')
                item.next_attempt_at = (service.now() - timedelta(seconds=1)).isoformat()
            db.session.commit()
        self.send.side_effect = None
        self.send.reset_mock()
        result = main.app.test_cli_runner().invoke(args=['retry-withdrawal-deliveries'])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.send.call_count, 2)
        later = next(call.args[0] for call in self.send.call_args_list if call.args[0]['To'] == self.values['email'])
        self.assertEqual(first['Message-ID'], later['Message-ID'])
        self.assertEqual(first.get_body().get_content(), later.get_body().get_content())
        with main.app.app_context():
            self.assertEqual(WithdrawalRequest.query.one().received_at, original_time)
            self.assertEqual(WithdrawalRequest.query.one().receipt_encrypted, original_receipt)
            self.assertTrue(all(item.status == 'sent' for item in WithdrawalDelivery.query.all()))

    def test_operator_failure_does_not_resend_consumer_receipt(self):
        def fail_operator(message):
            if message['To'] == service.SUPPORT:
                raise RuntimeError('support unavailable')
        self.send.side_effect = fail_operator
        token = self.draft()
        self.confirm(token)
        with main.app.app_context():
            operator = WithdrawalDelivery.query.filter_by(audience='operator').one()
            operator.next_attempt_at = (service.now() - timedelta(seconds=1)).isoformat()
            db.session.commit()
        self.send.reset_mock()
        self.send.side_effect = None
        result = main.app.test_cli_runner().invoke(args=['retry-withdrawal-deliveries'])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(self.send.call_count, 1)
        self.assertEqual(self.send.call_args.args[0]['To'], service.SUPPORT)

    def test_duplicate_confirm_reuses_record_and_does_not_resend(self):
        token = self.draft()
        self.confirm(token)
        with main.app.app_context():
            original = WithdrawalRequest.query.one().receipt_encrypted
        self.assertEqual(self.confirm(token).status_code, 200)
        with main.app.app_context():
            self.assertEqual(WithdrawalRequest.query.count(), 1)
            self.assertEqual(WithdrawalDelivery.query.count(), 2)
            self.assertEqual(WithdrawalRequest.query.one().receipt_encrypted, original)
        self.assertEqual(self.send.call_count, 2)

    def test_active_lease_excludes_concurrent_send_then_recovers_stale_worker(self):
        token = self.draft()
        with main.app.app_context():
            row = service.receive(token, service.read_draft(token), service.now())
            reference = row.id
            delivery = db.session.get(WithdrawalDelivery, (reference, 'consumer'))
            delivery.status = 'sending'
            delivery.lease_token = 'another-worker'
            delivery.lease_expires_at = (service.now() + timedelta(minutes=10)).isoformat()
            db.session.commit()
            self.assertEqual(service.deliver(reference, 'consumer'), 'busy')
            self.send.assert_not_called()
            delivery.lease_expires_at = (service.now() - timedelta(seconds=1)).isoformat()
            db.session.commit()
            self.assertEqual(service.deliver(reference, 'consumer'), 'sent')
            self.send.assert_called_once()

    def test_database_failure_does_not_claim_success_or_send_email(self):
        token = self.draft()
        with patch.object(service, 'receive', side_effect=OperationalError('insert', {}, Exception())):
            response = self.confirm(token)
        self.assertEqual(response.status_code, 503)
        self.assertIn('Receipt could not be confirmed', response.get_data(as_text=True))
        self.assertEqual(self.field(response, 'draft'), token)
        self.send.assert_not_called()
        with main.app.app_context():
            self.assertEqual(WithdrawalRequest.query.count(), 0)

    def test_html_is_escaped_and_mail_headers_are_not_user_controlled(self):
        token = self.draft(name='<script>alert(1)</script>', contract='<img src=x onerror=alert(1)>')
        response = self.confirm(token)
        self.assertNotIn(b'<script>alert(1)</script>', response.data)
        self.assertIn(b'&lt;script&gt;', response.data)
        for call in self.send.call_args_list:
            self.assertNotIn('alert', call.args[0]['Subject'])
            self.assertEqual(call.args[0]['Reply-To'], service.SUPPORT)

    def test_local_operator_workflow_and_no_automatic_license_changes(self):
        self.confirm(self.draft())
        runner = main.app.test_cli_runner()
        listing = runner.invoke(args=['list-withdrawals'])
        self.assertEqual(listing.exit_code, 0, listing.output)
        info = json.loads(listing.output)
        self.assertNotIn(self.values['email'], listing.output)
        shown = runner.invoke(args=['show-withdrawal', '--reference', info['reference']])
        self.assertIn(self.values['contract'], shown.output)
        marked = runner.invoke(args=['mark-withdrawal-reviewed', '--reference', info['reference']])
        self.assertEqual(marked.exit_code, 0)
        self.assertEqual(runner.invoke(args=['list-withdrawals']).output, '')
        self.assertIn(info['reference'], runner.invoke(args=['list-withdrawals', '--all-records']).output)

    def test_csrf_required_at_preview_and_confirmation(self):
        with patch.dict(main.app.config, WTF_CSRF_ENABLED=True):
            self.assertEqual(self.client.post('/withdrawal/preview', data=self.values).status_code, 400)
            page = self.client.get('/withdrawal')
            csrf = self.field(page, 'csrf_token')
            preview = self.client.post('/withdrawal/preview', data=self.values | {'csrf_token': csrf})
            self.assertEqual(preview.status_code, 200)
            token = self.field(preview, 'draft')
            self.assertEqual(self.confirm(token).status_code, 400)
            response = self.client.post('/withdrawal/confirm', data=dict(
                csrf_token=csrf, draft=token, confirm='withdraw'))
            self.assertEqual(response.status_code, 200)

    def test_missing_encryption_key_is_honest_and_keeps_manual_contact_available(self):
        with patch.dict(main.app.config, LICENSE_DELIVERY_ENCRYPTION_KEY='', ONRAMP_ENCRYPTION_KEY=''):
            response = self.client.post('/withdrawal/preview', data=self.values)
        self.assertEqual(response.status_code, 503)
        self.assertIn(b'support@echteralsfake.me', response.data)
        self.send.assert_not_called()
