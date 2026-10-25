"""Recovery links remain private, portable and bounded after fulfillment."""

import hashlib
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx

from _support import ServerTestCase, main
from pf_server import checkout_recovery as recovery
from pf_server.extensions import db
from pf_server.models import CheckoutRecovery, Transaction


class CheckoutRecoveryTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.settings = patch.dict(main.app.config, NOWPAYMENTS_SANDBOX=True, NOWPAYMENTS_API_KEY="test-api-key")
        self.settings.start()
        self.addCleanup(self.settings.stop)
        response = httpx.Response(200, json={"id": "invoice-recovery",
            "invoice_url": "https://nowpayments.io/payment/?iid=invoice-recovery"},
            request=httpx.Request("POST", "https://api.nowpayments.io/v1/invoice"))
        with patch("pf_server.nowpayments_service.httpx.post", return_value=response):
            created = self.client.post("/create-crypto-payment", json=dict(
                country="DE", terms_accepted=True, age_confirmed=True,
                withdrawal_accepted=True, test_acknowledged=True,
                no_email_acknowledged=True))
        self.assertEqual(created.status_code, 200)
        self.created = created.json
        self.session_id = created.json["session_id"]
        self.url = created.json["status_url"]
        self.token = parse_qs(urlsplit(self.url).query)["token"][0]

    def finish(self):
        result = self.client.post("/simulate-payment-success", json={"session_id": self.session_id})
        self.assertEqual(result.status_code, 200)

    def test_short_random_token_is_stored_only_as_a_hash(self):
        self.assertEqual(len(self.token), 22)
        with main.app.app_context():
            row = db.session.get(CheckoutRecovery, self.session_id)
            self.assertEqual(row.token_digest, hashlib.sha256(self.token.encode()).hexdigest())
            self.assertNotIn(self.token, row.token_digest)
        self.assertNotIn(self.session_id, self.url)

    def test_recovery_is_portable_to_a_new_browser_and_survives_refresh(self):
        other = main.app.test_client()
        for _ in range(2):
            page = other.get(self.url)
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"Save your private recovery link before paying", page.data)
            self.assertEqual(page.headers["Cache-Control"], "no-store")
            self.assertEqual(page.headers["Referrer-Policy"], "no-referrer")
            self.assertIn("noindex", page.headers["X-Robots-Tag"])

    def test_recovery_controls_precede_provider_launch_and_file_has_same_url(self):
        page = self.client.get(self.url)
        self.assertLess(page.data.index(b'id="recovery-heading"'), page.data.index(b'id="payment-launch"'))
        self.assertIn(b'Copy recovery link', page.data)
        self.assertIn(b'Save recovery file', page.data)
        result = main.app.test_client().get("/download-recovery?token=" + self.token)
        self.assertEqual(result.status_code, 200)
        self.assertIn(self.created["recovery_url"].encode(), result.data)
        self.assertIn("attachment", result.headers["Content-Disposition"])

    def test_raw_order_id_is_not_a_recovery_credential_in_another_browser(self):
        other = main.app.test_client()
        for path in ("/buy_success", "/check-payment-status", "/download_license",
                     "/download_invoice", "/download-recovery"):
            self.assertEqual(other.get(path, query_string={"session_id": self.session_id}).status_code, 410)

    def test_wrong_or_malformed_token_never_falls_back_to_an_order_id(self):
        for token in ("A" * 22, "too-short", "../bad"):
            self.assertEqual(self.client.get("/download_license", query_string={
                "token": token, "session_id": self.session_id}).status_code, 410)

    def test_paid_order_can_be_downloaded_without_email_or_original_cookies(self):
        self.finish()
        other = main.app.test_client()
        status = other.get("/check-payment-status?token=" + self.token)
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json["status"], "finished")
        self.assertEqual(other.get("/download_license?token=" + self.token).status_code, 200)
        self.assertEqual(other.get("/download_invoice?token=" + self.token).status_code, 200)

    def test_pending_payment_does_not_expire_after_six_hours(self):
        future = recovery.now() + timedelta(hours=7)
        with patch.object(recovery, "now", return_value=future):
            self.assertEqual(main.app.test_client().get(self.url).status_code, 200)

    def test_ready_token_expires_at_six_hours_even_with_original_cookie(self):
        self.finish()
        with main.app.app_context():
            row = db.session.get(CheckoutRecovery, self.session_id)
            transaction = db.session.get(Transaction, self.session_id)
            cutoff = recovery.deadline(row, transaction)
        with patch.object(recovery, "now", return_value=cutoff - timedelta(seconds=1)):
            self.assertEqual(self.client.get(self.url).status_code, 200)
        with patch.object(recovery, "now", return_value=cutoff):
            for query in ({"token": self.token}, {"session_id": self.session_id}):
                for path in ("/buy_success", "/check-payment-status", "/download_license", "/download_invoice", "/download-recovery"):
                    self.assertEqual(self.client.get(path, query_string=query).status_code, 410)
            self.assertEqual(self.client.post("/simulate-payment-success", json={"session_id": self.session_id}).status_code, 410)

    def test_pending_token_expires_after_seven_days(self):
        with patch.object(recovery, "now", return_value=recovery.now() + timedelta(days=7, seconds=1)):
            self.assertEqual(self.client.get(self.url).status_code, 410)

    def test_cleanup_removes_hash_without_reopening_raw_id_access(self):
        self.finish()
        with patch.object(recovery, "now", return_value=recovery.now() + timedelta(hours=7)):
            with main.app.app_context():
                self.assertEqual(recovery.expire_tokens(), 1)
                self.assertIsNone(db.session.get(CheckoutRecovery, self.session_id).token_digest)
            self.assertEqual(self.client.get("/download_license", query_string={"session_id": self.session_id}).status_code, 410)

    def test_pending_payment_completed_late_gets_full_six_hour_ready_window(self):
        completed = recovery.now() + timedelta(days=6, hours=23)
        with main.app.app_context():
            transaction = db.session.get(Transaction, self.session_id)
            transaction.status = "finished"
            transaction.finished_at = completed.isoformat()
            db.session.commit()
        with patch.object(recovery, "now", return_value=completed + timedelta(hours=5)):
            self.assertEqual(self.client.get(self.url).status_code, 200)
