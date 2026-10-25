"""Durable acknowledgment, retry, lease and replay boundaries for signed receipts."""

from datetime import timedelta
from unittest.mock import patch

from sqlalchemy.exc import SQLAlchemyError

from _support import ServerTestCase, main
from pf_server.extensions import db
from pf_server.models import License, PaymentReceipt, Transaction
from pf_server.payment_receipts import now, process_receipts


class PaymentReceiptTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        with main.app.app_context():
            db.session.add(Transaction(
                session_id="NP-receipt", provider_payment_id="invoice-receipt",
                provider_reference_type="invoice", expected_price_amount="19.99",
                expected_price_currency="eur", customer_country="Germany",
                country_evidence="test", geolocation_database="test", status="pending",
                created_at=now().isoformat(),
            ))
            db.session.commit()
        self.payload = dict(order_id="NP-receipt", payment_id="payment-receipt",
            invoice_id="invoice-receipt", payment_status="finished",
            price_amount=19.99, price_currency="eur", pay_currency="btc", actually_paid=0.01)

    def post(self, valid=True):
        return self.client.post("/nowpayments-ipn", json=self.payload,
            headers={"x-nowpayments-sig": self.nowpayments_signature(self.payload) if valid else "0" * 128},
            base_url="https://api.echteralsfake.me")

    def test_acknowledgment_persists_receipt_without_keygen_or_smtp(self):
        self.payload["customer_email"] = "must-not-be-stored@example.com"
        with patch("pf_server.payment_receipts.complete_payment") as fulfill:
            self.assertEqual(self.post().status_code, 200)
            fulfill.assert_not_called()
        with main.app.app_context():
            receipt = PaymentReceipt.query.one()
            self.assertEqual(receipt.status, "pending")
            self.assertNotIn("must-not-be-stored", receipt.payload)
            self.assertEqual(db.session.get(Transaction, "NP-receipt").status, "pending")
            self.assertEqual(License.query.count(), 0)

    def test_invalid_signature_never_enters_queue(self):
        self.assertEqual(self.post(valid=False).status_code, 403)
        with main.app.app_context():
            self.assertEqual(PaymentReceipt.query.count(), 0)

    def test_storage_failure_requests_provider_redelivery(self):
        with patch("pf_server.payment_receipts.enqueue", side_effect=SQLAlchemyError()):
            result = self.post()
        self.assertEqual(result.status_code, 503)
        self.assertEqual(result.headers["Retry-After"], "30")

    def test_worker_can_resume_after_failure_without_another_webhook(self):
        self.assertEqual(self.post().status_code, 200)
        with main.app.app_context():
            with patch("pf_server.payment_receipts.complete_payment", side_effect=OSError()):
                self.assertEqual(process_receipts(), 1)
            receipt = PaymentReceipt.query.one()
            self.assertEqual(receipt.status, "pending")
            self.assertEqual(receipt.attempts, 1)
            self.assertIsNone(receipt.lease_token)
            receipt.next_attempt_at = (now() - timedelta(seconds=1)).isoformat()
            db.session.commit()
            self.assertEqual(process_receipts(), 1)
            self.assertEqual(PaymentReceipt.query.one().status, "done")
            self.assertEqual(db.session.get(Transaction, "NP-receipt").status, "finished")
            self.assertEqual(License.query.count(), 1)

    def test_duplicate_notification_and_worker_runs_issue_one_license(self):
        self.post()
        self.post()
        with main.app.app_context():
            self.assertEqual(PaymentReceipt.query.count(), 1)
            self.assertEqual(process_receipts(), 1)
            self.assertEqual(process_receipts(), 0)
        self.post()
        with main.app.app_context():
            self.assertEqual(process_receipts(), 0)
            self.assertEqual(License.query.count(), 1)

    def test_active_lease_is_not_stolen_and_expired_lease_is_recovered(self):
        self.post()
        with main.app.app_context():
            receipt = PaymentReceipt.query.one()
            receipt.status = "processing"
            receipt.lease_token = "other-worker"
            receipt.lease_expires_at = (now() + timedelta(minutes=10)).isoformat()
            db.session.commit()
            self.assertEqual(process_receipts(), 0)
            receipt.lease_expires_at = (now() - timedelta(seconds=1)).isoformat()
            db.session.commit()
            self.assertEqual(process_receipts(), 1)
            self.assertEqual(License.query.count(), 1)

    def test_wrong_asset_or_price_remains_unfulfilled_after_acknowledgment(self):
        self.payload["price_amount"] = 1
        self.post()
        with main.app.app_context():
            self.assertEqual(process_receipts(), 1)
            self.assertEqual(PaymentReceipt.query.one().status, "rejected")
            self.assertEqual(db.session.get(Transaction, "NP-receipt").status, "pending")
            self.assertEqual(License.query.count(), 0)

    def test_partial_ordinary_invoice_cannot_bypass_finished_requirement(self):
        self.payload["payment_status"] = "partially_paid"
        self.post()
        with main.app.app_context():
            process_receipts()
            self.assertEqual(db.session.get(Transaction, "NP-receipt").status, "pending")
            self.assertEqual(License.query.count(), 0)
