"""Email language order, safe HTML, invoice attachments and retry identities."""

from unittest.mock import MagicMock, patch

from _support import ServerTestCase, main
from pf_server import licensing
from pf_server.invoice_service import build_simulated_invoice


class LicenseEmailTests(ServerTestCase):
    def send(self, *, invoice=None, environment="production"):
        smtp = MagicMock()
        smtp.__enter__.return_value = smtp
        with main.app.app_context(), patch.dict(main.app.config, {
            "LICENSE_SMTP_HOST": "localhost", "LICENSE_EMAIL_FROM": "sender@example.com",
            "LICENSE_SMTP_STARTTLS": False, "LICENSE_SMTP_SSL": False,
            "LICENSE_SMTP_USERNAME": "", "LICENSE_SMTP_PASSWORD": "",
        }), patch.object(licensing.smtplib, "SMTP", return_value=smtp):
            licensing.send_license_email("buyer@example.com", b"test-license-file",
                invoice=invoice, payment_environment=environment)
        return smtp.send_message.call_args.args[0]

    def test_english_first_with_readable_html_and_plain_text_fallback(self):
        message = self.send()
        plain = message.get_body(preferencelist=("plain",)).get_content()
        html = message.get_body(preferencelist=("html",)).get_content()
        self.assertTrue(str(message["Subject"]).startswith("Your Porn Fetch license"))
        self.assertLess(plain.index("English"), plain.index("Deutsch"))
        self.assertLess(html.index('<section lang="en">'), html.index('<section lang="de">'))
        self.assertIn("Arial,Helvetica,sans-serif", html)
        self.assertIn("font-size:16px", html)
        self.assertNotIn("<script", html)
        self.assertNotIn("<img", html)
        self.assertNotIn("@import", html)

    def test_license_and_original_invoice_are_both_attached(self):
        invoice = build_simulated_invoice()
        message = self.send(invoice=invoice)
        attachments = list(message.iter_attachments())
        self.assertEqual(len(attachments), 2)
        self.assertEqual(attachments[0].get_filename(), "porn_fetch.license")
        self.assertEqual(attachments[0].get_payload(decode=True), b"test-license-file")
        self.assertEqual(attachments[1].get_content_type(), "application/pdf")
        self.assertTrue(attachments[1].get_payload(decode=True).startswith(b"%PDF"))
        self.assertIn(invoice["Invoice Number"], attachments[1].get_filename())

    def test_invoice_content_is_escaped_in_html(self):
        invoice = build_simulated_invoice()
        invoice["Invoice Number"] = '<img src="https://example.invalid/tracker">'
        html = self.send(invoice=invoice).get_body(preferencelist=("html",)).get_content()
        self.assertNotIn('<img src=', html)
        self.assertIn("&lt;img", html)

    def test_retry_identity_is_stable_but_separate_invoices_are_distinct(self):
        invoice = build_simulated_invoice()
        first = self.send(invoice=invoice)["Message-ID"]
        self.assertEqual(first, self.send(invoice=invoice)["Message-ID"])
        self.assertNotEqual(first, self.send(invoice={**invoice, "Invoice Number": "INV-SECOND"})["Message-ID"])

    def test_sandbox_email_is_clearly_labelled_and_marks_pdf_as_test(self):
        invoice = build_simulated_invoice()
        with patch("pf_server.invoice_service.render_invoice_pdf", return_value=b"%PDF-test") as render:
            message = self.send(invoice=invoice, environment="sandbox")
        self.assertTrue(str(message["Subject"]).startswith("[TEST]"))
        self.assertIn("No real payment was received", message.get_body(preferencelist=("plain",)).get_content())
        self.assertEqual(render.call_args.args[0]["Environment"], "sandbox")
