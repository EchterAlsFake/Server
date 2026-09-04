"""Privacy-safe logging behavior tests."""

import logging
import os
import sys
import unittest

from pf_server.logging_config import PrivacySafeFormatter, safe_log_reference


class PrivacySafeLoggingTests(unittest.TestCase):
    def test_formatter_redacts_personal_data_secrets_and_url_queries(self):
        formatter = PrivacySafeFormatter("%(message)s")
        record = logging.LogRecord(
            "test",
            logging.ERROR,
            __file__,
            1,
            (
                "email=person@example.com ipv4=192.0.2.10 ipv6=2001:db8::1 "
                "mixed_ipv6=::ffff:192.0.2.25 "
                "url=https://example.test/path?token=visible secret=visible "
                "Authorization: Bearer credential Cookie: session=private"
            ),
            (),
            None,
        )

        rendered = formatter.format(record)

        for sensitive_value in (
            "person@example.com",
            "192.0.2.10",
            "2001:db8::1",
            "::ffff:192.0.2.25",
            "token=visible",
            "secret=visible",
            "credential",
            "session=private",
        ):
            self.assertNotIn(sensitive_value, rendered)
        self.assertIn("[REDACTED_EMAIL]", rendered)
        self.assertIn("[REDACTED_IP]", rendered)

    def test_formatter_redacts_exception_messages_without_hiding_timestamps(self):
        try:
            raise RuntimeError("SMTP failed for person@example.com from 203.0.113.8")
        except RuntimeError:
            exception_info = sys.exc_info()
        record = logging.LogRecord(
            "test",
            logging.ERROR,
            __file__,
            1,
            "Failure at 2026-09-01T10:00:00+02:00",
            (),
            exception_info,
        )

        rendered = PrivacySafeFormatter("%(message)s").format(record)

        self.assertIn("2026-09-01T10:00:00+02:00", rendered)
        self.assertNotIn("person@example.com", rendered)
        self.assertNotIn("203.0.113.8", rendered)
        self.assertNotIn("SMTP failed", rendered)
        self.assertNotIn(os.path.dirname(__file__), rendered)
        self.assertIn("RuntimeError", rendered)

    def test_safe_references_are_stable_and_do_not_expose_the_source(self):
        first = safe_log_reference("private-order-reference")
        second = safe_log_reference("private-order-reference")

        self.assertEqual(first, second)
        self.assertEqual(len(first), 12)
        self.assertNotIn("private-order-reference", first)
