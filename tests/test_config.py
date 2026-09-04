"""Environment configuration parsing and validation tests."""

import os
import tempfile
import unittest

from pf_server.config import load_environment_config


class ConfigurationTests(unittest.TestCase):
    def test_configuration_normalizes_paths_origins_booleans_and_tiers(self):
        with tempfile.TemporaryDirectory(prefix="server-config-") as directory:
            config = load_environment_config(
                directory,
                {
                    "SECRET_KEY": "configured-secret",
                    "APP_DOMAIN": "https://public.example/",
                    "API_DOMAIN": "https://API.EXAMPLE/",
                    "NOWPAYMENTS_SANDBOX": "no",
                    "NOWPAYMENTS_API_KEY": "api-key",
                    "NOWPAYMENTS_IPN_SECRET": "ipn-secret",
                    "PATREON_LICENSE_TIER_IDS": "first, second,first",
                    "LICENSE_SMTP_SSL": "yes",
                    "LICENSE_SMTP_STARTTLS": "false",
                },
            )

        self.assertEqual(config["APP_DOMAIN"], "https://public.example")
        self.assertEqual(config["API_DOMAIN"], "https://API.EXAMPLE")
        self.assertEqual(config["API_PUBLIC_HOST"], "api.example")
        self.assertFalse(config["NOWPAYMENTS_SANDBOX"])
        self.assertTrue(config["LICENSE_SMTP_SSL"])
        self.assertFalse(config["LICENSE_SMTP_STARTTLS"])
        self.assertEqual(
            config["PATREON_LICENSE_TIER_IDS"], frozenset({"first", "second"})
        )

    def test_invalid_public_origins_fail_fast(self):
        with tempfile.TemporaryDirectory(prefix="server-config-") as directory:
            for variable, value in (
                ("APP_DOMAIN", "public.example"),
                ("API_DOMAIN", "file:///tmp/api"),
                ("APP_DOMAIN", "https://user:password@public.example"),
                ("API_DOMAIN", "https://api.example/unexpected/path"),
                ("APP_DOMAIN", "https://public.example:not-a-port"),
                ("API_DOMAIN", "https://api.example:70000"),
            ):
                with self.subTest(variable=variable):
                    with self.assertRaisesRegex(ValueError, variable):
                        load_environment_config(
                            directory,
                            {"SECRET_KEY": "secret", variable: value},
                        )

    def test_invalid_booleans_fail_instead_of_silently_disabling_features(self):
        with tempfile.TemporaryDirectory(prefix="server-config-") as directory:
            for variable in (
                "NOWPAYMENTS_SANDBOX",
                "LICENSE_SMTP_SSL",
                "LICENSE_SMTP_STARTTLS",
            ):
                with self.subTest(variable=variable):
                    with self.assertRaisesRegex(ValueError, variable):
                        load_environment_config(
                            directory,
                            {"SECRET_KEY": "secret", variable: "treu"},
                        )

    def test_invalid_log_levels_fail_fast(self):
        with tempfile.TemporaryDirectory(prefix="server-config-") as directory:
            with self.assertRaisesRegex(ValueError, "LOG_LEVEL"):
                load_environment_config(
                    directory,
                    {"SECRET_KEY": "secret", "LOG_LEVEL": "verbose"},
                )

    def test_checkout_geolocation_configuration_is_normalized_and_validated(self):
        with tempfile.TemporaryDirectory(prefix="server-config-") as directory:
            config = load_environment_config(
                directory,
                {
                    "SECRET_KEY": "secret",
                    "GEOIP_DATABASE_PATH": "relative/country.mmdb",
                    "GEOIP_DATABASE_LABEL": "fixture release",
                    "CHECKOUT_IP_HEADER": "",
                },
            )
            self.assertEqual(
                config["GEOIP_DATABASE_PATH"],
                os.path.abspath("relative/country.mmdb"),
            )
            self.assertEqual(config["GEOIP_DATABASE_LABEL"], "fixture release")
            self.assertEqual(config["CHECKOUT_IP_HEADER"], "")

            default_config = load_environment_config(
                directory,
                {"SECRET_KEY": "secret"},
            )
            self.assertEqual(
                default_config["CHECKOUT_IP_HEADER"], "X-Forwarded-For"
            )

            with self.assertRaisesRegex(ValueError, "CHECKOUT_IP_HEADER"):
                load_environment_config(
                    directory,
                    {
                        "SECRET_KEY": "secret",
                        "CHECKOUT_IP_HEADER": "Forwarded",
                    },
                )

    def test_invalid_smtp_ports_fail_with_clear_errors(self):
        with tempfile.TemporaryDirectory(prefix="server-config-") as directory:
            for value, message in (
                ("not-a-port", "must be an integer"),
                ("70000", "must be between"),
            ):
                with self.subTest(value=value):
                    with self.assertRaisesRegex(ValueError, message):
                        load_environment_config(
                            directory,
                            {
                                "SECRET_KEY": "secret",
                                "LICENSE_SMTP_PORT": value,
                            },
                        )

    def test_production_payments_require_both_secrets(self):
        with tempfile.TemporaryDirectory(prefix="server-config-") as directory:
            with self.assertRaisesRegex(ValueError, "NOWPAYMENTS_API_KEY"):
                load_environment_config(
                    directory,
                    {
                        "SECRET_KEY": "secret",
                        "NOWPAYMENTS_SANDBOX": "false",
                    },
                )

    def test_inconsistent_smtp_security_fails_fast(self):
        with tempfile.TemporaryDirectory(prefix="server-config-") as directory:
            for settings, message in (
                (
                    {
                        "LICENSE_SMTP_SSL": "true",
                        "LICENSE_SMTP_STARTTLS": "true",
                    },
                    "cannot both be enabled",
                ),
                (
                    {"LICENSE_SMTP_USERNAME": "mailer"},
                    "LICENSE_SMTP_PASSWORD is required",
                ),
            ):
                with self.subTest(settings=settings):
                    with self.assertRaisesRegex(ValueError, message):
                        load_environment_config(
                            directory,
                            {"SECRET_KEY": "secret", **settings},
                        )

    def test_invalid_license_signing_keys_fail_fast(self):
        with tempfile.TemporaryDirectory(prefix="server-config-") as directory:
            for encoded_key, message in (
                ("not-base64", "valid base64"),
                ("c2hvcnQ=", "exactly 32 bytes"),
            ):
                with self.subTest(encoded_key=encoded_key):
                    with self.assertRaisesRegex(ValueError, message):
                        load_environment_config(
                            directory,
                            {
                                "SECRET_KEY": "secret",
                                "LICENSE_PRIVATE_KEY_B64": encoded_key,
                            },
                        )

    def test_generated_secret_is_private_and_stable(self):
        with tempfile.TemporaryDirectory(prefix="server-config-") as directory:
            first = load_environment_config(directory, {})
            second = load_environment_config(directory, {})
            secret_path = os.path.join(directory, ".flask_secret")

            self.assertEqual(first["SECRET_KEY"], second["SECRET_KEY"])
            self.assertEqual(os.stat(secret_path).st_mode & 0o777, 0o600)
