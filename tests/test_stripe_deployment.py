"""Ensure deployment settings keep secrets encrypted and other services intact."""

import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "stripe_deployment",
    Path(__file__).resolve().parents[1] / "deploy/configure-stripe.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class StripeDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.values = dict(
            STRIPE_TEST_ACCOUNT_ID="acct_Test",
            STRIPE_LIVE_ACCOUNT_ID="acct_Live",
            STRIPE_TEST_API_KEY="rk_test_synthetic",
            STRIPE_LIVE_API_KEY="rk_live_synthetic",
            STRIPE_TEST_WEBHOOK_SECRET="whsec_test",
            STRIPE_LIVE_WEBHOOK_SECRET="whsec_live",
        )
        self.source = "[Unit]\nDescription=Core\n[Container]\nImage=sha256:original\nEnvironment=MOLLIE_LIVE_ENABLED=true\nEnvironment=NOWPAYMENTS_SANDBOX=true\n[Service]\nLoadCredentialEncrypted=SECRET_KEY:original.cred\n[Install]\nWantedBy=default.target\n"

    def test_key_and_environment_mismatch_fails(self):
        for name, value in [
            ("STRIPE_LIVE_API_KEY", "pk_live_public"),
            ("STRIPE_LIVE_API_KEY", "sk_test_wrong"),
            ("STRIPE_TEST_API_KEY", "sk_live_wrong"),
            ("STRIPE_LIVE_ACCOUNT_ID", "acct_x\nEnvironment=ATTACK=true"),
        ]:
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                module.render_settings(self.source, self.values | {name: value})

    def test_configuration_is_idempotent_and_contains_no_secret_values(self):
        rendered = module.render_settings(self.source, self.values)
        self.assertEqual(module.render_settings(rendered, self.values), rendered)
        for name in module.SECRET_NAMES:
            if name in self.values:
                self.assertNotIn(self.values[name], rendered)
                self.assertIn("LoadCredentialEncrypted=" + name + ":", rendered)
        self.assertIn("Image=sha256:original", rendered)
        self.assertIn("Environment=NOWPAYMENTS_SANDBOX=true", rendered)
        self.assertIn("LoadCredentialEncrypted=SECRET_KEY:original.cred", rendered)
        self.assertIn("Environment=MOLLIE_LIVE_ENABLED=false", rendered)
        self.assertIn("Environment=STRIPE_LIVE_ENABLED=true", rendered)
        self.assertIn("Environment=STRIPE_TEST_ENABLED=false", rendered)

    def test_missing_credentials_or_sections_fail_before_mutating_anything(self):
        with self.assertRaises(ValueError):
            module.render_settings("[Container]\n", self.values)
        for name in self.values:
            incomplete = dict(self.values)
            incomplete.pop(name)
            with self.subTest(name=name), self.assertRaises(ValueError):
                module.render_settings(self.source, incomplete)
