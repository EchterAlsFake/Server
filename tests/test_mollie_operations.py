"""Production credential configuration preserves the commercial payment settings."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "mollie_operations",
    Path(__file__).resolve().parents[1] / "deploy/configure-mollie.py",
)
operations = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operations)


class MollieOperationsTests(unittest.TestCase):
    def test_configuration_preserves_unrelated_environment_and_credentials(self):
        original = "[Container]\nImage=unchanged\nEnvironment=NOWPAYMENTS_SANDBOX=false\nEnvironment=PATREON_SHOP_ENABLED=true\n[Service]\nLoadCredentialEncrypted=SECRET_KEY:existing.cred\n[Install]\nWantedBy=default.target\n"
        configured = operations.replace_settings(original, True, "pfl_Test")
        self.assertIn("Environment=NOWPAYMENTS_SANDBOX=false", configured)
        self.assertIn("Environment=PATREON_SHOP_ENABLED=true", configured)
        self.assertIn("LoadCredentialEncrypted=SECRET_KEY:existing.cred", configured)
        self.assertIn("Environment=MOLLIE_TEST_ENABLED=true", configured)
        self.assertIn("LoadCredentialEncrypted=MOLLIE_TEST_API_KEY:", configured)
        self.assertEqual(
            operations.replace_settings(configured, True, "pfl_Test"), configured
        )

    def test_disabling_preserves_credentials_for_pending_orders(self):
        configured = operations.replace_settings(
            "[Container]\n[Service]\n", True, "pfl_Test"
        )
        disabled = operations.replace_settings(configured, False, "pfl_Test")
        self.assertIn("Environment=MOLLIE_TEST_ENABLED=false", disabled)
        self.assertIn("LoadCredentialEncrypted=MOLLIE_TEST_API_KEY:", disabled)
        self.assertIn("LoadCredentialEncrypted=MOLLIE_TEST_PASSWORD_HASH:", disabled)
        self.assertNotIn("Environment=MOLLIE_TEST_ENABLED=true", disabled)

    def test_atomic_credential_write_keeps_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.cred"
            operations.atomic_write(
                path, b"synthetic ciphertext", os.getuid(), os.getgid()
            )
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            operations.atomic_write(path, b"replacement ciphertext")
            self.assertEqual(path.read_bytes(), b"replacement ciphertext")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
