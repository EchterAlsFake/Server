"""Shared isolated application fixture for server regression tests."""

import hashlib
import hmac
import json
import os
import tempfile
import unittest
from unittest.mock import patch

TEST_RUNTIME = tempfile.TemporaryDirectory(prefix="server-tests-")
os.environ["PF_SERVER_DATA_DIR"] = TEST_RUNTIME.name
os.environ["PF_SERVER_DB"] = os.path.join(TEST_RUNTIME.name, "server.db")
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["NOWPAYMENTS_IPN_SECRET"] = "nowpayments-test-secret"
os.environ["NOWPAYMENTS_SANDBOX"] = "true"
os.environ["NOWPAYMENTS_LOCAL_SIMULATION_ENABLED"] = "true"
os.environ["SEO_INDEXING_ENABLED"] = "true"
os.environ["APP_DOMAIN"] = "https://echteralsfake.me"


from cryptography.fernet import Fernet
os.environ["LICENSE_DELIVERY_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

import main  # noqa: E402
from pf_server.country_service import CountryEvidence  # noqa: E402
from pf_server.extensions import limiter  # noqa: E402
from pf_server.models import (  # noqa: E402
    PatreonShopCustomer, PatreonShopPurchase, PatreonShopHealth,
    WithdrawalRequest,
    WithdrawalDelivery,
    CheckoutAgreement,
    PaymentProgress,
    PaymentReceipt,
    CheckoutRecovery,
    CryptoLicenseDelivery,
    Checklist,
    CiStatus,
    License,
    OnrampCheckout,
    Transaction,
    LicenseRenewal,
)

with main.app.app_context():
    main.db.create_all()


class ServerTestCase(unittest.TestCase):
    def setUp(self):
        limiter.reset()
        limiter.enabled = False
        main.app.config.update(
            TESTING=True,
            RATELIMIT_ENABLED=False,
            WTF_CSRF_ENABLED=False,
        )
        self.client = main.app.test_client()
        from license_fixtures import issuance
        self.keygen_mock = patch("pf_server.licensing.ensure_license", side_effect=issuance)
        self.keygen_mock.start()
        self.addCleanup(self.keygen_mock.stop)
        self.country_lookup = patch.object(
            main.app.extensions["country_resolver"],
            "lookup",
            return_value=CountryEvidence(
                status="found",
                country_code="DE",
                subdivision="Saxony-Anhalt",
                database_label="DB-IP City Lite test fixture",
            ),
        )
        self.mock_country_lookup = self.country_lookup.start()
        with main.app.app_context():
            for model in (
                PatreonShopPurchase, PatreonShopCustomer, PatreonShopHealth,
                WithdrawalDelivery,
                WithdrawalRequest,
                CheckoutAgreement,
                PaymentProgress,
                PaymentReceipt,
                CheckoutRecovery,
                CryptoLicenseDelivery,
                Checklist,
                LicenseRenewal,
                CiStatus,
                OnrampCheckout,
                License,
                Transaction,
            ):
                main.db.session.execute(main.db.delete(model))
            main.db.session.commit()

    @staticmethod
    def offer_digest():
        from pf_server.contracts import offer_digest
        with main.app.app_context():
            return offer_digest()

    def accept_checkout(self, method="crypto", country="DE", **request_options):
        response = self.client.post("/checkout/start", json=dict(
            payment_method=method, country=country, age_confirmed=True,
            terms_accepted=True, withdrawal_accepted=method != "patreon",
            test_acknowledged=True, refund_method_accepted=True, offer_digest=self.offer_digest()), **request_options)
        self.assertEqual(response.status_code, 200, response.data)
        return response

    def tearDown(self):
        self.country_lookup.stop()
        with main.app.app_context():
            main.db.session.remove()
        limiter.reset()
        limiter.enabled = True


    @staticmethod
    def nowpayments_signature(payload: object) -> str:
        canonical_body = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(
            main.app.config["NOWPAYMENTS_IPN_SECRET"].encode("utf-8"),
            canonical_body,
            hashlib.sha512,
        ).hexdigest()


def drain_payment_receipts():
    from pf_server.payment_receipts import process_receipts
    with main.app.app_context():
        process_receipts()
