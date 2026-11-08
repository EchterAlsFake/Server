"""Explicit browser acknowledgment during the temporary real-payment rollout."""

from flask import current_app, session

NOTICE_VERSION = "real-payments-2026-11-08"
SESSION_KEY = "payment_testing_notice"
PURCHASE_POST_PATHS = frozenset({
    "/checkout/start", "/checkout/crypto-confirm", "/create-crypto-payment",
    "/onramp-acknowledgment", "/create-onramp-payment",
    "/payment-preview/patreon", "/payment-preview/card", "/payment-preview/banxa",
})


def acknowledgment_required():
    return (current_app.config["PAYMENT_TESTING_NOTICE_ENABLED"]
            and session.get(SESSION_KEY) != NOTICE_VERSION)
