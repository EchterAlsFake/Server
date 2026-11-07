"""Short-lived shared checkout confirmations stored in the signed browser session."""

import time
from flask import session
from .countries import COUNTRY_OPTIONS

CONSENT_VERSION = "checkout-lifetime-v1"
FIELDS = ("age_confirmed", "terms_accepted", "withdrawal_accepted", "refund_method_accepted", "test_acknowledged")


def required_fields(method):
    return tuple(field for field in FIELDS if method != 'patreon' or field != 'withdrawal_accepted')


def current_consent():
    value = session.get("checkout_consent")
    if not isinstance(value, dict) or value.get("version") != CONSENT_VERSION:
        return None
    timestamp = value.get("accepted_at")
    if (
        not isinstance(timestamp, (int, float))
        or not 0 <= time.time() - timestamp < 3600
    ):
        return None
    if (
        (value.get("payment_method") != "patreon" and (not isinstance(value.get("country"), str) or value.get("country") not in dict(COUNTRY_OPTIONS)))
        or not all(value.get(field) is True for field in required_fields(value.get('payment_method')))
    ):
        return None
    return value


def current_selection():
    """Shared confirmations, awaiting crypto-only country and supply consent."""
    value = session.get("checkout_selection")
    if not isinstance(value, dict) or value.get("version") != CONSENT_VERSION:
        return None
    accepted_at = value.get("accepted_at")
    if not isinstance(accepted_at, (int, float)) or not 0 <= time.time() - accepted_at < 3600:
        return None
    if value.get("payment_method") != "crypto" or not all(value.get(field) is True for field in FIELDS if field != "withdrawal_accepted"):
        return None
    return value
