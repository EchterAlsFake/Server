"""Short-lived shared checkout confirmations stored in the signed browser session."""

import time
from flask import session
from .countries import COUNTRY_OPTIONS

CONSENT_VERSION = "checkout-v1"
FIELDS = ("age_confirmed", "terms_accepted", "withdrawal_accepted", "test_acknowledged")


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
        not isinstance(value.get("country"), str)
        or value.get("country") not in dict(COUNTRY_OPTIONS)
        or not all(value.get(field) is True for field in FIELDS)
    ):
        return None
    return value
