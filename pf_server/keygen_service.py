"""Private, retry-safe communication with the locally hosted Keygen CE API."""

import hashlib
import json
import uuid
import httpx
from flask import current_app


class KeygenUnavailable(RuntimeError):
    """A fulfillment operation can be retried without changing payment state."""


def request(method: str, path: str, **kwargs) -> httpx.Response:
    config = current_app.config
    if not config.get("KEYGEN_PRODUCT_TOKEN"):
        raise KeygenUnavailable("Keygen is not configured")
    extra_headers = kwargs.pop('headers', {})
    try:
        return httpx.request(
            method,
            config["KEYGEN_INTERNAL_URL"] + "/v1" + path,
            headers={
                "Host": "licenses.pornfetch.to",
                "X-Forwarded-Proto": "https",
                "Authorization": "Bearer " + config["KEYGEN_PRODUCT_TOKEN"],
                "Accept": "application/vnd.api+json",
                "Content-Type": "application/vnd.api+json",
                **extra_headers,
            },
            timeout=httpx.Timeout(10, connect=3),
            follow_redirects=False,
            trust_env=False,
            **kwargs,
        )
    except httpx.HTTPError:
        raise KeygenUnavailable("Keygen request failed") from None


def ensure_license(issuance_id: str, *, test: bool = False) -> dict:
    """Caller persists a random UUID first; Keygen's primary key deduplicates it."""
    response = request("GET", "/licenses/" + issuance_id)
    if response.status_code == 404:
        response = request("POST", "/licenses", json={"data": {
            "type": "licenses", "id": issuance_id,
            "attributes": {"metadata": {"lifecycle": "test" if test else "commercial"}},
            "relationships": {"policy": {"data": {
                "type": "policies", "id": current_app.config["KEYGEN_POLICY_ID"],
            }}},
        }})
        # A concurrent create may win. Resolve the persisted ID, never generate another.
        if response.status_code in (409, 422, 500):
            response = request("GET", "/licenses/" + issuance_id)
    if response.status_code not in (200, 201):
        raise KeygenUnavailable("Keygen issuance is unavailable")
    try:
        data = response.json()["data"]
        assert data["id"] == issuance_id
        assert data["relationships"]["policy"]["data"]["id"] == current_app.config["KEYGEN_POLICY_ID"]
        assert data["attributes"]["scheme"] == "ED25519_SIGN"
        assert data["attributes"]["key"].startswith("key/")
        return data
    except (ValueError, KeyError, TypeError, AssertionError):
        raise KeygenUnavailable("Unexpected Keygen issuance response") from None


def renewal_target(signed_key: str) -> str:
    """Prove key possession in a POST body before binding a checkout to a license."""
    if not isinstance(signed_key, str) or not signed_key.startswith('key/') or len(signed_key) > 16384:
        raise ValueError('Invalid renewal license')
    response = request('POST', '/licenses/actions/validate-key', json={'meta': {'key': signed_key}})
    if response.status_code != 200:
        raise KeygenUnavailable('Renewal validation unavailable')
    try:
        data = response.json()['data']
        assert data['relationships']['policy']['data']['id'] == current_app.config['KEYGEN_POLICY_ID']
        assert data['attributes']['expiry'] is not None and not data['attributes']['suspended']
        assert data['attributes']['key'] == signed_key
        return str(uuid.UUID(data['id']))
    except (AssertionError, KeyError, TypeError, ValueError):
        raise ValueError('Renewal requires an activated commercial license') from None


def renew_verified_payment(provider: str, environment: str, payment_reference: str, license_id: str) -> dict:
    """Internal only: caller must verify settlement and bind the customer's target.

    Persist the target before I/O. Keygen commits expiry and deduplication together,
    so timeout, process death and concurrent delivery all retry the same operation.
    Never use a webhook delivery ID: use the stable settled payment/charge ID.
    """
    from sqlalchemy.exc import IntegrityError
    from .extensions import db
    from .models import LicenseRenewal
    if provider not in ('nowpayments', 'patreon') or environment not in ('sandbox', 'production') or not payment_reference:
        raise ValueError('Invalid payment identity')
    license_id = str(uuid.UUID(license_id))
    reference = hashlib.sha256(json.dumps([provider, environment, payment_reference], separators=(',', ':')).encode()).hexdigest()
    binding = db.session.get(LicenseRenewal, reference)
    if binding is None:
        binding = LicenseRenewal(reference_hash=reference, keygen_id=license_id)
        db.session.add(binding)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            binding = db.session.get(LicenseRenewal, reference)
    if binding is None or binding.keygen_id != license_id:
        raise ValueError('Payment is already bound to a different license')
    response = request('POST', '/licenses/' + license_id + '/actions/renew',
                       headers={'Idempotency-Key': reference})
    if response.status_code != 200:
        raise KeygenUnavailable('Renewal unavailable')
    try:
        data = response.json()['data']
        assert data['id'] == license_id
        assert data['relationships']['policy']['data']['id'] == current_app.config['KEYGEN_POLICY_ID']
        assert reference in data['attributes']['metadata']['pfRenewals']
    except (AssertionError, KeyError, TypeError, ValueError):
        raise KeygenUnavailable('Unexpected renewal response') from None
    binding.completed = True
    db.session.commit()
    return data
