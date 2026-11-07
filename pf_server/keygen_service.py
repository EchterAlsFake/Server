"""Private, retry-safe communication with the locally hosted Keygen CE API."""

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


LIFETIME_POLICY_ATTRIBUTES = {
    "scheme": "ED25519_SIGN",
    "duration": None,
    "expirationBasis": "FROM_FIRST_ACTIVATION",
    "expirationStrategy": "MAINTAIN_ACCESS",
    "renewalBasis": "FROM_NOW_IF_EXPIRED",
    "maxMachines": 10,
    "authenticationStrategy": "LICENSE",
}


def verify_lifetime_policy() -> dict:
    """Read-only verification; never modify policies or historical entitlements."""
    policy_id = current_app.config.get("KEYGEN_POLICY_ID")
    if not policy_id:
        raise KeygenUnavailable("Lifetime licensing policy is not configured")
    response = request("GET", "/policies/" + policy_id)
    if response.status_code != 200:
        raise KeygenUnavailable("Lifetime licensing policy could not be verified")
    try:
        data = response.json()["data"]
        if data["id"] != policy_id or any(
            name not in data["attributes"] or data["attributes"][name] != value
            for name, value in LIFETIME_POLICY_ATTRIBUTES.items()
        ):
            raise ValueError("Policy mismatch")
        return data
    except (ValueError, KeyError, TypeError, AttributeError):
        raise KeygenUnavailable("Configured policy does not match the lifetime offer") from None


def ensure_license(issuance_id: str, *, test: bool = False) -> dict:
    """Caller persists a random UUID first; Keygen's primary key deduplicates it."""
    response = request("GET", "/licenses/" + issuance_id)
    if response.status_code == 404:
        verify_lifetime_policy()
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
        if not (data["id"] == issuance_id):
            raise ValueError("Keygen response validation failed")
        if not (data["relationships"]["policy"]["data"]["id"] == current_app.config["KEYGEN_POLICY_ID"]):
            raise ValueError("Keygen response validation failed")
        if not (data["attributes"]["scheme"] == "ED25519_SIGN"):
            raise ValueError("Keygen response validation failed")
        if data["attributes"]["expiry"] is not None:
            raise ValueError("Lifetime licenses must not expire")
        if not (data["attributes"]["key"].startswith("key/")):
            raise ValueError("Keygen response validation failed")
        return data
    except (ValueError, KeyError, TypeError, AttributeError):
        raise KeygenUnavailable("Unexpected Keygen issuance response") from None
