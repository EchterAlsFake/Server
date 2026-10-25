"""Private, retry-safe communication with the locally hosted Keygen CE API."""

import httpx
from flask import current_app


class KeygenUnavailable(RuntimeError):
    """A fulfillment operation can be retried without changing payment state."""


def request(method: str, path: str, **kwargs) -> httpx.Response:
    config = current_app.config
    if not config.get("KEYGEN_PRODUCT_TOKEN"):
        raise KeygenUnavailable("Keygen is not configured")
    try:
        return httpx.request(
            method,
            config["KEYGEN_INTERNAL_URL"] + "/v1" + path,
            headers={
                "Host": "licenses.echteralsfake.me",
                "X-Forwarded-Proto": "https",
                "Authorization": "Bearer " + config["KEYGEN_PRODUCT_TOKEN"],
                "Accept": "application/vnd.api+json",
                "Content-Type": "application/vnd.api+json",
            },
            timeout=httpx.Timeout(10, connect=3),
            follow_redirects=False,
            trust_env=False,
            **kwargs,
        )
    except httpx.HTTPError:
        raise KeygenUnavailable("Keygen request failed") from None


ANNUAL_POLICY_ATTRIBUTES = {
    "scheme": "ED25519_SIGN",
    "duration": 31556952,
    "expirationBasis": "FROM_FIRST_ACTIVATION",
    "expirationStrategy": "MAINTAIN_ACCESS",
    "renewalBasis": "FROM_NOW_IF_EXPIRED",
    "maxMachines": 10,
    "authenticationStrategy": "LICENSE",
}


def verify_annual_policy() -> dict:
    """Read-only verification; never modify policies or historical entitlements."""
    policy_id = current_app.config.get("KEYGEN_POLICY_ID")
    if not policy_id:
        raise KeygenUnavailable("Annual licensing policy is not configured")
    response = request("GET", "/policies/" + policy_id)
    if response.status_code != 200:
        raise KeygenUnavailable("Annual licensing policy could not be verified")
    try:
        data = response.json()["data"]
        if data["id"] != policy_id or any(
            data["attributes"].get(name) != value
            for name, value in ANNUAL_POLICY_ATTRIBUTES.items()
        ):
            raise ValueError("Policy mismatch")
        return data
    except (ValueError, KeyError, TypeError, AttributeError):
        raise KeygenUnavailable("Configured policy does not match the annual offer") from None


def ensure_license(issuance_id: str) -> dict:
    """Caller persists a random UUID first; Keygen's primary key deduplicates it."""
    response = request("GET", "/licenses/" + issuance_id)
    if response.status_code == 404:
        verify_annual_policy()
        response = request("POST", "/licenses", json={"data": {
            "type": "licenses", "id": issuance_id,
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
