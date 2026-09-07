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


def ensure_license(issuance_id: str) -> dict:
    """Caller persists a random UUID first; Keygen's primary key deduplicates it."""
    response = request("GET", "/licenses/" + issuance_id)
    if response.status_code == 404:
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
