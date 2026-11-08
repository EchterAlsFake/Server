"""Local Tor exit checks before the checkout address is discarded."""

import ipaddress
import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import jsonify, render_template, request

MAX_AGE = 24 * 3600
TOR_PATHS = frozenset({
    "/porn_fetch", "/buy_license", "/buy_card", "/donation", "/checkout/start",
    "/checkout/crypto-confirm", "/create-crypto-payment", "/create-onramp-payment",
    "/payment-preview/card", "/payment-preview/banxa", "/buy_success",
})
CRYPTO_PATHS = TOR_PATHS - {"/porn_fetch", "/checkout/start", "/buy_success"}
SOURCE = "https://onionoo.torproject.org/details"


class TorExitResolver:
    def __init__(self, path):
        self.path = Path(path)
        self._stamp = None
        self._addresses = set()
        self._published = 0

    def lookup(self, raw_address):
        try:
            address = ipaddress.ip_address(raw_address.strip())
            if address.version == 6 and address.ipv4_mapped:
                address = address.ipv4_mapped
            # Private/loopback addresses cannot establish the visitor's route.
            if not address.is_global:
                return "unavailable"
            stamp = self.path.stat().st_mtime_ns
            if stamp != self._stamp:
                data = json.loads(self.path.read_text())
                addresses = {ipaddress.ip_address(item) for item in data["addresses"]}
                published = float(data["published_at"])
                if not addresses:
                    return "unavailable"
                self._addresses, self._published, self._stamp = addresses, published, stamp
            if not 0 <= time.time() - self._published < MAX_AGE:
                return "unavailable"
            return "tor" if address in self._addresses else "clear"
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            return "unavailable"


def update_exit_list(path):
    """Scheduled download; never send a visitor address to the Tor Project."""
    import httpx
    response = httpx.get(SOURCE, params={"type": "relay", "flag": "Exit",
        "fields": "or_addresses,exit_addresses"}, timeout=45, follow_redirects=False)
    response.raise_for_status()
    payload = response.json()
    if payload.get('relays_truncated', 0) or payload.get('relays_skipped', 0):
        raise ValueError('Tor exit data is incomplete')
    published = datetime.strptime(payload["relays_published"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    if not 0 <= time.time() - published < MAX_AGE:
        raise ValueError("Tor exit data is stale")
    addresses = set()
    for relay in payload["relays"]:
        for value in relay.get("exit_addresses", []):
            addresses.add(str(ipaddress.ip_address(value)))
        # Include advertised IPv6 addresses as well as observed exit addresses.
        # This deliberately also blocks relay addresses not used for this exit.
        for value in relay.get("or_addresses", []):
            host = value.rsplit(":", 1)[0].strip("[]")
            addresses.add(str(ipaddress.ip_address(host)))
    if len(addresses) < 100:
        raise ValueError("Tor exit data is incomplete")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".tor-exits-")
    try:
        with os.fdopen(descriptor, "w") as target:
            json.dump({"published_at": published, "addresses": sorted(addresses)}, target)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return len(addresses)


def checkout_network_status():
    from .onion import is_onion
    return "tor" if is_onion() else request.environ.get("PF_TOR_STATUS", "unavailable")


def block_crypto_checkout():
    status = checkout_network_status()
    if status == "clear":
        return None
    message = ("Cryptocurrency payments are unavailable over Tor. Use a direct connection to purchase."
        if status == "tor" else "Payment network verification is temporarily unavailable. Please try again later.")
    code = 403 if status == "tor" else 503
    if request.is_json or request.path.startswith("/create-") or request.method == "POST":
        return jsonify(error=message), code
    return render_template("crypto_unavailable.html", message=message), code


def guard_crypto_request():
    if request.path in CRYPTO_PATHS:
        return block_crypto_checkout()


def init_tor_checkout(app):
    app.extensions["tor_resolver"] = TorExitResolver(app.config["TOR_EXIT_LIST_PATH"])
    app.before_request(guard_crypto_request)
    app.context_processor(lambda: {"checkout_network_status": checkout_network_status()})
