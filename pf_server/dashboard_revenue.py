"""Private, read-only financial reporting for the operations dashboard."""
import fcntl
import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path

import httpx
from flask import current_app

from .extensions import db
from .models import PaymentProgress, Transaction


def data_file(name):
    return Path(current_app.config["DATA_DIR"]) / name


def read_snapshot(path, default):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default


def write_snapshot(path, data, mode=0o600):
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(data, output, separators=(",", ":"), allow_nan=False)
            os.fchmod(output.fileno(), mode)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def iso_time():
    return datetime.now(UTC).isoformat()


def reference(provider, identifier):
    return hashlib.sha256(f"{provider}:{identifier}".encode()).hexdigest()[:16]


def money(value):
    try:
        amount = Decimal(str(value))
        if amount.is_finite() and 0 <= amount <= 10**12:
            return format(amount, "f")
    except InvalidOperation:
        pass
    return None


def order_row(provider, identifier, day, currency, status, gross=None, refunds=None):
    return dict(provider=provider, reference=reference(provider, identifier), day=day,
                currency=currency, status=status, gross=money(gross),
                refunds=money(refunds), fees=None, net=None)


def parse_shop_accounting(payload):
    refunds = {str(item["id"]): item.get("attributes", {}).get("refunded_at")
               for item in payload.get("included", []) if item["type"] == "order_item"}
    for order in payload["data"]:
        attrs = order["attributes"]
        amount = attrs.get("charge_amount_cents")
        currency = attrs.get("currency_code", "")
        if type(amount) is not int or amount < 0 or not isinstance(currency, str) or not re.fullmatch("[A-Z]{3}", currency.upper()):
            continue
        day = datetime.fromisoformat(attrs["date_purchased"].replace("Z", "+00:00")).astimezone(UTC).date().isoformat()
        gross = Decimal(amount) / 100
        status = attrs["status"]
        items = order["relationships"]["order_items"]["data"]
        refunded = [bool(refunds.get(str(item["id"]))) for item in items]
        if status == "refunded" or (refunded and all(refunded)):
            yield order_row("patreon", order["id"], day, currency.upper(), "refunded", gross, gross)
        elif status == "fulfilled":
            yield order_row("patreon", order["id"], day, currency.upper(),
                            "partial refund" if any(refunded) else "confirmed", gross,
                            None if any(refunded) else 0)
        elif status in {"pending", "declined", "failed"}:
            yield order_row("patreon", order["id"], day, currency.upper(), status)


def publish_shop(rows, expected):
    write_snapshot(data_file("dashboard-patreon-sales.json"), {
        "last_success": iso_time(), "expected": expected, "items": list(rows),
    })


def read_paywarp(transaction):
    from .paywarp_service import api

    identifier = transaction.provider_payment_id
    if not re.fullmatch(r"pl_[A-Za-z0-9_-]{1,120}", identifier):
        raise ValueError("Invalid payment reference")
    result = api("GET", "/payments/" + identifier)
    if (result.get("reference") != transaction.session_id
            or identifier not in (result.get("id"), result.get("link_id"))
            or type(result.get("amount")) is not int
            or result["amount"] != Decimal(transaction.expected_price_amount) * 100
            or result.get("currency") != transaction.expected_price_currency.upper()):
        raise ValueError("Payment mismatch")
    state = result.get("status")
    if state == "completed":
        received = result.get("amount_paid")
        if type(received) is not int or received < result["amount"]:
            raise ValueError("Payment incomplete")
        return "confirmed", None, Decimal(received) / 100
    if state in {"failed", "pending", "refunded", "partially_refunded"}:
        refunded = result.get("amount_refunded")
        refund = Decimal(refunded) / 100 if type(refunded) is int and refunded >= 0 else None
        return state.replace("_", " "), refund, None
    raise ValueError("Unknown payment status")


def read_nowpayments(transaction, progress):
    identifier = progress.nowpayments_payment_id if progress else None
    if not identifier or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", identifier):
        raise ValueError("Payment reference unavailable")
    with httpx.Client(timeout=4, follow_redirects=False, trust_env=False) as client:
        response = client.get(f"{current_app.config['NOWPAYMENTS_API_URL']}/payment/{identifier}",
                              headers={"x-api-key": current_app.config["NOWPAYMENTS_API_KEY"]})
        response.raise_for_status()
    result = response.json()
    if (str(result.get("payment_id")) != identifier or result.get("order_id") != transaction.session_id
            or str(result.get("price_currency", "")).upper() != transaction.expected_price_currency.upper()
            or Decimal(str(result.get("price_amount"))) != Decimal(transaction.expected_price_amount)):
        raise ValueError("Payment mismatch")
    state = result["payment_status"]
    if state == "finished":
        return "confirmed", None, transaction.expected_price_amount
    if state in {"failed", "expired", "refunded", "partially_paid"}:
        return state.replace("_", " "), None, None
    if state in {"waiting", "confirming", "confirmed", "sending"}:
        return "pending", None, None
    raise ValueError("Unknown payment status")


def sync():
    from .patreon_shop import VerificationUnavailable, snapshot

    public_path = data_file("dashboard-revenue.json")
    with data_file("dashboard-revenue.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        shop_path = data_file("dashboard-patreon-sales.json")
        shop = read_snapshot(shop_path, {})
        if current_app.config.get("PATREON_SHOP_ENABLED") and (
                not shop_path.exists() or datetime.now(UTC).timestamp() - shop_path.stat().st_mtime > 3300):
            with data_file("patreon-shop.lock").open("a") as shop_lock:
                try:
                    fcntl.flock(shop_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    snapshot()
                    shop = read_snapshot(shop_path, shop)
                except (BlockingIOError, VerificationUnavailable):
                    pass
        previous = read_snapshot(public_path, {})
        now = datetime.now(UTC)
        shop_time = shop.get("last_success")
        sources = {"patreon": {
            "last_success": shop_time,
            "status": "unavailable" if not shop_time else "stale" if now - datetime.fromisoformat(shop_time) > timedelta(hours=2) else "current",
            "coverage": f"Shop orders with visible charge data ({len(shop.get('items', []))}/{shop.get('expected', 0)}). Net and payouts require a creator report.",
        }}
        items = list(shop.get("items", []))
        saved = {row["reference"]: row for row in previous.get("items", []) if row["provider"] != "patreon"}
        configured_readers = {"paywarp": read_paywarp, "nowpayments": read_nowpayments}
        recorded_providers = {row[0] for row in db.session.query(Transaction.provider)
                              .filter_by(environment="production").distinct()}
        for provider in sorted(configured_readers.keys() | recorded_providers):
            reader = configured_readers.get(provider)
            transactions = Transaction.query.filter_by(provider=provider, environment="production").order_by(Transaction.created_at.desc()).all()
            attempted = successes = 0
            source = previous.get("sources", {}).get(provider, {})
            key = "PAYWARP_API_KEY" if provider == "paywarp" else "NOWPAYMENTS_API_KEY"
            for transaction in transactions:
                if transaction.provider_payment_id.startswith("mock-"):
                    continue
                currency = transaction.expected_price_currency.upper()
                if not re.fullmatch("[A-Z]{3}", currency):
                    continue
                stamp = datetime.fromisoformat(transaction.finished_at or transaction.created_at)
                day = (stamp if stamp.tzinfo is None else stamp.astimezone(UTC)).date().isoformat()
                status = "confirmed" if transaction.status == "finished" else "pending"
                row = order_row(provider, transaction.provider_payment_id, day, currency, status,
                                transaction.expected_price_amount if status == "confirmed" else None)
                old = saved.get(row["reference"])
                if old and old.get("checked_at") and not (row["status"] == "confirmed" and old["status"] in {"pending", "failed"}):
                    row = old
                due = not row.get("checked_at") or (
                    now - datetime.fromisoformat(row["checked_at"]) > timedelta(hours=12))
                if reader and attempted < 12 and current_app.config.get(key) and due and day >= (now.date() - timedelta(days=90)).isoformat():
                    progress = db.session.get(PaymentProgress, transaction.session_id) if provider == "nowpayments" else None
                    if provider == "paywarp" or (progress and progress.nowpayments_payment_id):
                        attempted += 1
                        try:
                            state, refunds, gross = reader(transaction, progress) if provider == "nowpayments" else reader(transaction)
                            recorded_gross = gross if gross is not None else (row["gross"] if state in {"confirmed", "refunded"} else None)
                            row = dict(row, status=state, gross=money(recorded_gross),
                                       refunds=money(refunds), checked_at=iso_time())
                            successes += 1
                        except (RuntimeError, httpx.HTTPError, ValueError, KeyError, TypeError, ArithmeticError):
                            pass
                items.append(row)
            sources[provider] = dict(
                last_success=iso_time() if successes else source.get("last_success"),
                status=("partial" if attempted > successes else "current" if successes
                        else "local records" if transactions else "no storefront records"),
                coverage=(f"Production storefront references and verified payment events. API checks this run: {successes}/{attempted}."
                          if reader else "Verified production storefront records."),

            )
        write_snapshot(public_path, {"sources": sources, "items": sorted(items, key=lambda row: row["day"], reverse=True)}, 0o640)


if __name__ == "__main__":
    from main import app
    with app.app_context():
        sync()
