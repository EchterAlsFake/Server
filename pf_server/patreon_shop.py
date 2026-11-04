"""Email-only Shop activation; unofficial sales access is isolated to the worker."""
import fcntl
import hashlib
import hmac
import http.cookiejar
import os
import stat
import time
from datetime import datetime
from pathlib import Path

from flask import current_app
from sqlalchemy.exc import IntegrityError

from .extensions import db
from .crypto_delivery import cipher
from .licensing import normalize_recipient_email, get_or_create_license, build_license_file, send_license_email
from .models import PatreonShopCustomer as Customer, PatreonShopPurchase as Purchase, PatreonShopHealth as Health, License

API_URL = 'https://www.patreon.com/api/sales'
PARAMS = {
    'include': 'order,order_items.null,order_items.product_variant',
    'fields[order]': 'buyer_email,public_order_id,status,date_purchased,charge_amount_cents,currency_code',
    'fields[order_item]': 'refunded_at',
    'fields[product-variant]': 'name,content_type,is_deleted',
    'filter[timezone]': 'Europe/Berlin', 'sort': '',
    'json-api-use-default-includes': 'false', 'json-api-version': '1.0',
}


class VerificationUnavailable(Exception):
    def __init__(self, reason, delay=300):
        self.reason, self.delay = reason, delay


def digest_email(email):
    key = current_app.config.get('PATREON_SHOP_LOOKUP_KEY', '')
    if len(key) < 32:
        raise ValueError('Shop lookup key must have at least 32 characters')
    return hmac.new(key.encode(), email.encode(), hashlib.sha256).hexdigest()


def enqueue(email):
    """One outstanding job per email; cooldown also applies to negative results."""
    digest = digest_email(email)
    now = time.time()
    row = db.session.get(Customer, digest)
    if row is None:
        db.session.add(Customer(email_digest=digest, recipient_encrypted=cipher().encrypt(email.encode()).decode(), requested_at=now, pending=True))
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()  # Another request already queued the same mailbox.
        return
    db.session.execute(db.update(Customer).where(
        Customer.email_digest == digest, Customer.pending.is_(False),
        Customer.requested_at <= now - 900,
    ).values(pending=True, requested_at=now, next_attempt_at=0))
    db.session.commit()


def _timestamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Purchase timestamp must include timezone')
    return parsed.timestamp()


def parse_page(payload, variant_id):
    """Validate the whole page before allowing a negative purchase decision."""
    try:
        orders = payload['data']
        included = payload.get('included', [])
        if not isinstance(orders, list) or not isinstance(included, list):
            raise ValueError()
        index = {(x['type'], str(x['id'])): x for x in included}
        result = []
        for order in orders:
            if order['type'] != 'order':
                raise ValueError()
            attrs = order['attributes']
            order_id = str(order['id'])
            email = normalize_recipient_email(attrs['buyer_email'])
            if not email or not order_id or len(order_id) > 128:
                raise ValueError()
            purchased = _timestamp(attrs['date_purchased'])
            items = order['relationships']['order_items']['data']
            if not isinstance(items, list) or not items:
                raise ValueError()
            matching = False
            refunded = True
            for ref in items:
                if ref['type'] != 'order_item':
                    raise ValueError()
                item = index[('order_item', str(ref['id']))]
                variant = item['relationships']['product_variant']['data']
                if variant['type'] != 'product-variant':
                    raise ValueError()
                if str(variant['id']) == variant_id:
                    matching = True
                    refund = item['attributes']['refunded_at']
                    if refund is not None:
                        _timestamp(refund)
                    else:
                        refunded = False
            status = attrs['status']
            if not isinstance(status, str) or not status:
                raise ValueError()
            result.append((order_id, email, purchased, status == 'fulfilled' and matching and not refunded))
        return result
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        raise VerificationUnavailable('schema') from None


def fetch_sales():
    """Bounded complete snapshot. Never follow upstream-controlled URLs."""
    from curl_cffi import requests
    try:
        path = Path(current_app.config['PATREON_SHOP_COOKIE_FILE'])
        # Reject symlinks, group/world access, non-files, and other owners.
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'r') as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError()
            jar = http.cookiejar.MozillaCookieJar()
            jar._really_load(source, str(path), True, False)
        for cookie in list(jar):
            if cookie.domain.lstrip('.').lower() not in {'patreon.com', 'www.patreon.com'}:
                jar.clear(cookie.domain, cookie.path, cookie.name)
        if not list(jar):
            raise ValueError()
    except (OSError, ValueError, http.cookiejar.LoadError):
        raise VerificationUnavailable('cookies', 900) from None
    rows, seen = [], set()
    expected_total = None
    deadline = time.monotonic() + 120
    with requests.Session(cookies=jar, impersonate='chrome', trust_env=False,
                          headers={'Accept': 'application/json', 'Referer': 'https://www.patreon.com/sales'}) as session:
        for page in range(100):
            if time.monotonic() >= deadline:
                raise VerificationUnavailable('scan_limit')
            try:
                response = session.get(API_URL, params={**PARAMS, 'page[offset]': str(page * 50), 'page[count]': '50'}, timeout=20, allow_redirects=False)
            except Exception:
                raise VerificationUnavailable('network') from None
            if response.status_code == 429:
                try:
                    delay = max(300, int(response.headers.get('Retry-After', '300')))
                except ValueError:
                    from email.utils import parsedate_to_datetime
                    try:
                        delay = max(300, parsedate_to_datetime(response.headers['Retry-After']).timestamp() - time.time())
                    except (ValueError, TypeError, KeyError):
                        delay = 900
                raise VerificationUnavailable('rate_limit', delay)
            if response.status_code != 200:
                raise VerificationUnavailable('upstream', 900)
            try:
                payload = response.json()
                batch = parse_page(payload, current_app.config['PATREON_SHOP_PRODUCT_VARIANT_ID'])
                total = payload['meta']['pagination']['total']
                if isinstance(total, bool) or not isinstance(total, int) or total < 0:
                    raise ValueError()
            except VerificationUnavailable:
                raise
            except (ValueError, KeyError, TypeError):
                raise VerificationUnavailable('pagination') from None
            if expected_total is not None and total != expected_total:
                raise VerificationUnavailable('changing_snapshot')
            expected_total = total
            ids = [row[0] for row in batch]
            if len(ids) != len(set(ids)) or seen.intersection(ids) or len(batch) > 50:
                raise VerificationUnavailable('pagination')
            seen.update(ids)
            rows.extend(batch)
            if len(rows) == total:
                return rows
            if len(batch) != 50 or len(rows) > total:
                raise VerificationUnavailable('pagination')
    raise VerificationUnavailable('scan_limit')


def snapshot():
    health = db.session.get(Health, 1)
    if health is None:
        health = Health(id=1, retry_at=0)
        db.session.add(health)
        db.session.commit()
    if health.retry_at > time.time():
        return None
    try:
        sales = fetch_sales()
    except VerificationUnavailable as error:
        health.retry_at = time.time() + error.delay
        health.reason = error.reason
        current_app.logger.warning('Patreon Shop verification unavailable (%s)', error.reason)
        db.session.commit()
        return None
    health.last_success_at = time.time()
    health.retry_at, health.reason = 0, None
    db.session.commit()
    return sales


def choose_license(customer, sales):
    """Persist the selected identity before contacting Keygen or SMTP."""
    if customer.delivery_key:
        return customer.delivery_key
    purchases = []
    if sales is not None:
        email = cipher().decrypt(customer.recipient_encrypted.encode()).decode()
        for order_id, buyer, purchased, eligible in sales:
            if buyer != email:
                continue
            row = db.session.get(Purchase, order_id)
            if row is None:
                row = Purchase(order_id=order_id, email_digest=customer.email_digest, purchased_at=purchased, eligible=eligible)
                db.session.add(row)
            if row.email_digest != customer.email_digest:
                raise RuntimeError('Purchase identity changed')
            row.eligible = eligible
            purchases.append(row)
        purchases.sort(key=lambda row: (row.purchased_at, row.order_id), reverse=True)
        if customer.fallback_key:
            prior = next((p for p in purchases if p.eligible and not p.license_key and p.purchased_at <= customer.fallback_created_at), None)
            if prior:
                prior.license_key = customer.fallback_key
                customer.fallback_key = None
        selected = next((p for p in purchases if p.eligible and not p.license_key), None)
        if selected:
            record = get_or_create_license('patreon-shop:' + selected.order_id)
            selected.license_key = record.license_key
            key, reason = record.license_key, 'verified'
        else:
            issued = next((p for p in purchases if p.eligible and p.license_key), None)
            known_recovery = Purchase.query.filter_by(email_digest=customer.email_digest, eligible=True).filter(Purchase.license_key.is_not(None)).order_by(Purchase.purchased_at.desc()).first()
            key = issued.license_key if issued else (known_recovery.license_key if known_recovery else customer.fallback_key)
            reason = 'recovery' if key else 'ineligible'
    else:
        # Previously observed ineligible orders do not gain a new fallback.
        known = Purchase.query.filter_by(email_digest=customer.email_digest).all()
        eligible = sorted((p for p in known if p.eligible and p.license_key), key=lambda p: p.purchased_at, reverse=True)
        key = eligible[0].license_key if eligible else customer.fallback_key
        reason = 'recovery'
        if not key and not known:
            record = get_or_create_license('patreon-shop-fallback:' + customer.email_digest)
            key, reason = record.license_key, 'fallback'
            customer.fallback_key, customer.fallback_created_at = key, time.time()
    customer.reason, customer.delivery_key = reason, key
    db.session.commit()
    return key


def reconcile_fallbacks(sales):
    """Bind grants after recovery without issuing or sending unsolicited licenses."""
    if sales is None:
        return
    for customer in Customer.query.filter(Customer.fallback_key.is_not(None)).yield_per(100):
        email = cipher().decrypt(customer.recipient_encrypted.encode()).decode()
        matches = sorted((sale for sale in sales if sale[1] == email and sale[3] and sale[2] <= customer.fallback_created_at), key=lambda sale: (sale[2], sale[0]), reverse=True)
        for order_id, _, purchased, _ in matches:
            row = db.session.get(Purchase, order_id)
            if row is not None and (row.license_key or row.email_digest != customer.email_digest):
                continue
            if row is None:
                row = Purchase(order_id=order_id, email_digest=customer.email_digest, purchased_at=purchased, eligible=True)
                db.session.add(row)
            row.license_key = customer.fallback_key
            customer.fallback_key = None
            break
    db.session.commit()


def process_claims():
    """Single local worker matches the deployment's SQLite and shared DATA_DIR."""
    if not current_app.config.get('PATREON_SHOP_ENABLED'):
        return 0
    lock_path = Path(current_app.config['DATA_DIR']) / 'patreon-shop.lock'
    with open(lock_path, 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        db.session.execute(db.update(Customer).where(Customer.pending.is_(False), Customer.completed_at < time.time() - 30 * 86400).values(reason=None, completed_at=None))
        db.session.commit()
        rows = Customer.query.filter(Customer.pending.is_(True), Customer.next_attempt_at <= time.time()).order_by(Customer.requested_at).limit(100).all()
        unbound = Customer.query.filter(Customer.fallback_key.is_not(None)).first() is not None
        if not rows and not unbound:
            return 0
        sales = snapshot() if unbound or any(not row.delivery_key for row in rows) else None
        reconcile_fallbacks(sales)
        for row in rows:
            try:
                key = choose_license(row, sales)
                if key:
                    record = db.session.get(License, key)
                    content = build_license_file(key, record.issuance_reference, record.created_at)
                    recipient = cipher().decrypt(row.recipient_encrypted.encode()).decode()
                    send_license_email(recipient, content)
                    row.last_key = key
                row.pending, row.delivery_key = False, None
                row.completed_at = time.time()
                db.session.commit()
            except Exception:
                db.session.rollback()
                row.next_attempt_at = time.time() + 60
                db.session.commit()
                current_app.logger.warning('Patreon Shop fulfillment deferred')
        health = db.session.get(Health, 1)
        oldest = Customer.query.filter_by(pending=True).order_by(Customer.requested_at).first()
        current_app.logger.info('Patreon Shop batch: processed=%d fallback=%d pending=%d oldest_seconds=%d verification_healthy=%s', len(rows), sum(r.reason == 'fallback' for r in rows), Customer.query.filter_by(pending=True).count(), int(time.time() - oldest.requested_at) if oldest else 0, bool(health and not health.reason))
        return len(rows)
