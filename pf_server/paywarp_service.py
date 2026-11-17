"""PayWarp hosted payments. Only authenticated API observations settle an order."""
import hashlib
import hmac
import re
import time
from datetime import datetime, timezone
from decimal import Decimal
from urllib.parse import urlsplit

import httpx
from flask import current_app

from .extensions import db
from .models import Transaction, PaymentProgress
from .nowpayments_service import PaymentProviderError, CompletionState, _claim_payment

SUPPORTED_COUNTRIES = frozenset('US AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE'.split())
BASE = 'https://paywarp.app/api/v1'


def checkout_url(value):
    try:
        p = urlsplit(value)
        if (isinstance(value, str) and len(value) <= 4096 and p.scheme == 'https'
            and p.hostname == 'paywarp.app' and p.port in {None, 443}
            and not p.username and not p.password and p.path.startswith('/pay/')):
            return value
    except (ValueError, TypeError, AttributeError):
        pass
    return None


def api(method, path, **kwargs):
    headers = {
        'Authorization': 'Bearer ' + current_app.config['PAYWARP_API_KEY'],
        'Content-Type': 'application/json',
        # Site-bound keys require the registered origin on every API call.
        # Never derive this from the visitor's Host or Origin headers.
        'X-Paywarp-Site-Url': current_app.config.get('PAYWARP_SITE_URL') or current_app.config['APP_DOMAIN'],
    }
    headers.update(kwargs.pop('headers', {}))
    try:
        with httpx.Client(timeout=10, follow_redirects=False, trust_env=False) as client:
            response = client.request(method, BASE + path, headers=headers, **kwargs)
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict) or body.get('ok') is not True or not isinstance(body.get('data'), dict):
            raise ValueError('Invalid response')
        return body['data']
    except (httpx.HTTPError, ValueError, TypeError) as error:
        # Provider bodies and request headers can contain personal data and secrets.
        raise PaymentProviderError('PayWarp is temporarily unavailable. Retry or use Patreon.') from error


def create_payment(transaction, token, email):
    payload = dict(amount_minor=int(Decimal(transaction.expected_price_amount) * 100),
        currency=transaction.expected_price_currency.upper(), reference=transaction.session_id,
        return_url=current_app.config['APP_DOMAIN'] + '/buy_success?token=' + token,
        customer_email=email, fee_mode='inherit')
    if current_app.config.get('PAYWARP_SITE_ID'):
        payload['site_id'] = current_app.config['PAYWARP_SITE_ID']
    data = api('POST', '/payments', json=payload, headers={'Idempotency-Key': transaction.session_id})
    identifier = data.get('id')
    url = checkout_url(data.get('checkout_url'))
    if (not isinstance(identifier, str) or not re.fullmatch(r'pl_[A-Za-z0-9_-]{1,120}', identifier)
        or not url or type(data.get('amount')) is not int or data['amount'] != payload['amount_minor']
        or data.get('currency') != payload['currency'] or data.get('reference') != transaction.session_id):
        raise PaymentProviderError('PayWarp returned an invalid checkout.')
    transaction.provider_payment_id = identifier
    db.session.get(PaymentProgress, transaction.session_id).checkout_url = url
    db.session.commit()
    return url


def valid_signature(raw, headers, secret, now=None):
    stamp = headers.get('X-Paywarp-Timestamp', '')
    event = headers.get('X-Paywarp-Event-Id', '')
    sig = headers.get('X-Paywarp-Signature', '')
    if (not secret or not re.fullmatch(r'[0-9]{1,12}', stamp) or not event or len(event) > 191
        or not re.fullmatch(r'[0-9a-fA-F]{64}', sig)):
        return False
    if abs((time.time() if now is None else now) - int(stamp)) > 300:
        return False
    signed = stamp.encode() + b'.' + event.encode() + b'.' + raw
    return hmac.compare_digest(hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest(), sig.lower())


def refresh_payment(transaction):
    """Match link, reference, order total, and currency before an idempotent claim."""
    if transaction.provider_reference_type != 'paywarp' or transaction.status == 'finished':
        return
    identifier = transaction.provider_payment_id
    if not re.fullmatch(r'pl_[A-Za-z0-9_-]{1,120}', identifier):
        return
    data = api('GET', '/payments/' + identifier)
    if (data.get('reference') != transaction.session_id
        or identifier not in (data.get('id'), data.get('link_id'))
        or type(data.get('amount')) is not int
        or data['amount'] != int(Decimal(transaction.expected_price_amount) * 100)
        or data.get('currency') != transaction.expected_price_currency.upper()):
        raise PaymentProviderError('PayWarp payment does not match this order.')
    record = db.session.get(PaymentProgress, transaction.session_id)
    if data.get('status') != 'completed':
        if data.get('status') not in {'pending', 'failed'}:
            raise PaymentProviderError('Invalid PayWarp status.')
        record.nowpayments_state = 'failed' if data['status'] == 'failed' else 'waiting'
        record.checked_at = datetime.now(timezone.utc).isoformat()
        db.session.commit()
        return
    if type(data.get('amount_paid')) is not int or data['amount_paid'] < data['amount']:
        raise PaymentProviderError('PayWarp payment is incomplete.')
    state = _claim_payment(transaction.session_id)
    if state == CompletionState.ALREADY_FINISHED:
        return
    if state != CompletionState.COMPLETED:
        raise PaymentProviderError('Payment fulfillment is in progress. Retry shortly.')
    try:
        from .licensing import fulfill_transaction_license
        from .invoice_service import build_invoice, save_invoice, load_invoice
        fulfill_transaction_license(transaction)
        if load_invoice(transaction.session_id) is None:
            invoice = build_invoice(fiat_amount=float(transaction.expected_price_amount), crypto_amount=0,
                pay_currency='EUR', transaction_hash=data.get('id', identifier))
            invoice.pop('Crypto Paid', None)
            invoice.pop('Exchange Rate', None)
            invoice['Payment Method'] = 'PayWarp / Stripe (Link)'
            invoice['Amount Paid'] = f"{Decimal(data['amount_paid']) / 100:.2f} {data['currency']}"
            save_invoice(transaction.session_id, invoice)
        transaction.status = 'finished'
        transaction.processing_started_at = None
        transaction.finished_at = datetime.now(timezone.utc).isoformat()
        record.nowpayments_state = 'finished'
        db.session.commit()
    except Exception:
        db.session.rollback()
        db.session.execute(db.update(Transaction).where(Transaction.session_id == transaction.session_id,
            Transaction.status == 'processing').values(status='pending', processing_started_at=None))
        db.session.commit()
        raise
