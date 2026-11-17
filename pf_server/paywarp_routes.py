"""PayWarp checkout and signed completion notifications."""
import json
import secrets
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, render_template, request, session, redirect
from sqlalchemy.exc import SQLAlchemyError

from .checkout_consent import CONSENT_VERSION, current_consent, current_selection
from .countries import COUNTRY_OPTIONS
from .extensions import csrf, db, limiter, browser_limit_key
from .models import Transaction, PaymentProgress, CryptoLicenseDelivery
from .paywarp_service import SUPPORTED_COUNTRIES, create_payment, refresh_payment, valid_signature
from .nowpayments_service import PaymentProviderError

paywarp_bp = Blueprint('paywarp', __name__)


@paywarp_bp.after_request
def private_checkout(response):
    response.headers['Cache-Control'] = 'private, no-store'
    return response


@paywarp_bp.get('/buy_paywarp')
def checkout():
    session.setdefault('paywarp_order', 'PW-' + secrets.token_urlsafe(24))
    return render_template('paywarp_checkout.html', countries=[c for c in COUNTRY_OPTIONS if c[0] in SUPPORTED_COUNTRIES])


@paywarp_bp.post('/create-paywarp-payment')
@limiter.limit('20 per hour', key_func=browser_limit_key)
def create():
    if not current_app.config.get('PAYWARP_ENABLED'):
        return jsonify(error='PayWarp is temporarily unavailable. Please use Patreon.'), 503
    from .payment_routes import validate_checkout_country
    from .contracts import offer_digest, record_agreement, checkout_snapshot
    from .licensing import normalize_recipient_email
    from .crypto_delivery import encrypt_recipient
    from .checkout_recovery import issue
    from .keygen_service import verify_lifetime_policy, KeygenUnavailable
    from .offer import PREMIUM_PRICE_TEXT
    data = request.form
    selection = current_selection() or current_consent()
    if not selection or selection.get('payment_method') != 'paywarp' or selection.get('offer_digest') != offer_digest():
        return jsonify(error='Review the payment methods and confirmations again.'), 409
    if data.get('withdrawal_accepted') != 'yes' or data.get('verification_acknowledged') != 'yes':
        return jsonify(error='Confirm immediate delivery and the verification requirements.'), 400
    if data.get('country') not in SUPPORTED_COUNTRIES:
        return jsonify(error='PayWarp supports US and EU residents only.'), 400
    country, error = validate_checkout_country(data)
    if error:
        return error
    email = normalize_recipient_email(data.get('delivery_email'))
    if not email:
        return jsonify(error='Enter a valid license delivery email.'), 400
    try:
        encrypted = encrypt_recipient(email)
        verify_lifetime_policy()
        agreement = record_agreement('paywarp', data['country'], datetime.now(timezone.utc).isoformat())
        session['checkout_consent'] = dict(selection, agreement_id=agreement, country=data['country'],
            withdrawal_accepted=True, version=CONSENT_VERSION)
        session.pop('checkout_selection', None)
        snapshot = checkout_snapshot('paywarp', data['country'])
        transaction = db.session.get(Transaction, session.get('paywarp_order', ''))
        if transaction and (transaction.customer_country != country.country_name or transaction.expected_price_amount != PREMIUM_PRICE_TEXT):
            transaction = None
            session.pop('paywarp_order', None)
        if transaction and transaction.status == 'finished':
            return redirect('/buy_success?token=' + issue(transaction.session_id), code=303)
        if transaction:
            from .crypto_delivery import cipher
            if cipher().decrypt(transaction.customer_email_encrypted.encode()).decode() != email:
                return jsonify(error='Use the original delivery email to resume this order.'), 409
        else:
            identifier = session.get('paywarp_order') or 'PW-' + secrets.token_urlsafe(24)
            session['paywarp_order'] = identifier
            timestamp = datetime.now(timezone.utc).isoformat()
            transaction = Transaction(session_id=identifier, provider_payment_id='reserved-' + identifier,
                provider_reference_type='paywarp', environment='production', expected_price_amount=PREMIUM_PRICE_TEXT,
                expected_price_currency='eur', customer_country=country.country_name, country_evidence=country.evidence_source,
                geolocation_database=country.database_label, status='pending', created_at=timestamp,
                contract_snapshot=snapshot, customer_email_encrypted=encrypted)
            db.session.add_all([transaction, PaymentProgress(session_id=identifier),
                CryptoLicenseDelivery(session_id=identifier, recipient_encrypted=encrypted, created_at=timestamp)])
            db.session.commit()
        token = issue(transaction.session_id)
        create_payment(transaction, token, email)
        # Keep the recovery page available before opening the hosted checkout.
        return redirect('/buy_success?token=' + token, code=303)
    except (PaymentProviderError, KeygenUnavailable, SQLAlchemyError, ValueError):
        db.session.rollback()
        return render_template('paywarp_checkout.html', countries=[c for c in COUNTRY_OPTIONS if c[0] in SUPPORTED_COUNTRIES],
            checkout_error='PayWarp checkout is unavailable. Retry with the same details or choose Patreon.'), 503


@paywarp_bp.post('/paywarp-webhook')
@csrf.exempt
@limiter.limit('20 per second')
def webhook():
    from .payment_routes import require_api_subdomain
    require_api_subdomain()
    secret = current_app.config.get('PAYWARP_WEBHOOK_SECRET')
    if not secret:
        return jsonify(error='Webhook unavailable'), 503
    raw = request.get_data()
    if not valid_signature(raw, request.headers, secret):
        return jsonify(error='Invalid signature or timestamp'), 400
    try:
        event = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return jsonify(error='Invalid JSON'), 400
    if not isinstance(event, dict):
        return jsonify(error='Invalid event'), 400
    if request.headers.get('X-Paywarp-Event') != event.get('event'):
        return jsonify(error='Event mismatch'), 400
    if event.get('event') != 'payment.completed':
        return jsonify(ok=True)
    reference = event.get('reference')
    if not isinstance(reference, str):
        return jsonify(error='Invalid reference'), 400
    transaction = db.session.get(Transaction, reference)
    if not transaction or transaction.provider_reference_type != 'paywarp':
        return jsonify(ok=True)
    if event.get('payment_id') != transaction.provider_payment_id:
        # A callback can race the create response; retry until the link is stored.
        return jsonify(error='Payment link mismatch'), 409
    if transaction.status == 'finished':
        return jsonify(ok=True)  # Duplicate event: fulfillment is already durable.
    try:
        refresh_payment(transaction)
        if transaction.status != 'finished':
            return jsonify(error='Payment not yet confirmed'), 503
    except Exception:
        db.session.rollback()
        current_app.logger.warning('PayWarp confirmation deferred for retry')
        return jsonify(error='Confirmation unavailable'), 503
    return jsonify(ok=True)
