"""Accountless checkout recovery with random, expiring bearer tokens.

No token plaintext is stored server-side. A signed browser session can remember
its own tokens; access always rechecks the database hash and deadline. Existing
orders without a recovery row retain their original links for compatibility.
"""

import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from flask import abort, current_app, request, session

from .extensions import db
from .models import CheckoutRecovery, Transaction

PENDING_LIFETIME = timedelta(days=7)
READY_LIFETIME = timedelta(hours=6)
INVALID_LINK = "This recovery link is invalid or has expired. If you paid, contact support with your payment transaction hash or invoice reference. Do not pay again."


def now():
    return datetime.now(timezone.utc)


def _timestamp(value):
    parsed = datetime.fromisoformat(value)
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def deadline(row, transaction):
    pending_until = _timestamp(row.created_at) + PENDING_LIFETIME
    if transaction and transaction.status == "finished":
        if not transaction.finished_at:
            return _timestamp(row.created_at)
        finished = _timestamp(transaction.finished_at)
        # A payment completed after the pending window cannot revive a dead link.
        return finished + READY_LIFETIME if finished < pending_until else pending_until
    return pending_until


def _digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def issue(session_id):
    cached = dict(session.get("checkout_recovery", {}))
    row = db.session.get(CheckoutRecovery, session_id)
    if row:
        token = cached.get(session_id, "")
        if (row.token_digest and hmac.compare_digest(_digest(token), row.token_digest)
            and now() < deadline(row, db.session.get(Transaction, session_id))):
            return token
        abort(409, description="Use the recovery link you already saved for this order.")
    token = secrets.token_urlsafe(16)  # 128 bits of entropy, 22 URL-safe characters.
    db.session.add(CheckoutRecovery(session_id=session_id,
        token_digest=_digest(token), created_at=now().isoformat()))
    db.session.commit()
    cached[session_id] = token
    session["checkout_recovery"] = dict(list(cached.items())[-8:])
    return token


def resolve_session_id(session_id=None):
    """Protect status, download and launch routes, including raw-ID attempts."""
    token = request.values.get("token")
    if token is not None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{22}", token):
            abort(410, description=INVALID_LINK)
        row = CheckoutRecovery.query.filter_by(token_digest=_digest(token)).first()
        transaction = db.session.get(Transaction, row.session_id) if row else None
        if not row or not transaction or now() >= deadline(row, transaction):
            abort(410, description=INVALID_LINK)
        return row.session_id
    session_id = session_id if session_id is not None else request.values.get("session_id", "")
    row = db.session.get(CheckoutRecovery, session_id) if session_id else None
    if row:
        token = session.get("checkout_recovery", {}).get(session_id, "")
        transaction = db.session.get(Transaction, session_id)
        if (not row.token_digest or not token
            or not hmac.compare_digest(_digest(token), row.token_digest)
            or now() >= deadline(row, transaction)):
            abort(410, description=INVALID_LINK)
    return session_id


def view_context(session_id):
    row = db.session.get(CheckoutRecovery, session_id) if session_id else None
    token = request.values.get("token") or session.get("checkout_recovery", {}).get(session_id)
    query = urlencode({"token": token}) if row and token else urlencode({"session_id": session_id or ""})
    return dict(access_query=query, recovery_token=token if row else None,
        recovery_url=current_app.config["APP_DOMAIN"] + "/buy_success?" + query,
        recovery_expires_at=deadline(row, db.session.get(Transaction, session_id)).isoformat() if row else None)


def expire_tokens():
    """Discard expired hashes but keep tombstones, so old IDs cannot regain access."""
    # Ignore rows too new to have expired under either deadline.
    rows = db.session.execute(db.select(CheckoutRecovery, Transaction).outerjoin(
        Transaction, Transaction.session_id == CheckoutRecovery.session_id
    ).where(CheckoutRecovery.token_digest.is_not(None),
        CheckoutRecovery.created_at <= (now() - READY_LIFETIME).isoformat())).all()
    count = 0
    for row, transaction in rows:
        if now() >= deadline(row, transaction):
            row.token_digest = None
            count += 1
    db.session.commit()
    return count
