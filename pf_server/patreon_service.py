"""Patreon eligibility, signature, and idempotent license-delivery services."""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from flask import current_app
from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from .extensions import db
from .licensing import (
    build_license_file,
    make_license_key,
    normalize_recipient_email,
    send_license_email,
)
from .models import License, PatreonLicenseDelivery
from .time_utils import rfc3339_utc
from .webhook_models import PatreonMember, PatreonWebhook


def calculate_patreon_signature(secret: str, request_body: bytes) -> str:
    """Implement Patreon's protocol-mandated HMAC-MD5 signature exactly."""

    def digest_factory(data=b""):
        return hashlib.md5(data, usedforsecurity=False)

    return hmac.new(secret.encode("utf-8"), request_body, digest_factory).hexdigest()


def extract_patreon_email(payload: PatreonWebhook) -> str | None:
    direct_email = normalize_recipient_email(payload.data.attributes.email)
    if direct_email:
        return direct_email

    user_relationship = payload.data.relationships.get("user", {})
    related_user = (
        user_relationship.get("data", {}) if isinstance(user_relationship, dict) else {}
    )
    related_user_id = related_user.get("id") if isinstance(related_user, dict) else None
    for resource in payload.included:
        if resource.get("type") != "user":
            continue
        if related_user_id and resource.get("id") != related_user_id:
            continue
        attributes = resource.get("attributes", {})
        if isinstance(attributes, dict):
            included_email = normalize_recipient_email(attributes.get("email"))
            if included_email:
                return included_email
    return None


def patreon_member_has_license_tier(member: PatreonMember) -> bool:
    allowed_tier_ids = current_app.config.get("PATREON_LICENSE_TIER_IDS") or frozenset()
    if not allowed_tier_ids:
        return True
    tiers_relationship = member.relationships.get("currently_entitled_tiers", {})
    tier_data = (
        tiers_relationship.get("data", [])
        if isinstance(tiers_relationship, dict)
        else []
    )
    if not isinstance(tier_data, list):
        return False
    entitled_ids = {
        str(resource.get("id"))
        for resource in tier_data[:100]
        if isinstance(resource, dict)
        and resource.get("type") == "tier"
        and resource.get("id")
    }
    return bool(entitled_ids & allowed_tier_ids)


def patreon_member_is_paid_and_entitled(member: PatreonMember) -> bool:
    attributes = member.attributes
    return (
        attributes.patron_status == "active_patron"
        and (attributes.last_charge_status or "").casefold() == "paid"
        and (attributes.currently_entitled_amount_cents or 0) > 0
        and not attributes.is_free_trial
        and not attributes.is_gifted
        and patreon_member_has_license_tier(member)
    )


def ensure_patreon_delivery(member_id: str) -> PatreonLicenseDelivery:
    delivery = db.session.get(PatreonLicenseDelivery, member_id)
    if delivery is not None:
        return delivery

    timestamp = datetime.now(timezone.utc).isoformat()
    delivery = PatreonLicenseDelivery(
        member_id=member_id,
        status="pending",
        created_at=timestamp,
        updated_at=timestamp,
    )
    db.session.add(delivery)
    try:
        db.session.commit()
        return delivery
    except IntegrityError:
        db.session.rollback()
        concurrent_delivery = db.session.get(PatreonLicenseDelivery, member_id)
        if concurrent_delivery is None:
            raise
        return concurrent_delivery


def claim_patreon_delivery(member_id: str) -> str:
    now = datetime.now(timezone.utc)
    now_text = now.isoformat()
    lease_expires_at = (now + timedelta(minutes=10)).isoformat()
    statement = (
        db.update(PatreonLicenseDelivery)
        .where(
            PatreonLicenseDelivery.member_id == member_id,
            or_(
                PatreonLicenseDelivery.status.in_(("pending", "failed")),
                and_(
                    PatreonLicenseDelivery.status == "sending",
                    PatreonLicenseDelivery.lease_expires_at < now_text,
                ),
            ),
        )
        .values(
            status="sending", updated_at=now_text, lease_expires_at=lease_expires_at
        )
    )
    result = db.session.execute(statement)
    db.session.commit()
    if result.rowcount == 1:
        return "claimed"
    delivery = db.session.get(PatreonLicenseDelivery, member_id)
    return "sent" if delivery and delivery.status == "sent" else "busy"


def mark_patreon_delivery_failed(member_id: str) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    db.session.execute(
        db.update(PatreonLicenseDelivery)
        .where(PatreonLicenseDelivery.member_id == member_id)
        .values(status="failed", updated_at=timestamp, lease_expires_at=None)
    )
    db.session.commit()


def deliver_patreon_license(member_id: str, recipient: str) -> str:
    """Create at most one license per Patreon member and send it with retry support."""
    ensure_patreon_delivery(member_id)
    claim_status = claim_patreon_delivery(member_id)
    if claim_status != "claimed":
        return claim_status

    try:
        delivery = db.session.get(PatreonLicenseDelivery, member_id)
        if delivery is None:
            raise RuntimeError("Patreon delivery record disappeared")

        license_record = (
            db.session.get(License, delivery.license_key)
            if delivery.license_key
            else None
        )
        if license_record is None:
            created_at = rfc3339_utc(datetime.now(timezone.utc).replace(microsecond=0))
            issuance_reference = "PT-" + secrets.token_urlsafe(16)
            license_record = License(
                license_key=make_license_key(),
                state="valid",
                issuance_reference=issuance_reference,
                created_at=created_at,
            )
            db.session.add(license_record)
            delivery.license_key = license_record.license_key
            delivery.updated_at = datetime.now(timezone.utc).isoformat()
            db.session.commit()

        license_file = build_license_file(
            license_record.license_key,
            license_record.issuance_reference,
            license_record.created_at,
        )
        send_license_email(recipient, license_file)
    except Exception:
        db.session.rollback()
        try:
            mark_patreon_delivery_failed(member_id)
        except SQLAlchemyError:
            db.session.rollback()
        raise

    sent_at = datetime.now(timezone.utc).isoformat()
    db.session.execute(
        db.update(PatreonLicenseDelivery)
        .where(PatreonLicenseDelivery.member_id == member_id)
        .values(
            status="sent",
            updated_at=sent_at,
            sent_at=sent_at,
            lease_expires_at=None,
        )
    )
    db.session.commit()
    return "sent"
