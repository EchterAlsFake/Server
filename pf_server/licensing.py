"""License creation, recipient validation, and SMTP delivery services."""

import json
import os
import re
import uuid
import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid

from flask import current_app
from sqlalchemy.exc import IntegrityError

from .extensions import db
from .models import License
from .keygen_service import ensure_license
from .time_utils import rfc3339_utc


def make_license_key(prefix: str = "PF") -> str:
    """Local opaque identity, never a customer credential or signing key."""
    return str(uuid.uuid4())


def build_license_file(license_key: str, issuance_reference: str, created_at: str) -> bytes:
    """Package Keygen's signed key; provider identifiers never leave this service."""
    record = db.session.get(License, license_key)
    if record is None:
        raise ValueError("Missing issuance record")
    if not record.keygen_id:
        record.keygen_id = str(uuid.uuid5(uuid.NAMESPACE_URL,
            "https://licenses.echteralsfake.me/issuance/" + record.license_key))
        db.session.commit()
    if not record.signed_key:
        remote = ensure_license(record.keygen_id)
        record.signed_key = remote["attributes"]["key"]
        db.session.commit()
    payload = {"schema": 2, "product": "porn-fetch", "license_key": record.signed_key}
    return (json.dumps(payload, indent=2) + "\n").encode("utf-8")


def get_or_create_license(issuance_reference: str) -> License:
    license_record = License.query.filter_by(
        issuance_reference=issuance_reference
    ).first()
    if license_record is None:
        license_record = License(
            license_key=make_license_key(),
            state="valid",
            issuance_reference=issuance_reference,
            created_at=rfc3339_utc(datetime.now(timezone.utc).replace(microsecond=0)),
        )
        db.session.add(license_record)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            license_record = License.query.filter_by(issuance_reference=issuance_reference).one()
    return license_record


def normalize_recipient_email(value: str | None) -> str | None:
    """Validate a conservative SMTP mailbox without retaining it locally."""
    candidate = str(value or "").strip()
    if not candidate or len(candidate) > 254 or "\r" in candidate or "\n" in candidate:
        return None

    local_part, separator, domain = candidate.rpartition("@")
    if not separator or not local_part or len(local_part) > 64 or not domain:
        return None
    if local_part.startswith(".") or local_part.endswith(".") or ".." in local_part:
        return None
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local_part):
        return None

    try:
        ascii_domain = domain.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        return None
    if len(ascii_domain) > 253 or "." not in ascii_domain:
        return None
    labels = ascii_domain.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not re.fullmatch(r"[a-z0-9-]+", label)
        for label in labels
    ):
        return None
    return f"{local_part}@{ascii_domain}"


def load_license_email_catalog(language: str) -> dict[str, str]:
    if language not in {"de", "en"}:
        raise ValueError("Unsupported license email language")
    catalog_path = os.path.join(
        current_app.config["PROJECT_ROOT"],
        "i18n",
        f"license_email_{language}.json",
    )
    with open(catalog_path, encoding="utf-8") as catalog_file:
        catalog = json.load(catalog_file)
    messages = catalog.get("messages") if isinstance(catalog, dict) else None
    if (
        not isinstance(catalog, dict)
        or not isinstance(catalog.get("reviewed"), bool)
        or not isinstance(messages, dict)
        or not all(isinstance(value, str) for value in messages.values())
    ):
        raise RuntimeError(f"Invalid license email catalog: {language}")
    return messages


def send_license_email(recipient: str, license_file: bytes) -> None:
    """Send a bilingual plain-text email with the signed license attached."""
    config = current_app.config
    smtp_host = config.get("LICENSE_SMTP_HOST")
    email_from = config.get("LICENSE_EMAIL_FROM")
    smtp_username = config.get("LICENSE_SMTP_USERNAME")
    smtp_password = config.get("LICENSE_SMTP_PASSWORD")
    use_ssl = bool(config.get("LICENSE_SMTP_SSL"))
    use_starttls = bool(config.get("LICENSE_SMTP_STARTTLS"))
    if not smtp_host or not email_from:
        raise RuntimeError("License email SMTP configuration is incomplete")
    if use_ssl and use_starttls:
        raise RuntimeError(
            "LICENSE_SMTP_SSL and LICENSE_SMTP_STARTTLS cannot both be enabled"
        )
    if smtp_username and not smtp_password:
        raise RuntimeError(
            "LICENSE_SMTP_PASSWORD is required with LICENSE_SMTP_USERNAME"
        )

    filename = "porn_fetch.license"
    german = load_license_email_catalog("de")
    english = load_license_email_catalog("en")
    message = EmailMessage()
    message["From"] = email_from
    message["To"] = recipient
    message["Subject"] = f"{german['subject']} / {english['subject']}"
    message["Date"] = format_datetime(datetime.now(timezone.utc))
    message["Message-ID"] = make_msgid(domain=email_from.rpartition("@")[2] or None)
    message.set_content(
        "Deutsch\n--------\n"
        + german["body"].format(filename=filename)
        + "\n\nEnglish\n-------\n"
        + english["body"].format(filename=filename)
    )
    message.add_attachment(
        license_file,
        maintype="application",
        subtype="json",
        filename=filename,
    )

    tls_context = ssl.create_default_context()
    connection_args = {
        "host": smtp_host,
        "port": config["LICENSE_SMTP_PORT"],
        "timeout": config["LICENSE_SMTP_TIMEOUT_SECONDS"],
    }
    if use_ssl:
        smtp_client = smtplib.SMTP_SSL(**connection_args, context=tls_context)
    else:
        smtp_client = smtplib.SMTP(**connection_args)

    with smtp_client:
        smtp_client.ehlo()
        if use_starttls:
            smtp_client.starttls(context=tls_context)
            smtp_client.ehlo()
        if smtp_username:
            smtp_client.login(smtp_username, smtp_password)
        smtp_client.send_message(message)
