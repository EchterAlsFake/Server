"""License creation, recipient validation, and SMTP delivery services."""

import base64
import json
import os
import re
import secrets
import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flask import current_app
from sqlalchemy.exc import SQLAlchemyError

from .extensions import db
from .models import License
from .time_utils import rfc3339_utc


def canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def make_license_key(prefix: str = "PF") -> str:
    raw = secrets.token_hex(16).upper()
    return f"{prefix}-" + "-".join(raw[index : index + 8] for index in range(0, 32, 8))


def sign_license(payload: dict) -> str:
    encoded_private_key = current_app.config.get("LICENSE_PRIVATE_KEY_B64")
    if not encoded_private_key:
        raise RuntimeError("Missing LICENSE_PRIVATE_KEY_B64")
    private_key = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(encoded_private_key, validate=True)
    )
    signature = private_key.sign(canonical_json_bytes(payload))
    return base64.b64encode(signature).decode("ascii")


def build_license_file(
    license_key: str,
    issuance_reference: str,
    created_at: str,
) -> bytes:
    """Create the signed license document used by downloads and email delivery."""
    payload = {
        "schema": 1,
        "product": "porn-fetch",
        "kid": "v1",
        "alg": "ed25519",
        "license_key": license_key,
        "issuance_reference": issuance_reference,
        "created_at": created_at,
        "features": ["full_unlock"],
    }
    payload["sig"] = sign_license(payload)
    return (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


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
        except SQLAlchemyError:
            db.session.rollback()
            raise
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
