"""Validated environment configuration for the Flask application."""

import base64
import binascii
import fcntl
import os
import secrets
from collections.abc import Mapping
from urllib.parse import urlsplit

DEFAULT_RATE_LIMIT = "10000 per minute"
MAX_REQUEST_SIZE = 200 * 1024
LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


def _boolean(source: Mapping[str, str], name: str, default: bool) -> bool:
    fallback = "true" if default else "false"
    value = source.get(name, fallback).strip().lower()
    if value in {"true", "1", "yes"}:
        return True
    if value in {"false", "0", "no"}:
        return False
    raise ValueError(f"{name} must be true or false")


def _origin(source: Mapping[str, str], name: str, default: str) -> tuple[str, str]:
    origin = source.get(name, default).strip().rstrip("/")
    parsed = urlsplit(origin)
    try:
        parsed_port = parsed.port
    except ValueError as error:
        raise ValueError(f"{name} must use a valid port") from error
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{name} must be an absolute HTTP(S) URL")
    if parsed_port is not None and not 1 <= parsed_port <= 65535:
        raise ValueError(f"{name} must use a valid port")
    return origin, parsed.hostname.lower().rstrip(".")


def _secret_key(source: Mapping[str, str], data_directory: str) -> str:
    configured_secret = source.get("SECRET_KEY")
    if configured_secret:
        return configured_secret

    secret_path = os.path.join(data_directory, ".flask_secret")
    with open(secret_path, "a+", encoding="utf-8") as secret_file:
        fcntl.flock(secret_file.fileno(), fcntl.LOCK_EX)
        os.chmod(secret_path, 0o600)
        secret_file.seek(0)
        secret = secret_file.read().strip()
        if not secret:
            secret = secrets.token_hex(32)
            secret_file.write(secret)
            secret_file.flush()
            os.fsync(secret_file.fileno())
        return secret


def load_environment_config(
    project_root: str,
    environ: Mapping[str, str] | None = None,
) -> dict:
    """Read, validate, and normalize all environment-backed settings."""
    source = os.environ if environ is None else environ
    project_root = os.path.abspath(project_root)
    data_directory = os.path.abspath(source.get("PF_SERVER_DATA_DIR", project_root))
    database_path = os.path.abspath(
        source.get("PF_SERVER_DB", os.path.join(data_directory, "server.db"))
    )
    os.makedirs(data_directory, exist_ok=True)

    app_domain, _ = _origin(source, "APP_DOMAIN", "https://echteralsfake.me")
    api_domain, api_public_host = _origin(
        source,
        "API_DOMAIN",
        "https://api.echteralsfake.me",
    )

    try:
        smtp_port = int(source.get("LICENSE_SMTP_PORT", "587"))
    except ValueError as error:
        raise ValueError("LICENSE_SMTP_PORT must be an integer") from error
    if not 1 <= smtp_port <= 65535:
        raise ValueError("LICENSE_SMTP_PORT must be between 1 and 65535")

    smtp_username = source.get("LICENSE_SMTP_USERNAME", "").strip()
    smtp_password = source.get("LICENSE_SMTP_PASSWORD", "")
    smtp_starttls = _boolean(source, "LICENSE_SMTP_STARTTLS", True)
    smtp_ssl = _boolean(source, "LICENSE_SMTP_SSL", False)
    if smtp_starttls and smtp_ssl:
        raise ValueError(
            "LICENSE_SMTP_SSL and LICENSE_SMTP_STARTTLS cannot both be enabled"
        )
    if smtp_username and not smtp_password:
        raise ValueError("LICENSE_SMTP_PASSWORD is required with LICENSE_SMTP_USERNAME")

    encoded_private_key = source.get("LICENSE_PRIVATE_KEY_B64", "")
    if encoded_private_key:
        try:
            private_key = base64.b64decode(encoded_private_key, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("LICENSE_PRIVATE_KEY_B64 must be valid base64") from error
        if len(private_key) != 32:
            raise ValueError("LICENSE_PRIVATE_KEY_B64 must encode exactly 32 bytes")

    nowpayments_sandbox = _boolean(source, "NOWPAYMENTS_SANDBOX", True)
    nowpayments_api_key = source.get("NOWPAYMENTS_API_KEY")
    nowpayments_ipn_secret = source.get("NOWPAYMENTS_IPN_SECRET")
    if not nowpayments_sandbox and (
        not nowpayments_api_key or not nowpayments_ipn_secret
    ):
        raise ValueError(
            "CRITICAL: NOWPAYMENTS_API_KEY and NOWPAYMENTS_IPN_SECRET must be set in production."
        )

    nowpayments_api_url = (
        "https://api-sandbox.nowpayments.io/v1"
        if nowpayments_sandbox
        else "https://api.nowpayments.io/v1"
    )
    tier_ids = frozenset(
        tier_id.strip()
        for tier_id in source.get("PATREON_LICENSE_TIER_IDS", "").split(",")
        if tier_id.strip()
    )
    log_level = source.get("LOG_LEVEL", "INFO").strip().upper()
    if log_level not in LOG_LEVELS:
        raise ValueError(f"LOG_LEVEL must be one of: {', '.join(sorted(LOG_LEVELS))}")
    checkout_ip_header = source.get(
        "CHECKOUT_IP_HEADER", "CF-Connecting-IP"
    ).strip()
    if checkout_ip_header not in {"", "CF-Connecting-IP"}:
        raise ValueError("CHECKOUT_IP_HEADER must be CF-Connecting-IP or empty")
    geoip_database_path = os.path.abspath(
        source.get(
            "GEOIP_DATABASE_PATH",
            os.path.join(data_directory, "geoip", "dbip-city-lite.mmdb"),
        )
    )

    return {
        "MAX_CONTENT_LENGTH": MAX_REQUEST_SIZE,
        "SECRET_KEY": _secret_key(source, data_directory),
        "WTF_CSRF_SSL_STRICT": False,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "PROJECT_ROOT": project_root,
        "DATA_DIR": data_directory,
        "APP_DOMAIN": app_domain,
        "API_DOMAIN": api_domain,
        "API_PUBLIC_HOST": api_public_host,
        "GITHUB_TOKEN": source.get("GITHUB_TOKEN", ""),
        "KILL_TOKEN": source.get("KILL_TOKEN"),
        "CI_TOKEN": source.get("CI_TOKEN"),
        "CHECKLIST_AUTH": source.get("CHECKLIST_AUTH"),
        "PATREON_SECRET": source.get("PATREON_SECRET", ""),
        "PATREON_LICENSE_TIER_IDS": tier_ids,
        "LICENSE_PRIVATE_KEY_B64": encoded_private_key,
        "LICENSE_SMTP_HOST": source.get("LICENSE_SMTP_HOST", "").strip(),
        "LICENSE_SMTP_PORT": smtp_port,
        "LICENSE_SMTP_USERNAME": smtp_username,
        "LICENSE_SMTP_PASSWORD": smtp_password,
        "LICENSE_EMAIL_FROM": source.get("LICENSE_EMAIL_FROM", smtp_username).strip(),
        "LICENSE_SMTP_STARTTLS": smtp_starttls,
        "LICENSE_SMTP_SSL": smtp_ssl,
        "LICENSE_SMTP_TIMEOUT_SECONDS": 15,
        "NOWPAYMENTS_API_KEY": nowpayments_api_key,
        "NOWPAYMENTS_IPN_SECRET": nowpayments_ipn_secret,
        "NOWPAYMENTS_SANDBOX": nowpayments_sandbox,
        "NOWPAYMENTS_API_URL": nowpayments_api_url,
        "RATELIMIT_DEFAULT": DEFAULT_RATE_LIMIT,
        "RATELIMIT_STORAGE_URI": source.get("RATELIMIT_STORAGE_URI", "memory://"),
        "LOG_LEVEL": log_level,
        "CHECKOUT_IP_HEADER": checkout_ip_header,
        "GEOIP_DATABASE_PATH": geoip_database_path,
        "GEOIP_DATABASE_LABEL": source.get("GEOIP_DATABASE_LABEL", "").strip()[:100],
    }
