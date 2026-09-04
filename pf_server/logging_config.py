"""Privacy-safe logging configuration and correlation helpers."""

import hashlib
import logging
import os
import re
import traceback

from flask import Flask

_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_IPV4 = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
)
_IPV6 = re.compile(
    r"(?<![0-9A-Fa-f:])(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){6}(?:\d{1,3}\.){3}\d{1,3}|"
    r"[0-9A-Fa-f:.]*::[0-9A-Fa-f:.]*"
    r")"
    r"(?![0-9A-Fa-f:])"
)
_URL_QUERY = re.compile(r"(https?://[^\s?]+)\?[^\s]+", re.IGNORECASE)
_AUTHORIZATION = re.compile(
    r"(?i)\bauthorization\s*[:=]\s*(?:bearer\s+|basic\s+)?[^\s,;]+"
)
_COOKIE = re.compile(r"(?i)\b(?:set-cookie|cookie)\s*[:=]\s*[^\r\n]+")
_NAMED_SECRET = re.compile(
    r"(?i)\b(api[_ -]?key|password|secret|token)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)


def redact_log_text(text: str) -> str:
    """Remove common personal data and credentials from rendered log text."""
    text = _URL_QUERY.sub(r"\1?[REDACTED]", text)
    text = _AUTHORIZATION.sub("authorization=[REDACTED]", text)
    text = _COOKIE.sub("cookie=[REDACTED]", text)
    text = _EMAIL.sub("[REDACTED_EMAIL]", text)
    text = _IPV6.sub("[REDACTED_IP]", text)
    text = _IPV4.sub("[REDACTED_IP]", text)
    return _NAMED_SECRET.sub(r"\1\2[REDACTED]", text)


def safe_log_reference(value: object) -> str:
    """Return a non-reversible short reference suitable for log correlation."""
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()
    return digest[:12]


class PrivacySafeFormatter(logging.Formatter):
    """Redact the final message, including formatted exception tracebacks."""

    def format(self, record: logging.LogRecord) -> str:
        return redact_log_text(super().format(record))

    def formatException(self, exc_info) -> str:
        """Keep stack frames and type while omitting data-bearing messages."""
        exception_type, _exception, exception_traceback = exc_info
        frames = "".join(
            f'  File "{os.path.basename(frame.filename)}", line {frame.lineno}, '
            f"in {frame.name}\n"
            for frame in traceback.extract_tb(exception_traceback)
        )
        type_name = f"{exception_type.__module__}.{exception_type.__qualname__}"
        return f"Traceback (most recent call last):\n{frames}{type_name}"


def configure_logging(application: Flask) -> None:
    """Configure application-owned loggers without access-log personal data."""
    level = logging.getLevelName(application.config["LOG_LEVEL"])
    handler = logging.StreamHandler()
    handler.setFormatter(
        PrivacySafeFormatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )

    for logger in (
        application.logger,
        logging.getLogger("pf_server"),
        logging.getLogger("pf_server.access"),
        logging.getLogger("py.warnings"),
    ):
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = False
    logging.captureWarnings(True)
