"""Canonical timestamp formatting shared by API modules."""

from datetime import datetime, timezone


def rfc3339_utc(value: str | datetime) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

