"""HTTP normalization helpers shared across route groups."""


def normalized_hostname(raw_host: str) -> str:
    """Normalize a Host value, including bracketed IPv6 hosts and optional ports."""
    normalized = str(raw_host or "").strip().lower()
    if normalized.startswith("["):
        return normalized[1:].partition("]")[0].rstrip(".")
    return normalized.partition(":")[0].rstrip(".")

