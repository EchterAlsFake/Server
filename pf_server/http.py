"""HTTP normalization helpers shared across route groups."""


def normalized_hostname(raw_host: str) -> str:
    """Normalize a Host value, including bracketed IPv6 hosts and optional ports."""
    normalized = str(raw_host or "").strip().lower()
    if normalized.startswith("["):
        return normalized[1:].partition("]")[0].rstrip(".")
    return normalized.partition(":")[0].rstrip(".")



class TrustedHostMiddleware:
    """Reject hostile hosts before Flask hooks inspect request.host on errors."""

    def __init__(self, application, trusted_hosts):
        self.application = application
        self.trusted_hosts = trusted_hosts

    def __call__(self, environ, start_response):
        from werkzeug.exceptions import SecurityError
        from werkzeug.wrappers import Response
        from werkzeug.wsgi import get_host
        try:
            get_host(environ, trusted_hosts=self.trusted_hosts)
        except SecurityError:
            return Response("Invalid host", status=400)(environ, start_response)
        return self.application(environ, start_response)
