"""Identifier-free daily counters. No event log and no business database access."""

import calendar
import json
import os
import sqlite3
import tempfile
from contextlib import closing
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import click
from flask import Blueprint, abort, current_app, request

from .download_pages import PLATFORMS
from .extensions import csrf, limiter
from .guide_content import GUIDES
from .onion import is_onion

analytics_bp = Blueprint("aggregate_analytics", __name__)
PAGES = {
    "/": "home", "/guides": "guides", "/download": "download",
    "/about": "about", "/help": "help", "/releases": "releases",
    "/porn_fetch": "premium", "/buy_license": "checkout",
    "/buy_card": "checkout", "/payment-preview/patreon": "checkout",
    "/payment-preview/card": "checkout", "/payment-preview/banxa": "checkout",
    **{f"/guides/download-{key}-videos": f"guide_{key}" for key in GUIDES},
    **{f"/download/{key}": f"download_{key}" for key in PLATFORMS},
}
ACTIONS = frozenset({
    "pageview", "open_download", "open_premium", "checkout_continue",
    "download_click", "installation_guide", "open_help",
    *{f"choose_{key}" for key in PLATFORMS},
})
PAGE_IDS = frozenset(PAGES.values())
ENDPOINT = "/_metrics/event"


def utc_today():
    return datetime.now(timezone.utc).date()


def retention_cutoff(today):
    # Thirteen calendar months, including short months and leap years.
    month = today.year * 12 + today.month - 1 - 13
    year, zero_month = divmod(month, 12)
    return date(year, zero_month + 1, min(today.day, calendar.monthrange(year, zero_month + 1)[1]))


class AggregateCounters:
    def __init__(self, path):
        self.path = Path(path)

    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Create privately even when launched outside the hardened systemd service.
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        os.chmod(self.path, 0o600)
        connection = sqlite3.connect(self.path, timeout=1)
        try:
            connection.execute("CREATE TABLE IF NOT EXISTS daily_counts (day TEXT NOT NULL, page TEXT NOT NULL, action TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY (day, page, action))")
        except sqlite3.Error:
            connection.close()
            raise
        return connection

    def increment(self, page, action):
        if page not in PAGE_IDS or action not in ACTIONS:
            raise ValueError("Unknown aggregate counter")
        today = utc_today()
        with closing(self.connect()) as connection, connection:
            connection.execute("DELETE FROM daily_counts WHERE day < ?", (retention_cutoff(today).isoformat(),))
            connection.execute("INSERT INTO daily_counts VALUES (?, ?, ?, 1) ON CONFLICT(day, page, action) DO UPDATE SET count = count + 1", (today.isoformat(), page, action))

    def purge(self):
        with closing(self.connect()) as connection, connection:
            result = connection.execute("DELETE FROM daily_counts WHERE day < ?", (retention_cutoff(utc_today()).isoformat(),))
            return result.rowcount

    def report(self, weeks):
        today = utc_today()
        end = today - timedelta(days=today.weekday())
        start = end - timedelta(weeks=weeks)
        self.purge()
        with closing(self.connect()) as connection:
            rows = connection.execute("SELECT day, page, action, count FROM daily_counts WHERE day >= ? AND day < ?", (start.isoformat(), end.isoformat())).fetchall()
        grouped = {}
        for day, page, action, count in rows:
            day = date.fromisoformat(day)
            week = (day - timedelta(days=day.weekday())).isoformat()
            key = (week, page, action)
            grouped[key] = grouped.get(key, 0) + count
        return {
            "start": start.isoformat(), "end_exclusive": end.isoformat(),
            "timezone": "UTC", "minimum_count": 20,
            "note": "Event counts, not people or connected funnels. Cells below 20 omitted; no totals for suppressed cells.",
            "rows": [dict(week=week, page=page, action=action, count=count)
                     for (week, page, action), count in sorted(grouped.items()) if count >= 20],
        }


def public_origin():
    return request.host.lower() == urlsplit(current_app.config["APP_DOMAIN"]).netloc.lower()


@analytics_bp.post(ENDPOINT)
@csrf.exempt
@limiter.limit("6000 per minute", key_func=lambda: "aggregate-analytics-global")
def collect():
    if not current_app.config["AGGREGATE_ANALYTICS_ENABLED"] or not public_origin() or is_onion():
        abort(404)
    # Do not accept URL parameters, cross-origin submissions, or ambient identities.
    if request.query_string or request.headers.get("Cookie") or request.headers.get("Authorization"):
        return "", 400
    if request.headers.get("Origin") != current_app.config["APP_DOMAIN"] or request.headers.get("Sec-Fetch-Site") not in {None, "same-origin"}:
        return "", 403
    if request.headers.get("DNT") == "1" or request.headers.get("Sec-GPC") == "1":
        return "", 204
    if request.mimetype != "application/json":
        return "", 415
    if request.content_length is None or request.content_length > 256:
        return "", 413
    request.max_content_length = 256
    payload = request.get_json(silent=True)
    if (not isinstance(payload, dict) or set(payload) != {"page", "action"}
        or not isinstance(payload["page"], str) or payload["page"] not in PAGE_IDS
        or not isinstance(payload["action"], str) or payload["action"] not in ACTIONS):
        return "", 400
    try:
        current_app.extensions["aggregate_analytics"].increment(payload["page"], payload["action"])
    except (OSError, sqlite3.Error):
        # Fixed message only: no payload, headers, exceptions, or request details.
        current_app.logger.warning("Aggregate analytics storage unavailable")
        return "", 503
    return "", 204


def init_aggregate_analytics(app):
    app.extensions["aggregate_analytics"] = AggregateCounters(Path(app.config["DATA_DIR"]) / "aggregate-analytics.sqlite3")
    app.register_blueprint(analytics_bp)

    @app.context_processor
    def analytics_context():
        page = None
        if app.config["AGGREGATE_ANALYTICS_ENABLED"] and public_origin() and not is_onion() and request.method == "GET":
            page = PAGES.get(request.path)
        return {"aggregate_analytics_page": page}

    @app.after_request
    def analytics_headers(response):
        if request.path == ENDPOINT:
            response.headers["Cache-Control"] = "no-store"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["X-Robots-Tag"] = "noindex, nofollow"
        return response

    @app.cli.command("analytics-report")
    @click.option("--weeks", type=click.IntRange(1, 57), default=4, show_default=True)
    def report(weeks):
        """Print completed UTC weeks only, suppressing counts below twenty."""
        click.echo(json.dumps(app.extensions["aggregate_analytics"].report(weeks), indent=2))

    @app.cli.command("analytics-export")
    def export():
        """Atomically export suppressed weekly counts for the private dashboard."""
        store = app.extensions["aggregate_analytics"]
        report = store.report(57)
        report.update(enabled=app.config["AGGREGATE_ANALYTICS_ENABLED"], updated_day=utc_today().isoformat())
        descriptor, temporary = tempfile.mkstemp(prefix=".analytics-report-", dir=store.path.parent)
        try:
            with os.fdopen(descriptor, "w") as target:
                json.dump(report, target)
                target.flush()
                os.fsync(target.fileno())
                os.fchmod(target.fileno(), 0o640)
            os.replace(temporary, store.path.parent / "aggregate-analytics-report.json")
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        click.echo("Exported suppressed weekly analytics report")

    @app.cli.command("analytics-purge")
    def purge():
        """Delete counters older than thirteen calendar months."""
        click.echo(f"Removed {app.extensions['aggregate_analytics'].purge()} expired aggregate cells")
