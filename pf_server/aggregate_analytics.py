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
PLACEMENTS = frozenset({"header", "guide_top", "guide_steps", "comparison", "content", "footer"})
FEEDBACK = frozenset({"price", "information", "payment", "try_first", "free_sufficient"})
DEVICES = frozenset({"mobile", "tablet", "desktop"})
CLIENT_ACTIONS = ACTIONS | {f"{kind}_{placement}" for kind in ("visible_download", "visible_premium", "click_download", "click_premium") for placement in PLACEMENTS} | {f"feedback_{answer}" for answer in FEEDBACK} | {f"pageview_{device}" for device in DEVICES}
SERVER_ACTIONS = frozenset(f"checkout_valid_{method}_{environment}" for method in ("patreon", "crypto", "card") for environment in ("production", "sandbox"))
ACTIONS = CLIENT_ACTIONS | SERVER_ACTIONS
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
            connection.execute("CREATE TABLE IF NOT EXISTS country_counts (day TEXT NOT NULL, country TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(day, country))")
            connection.execute("CREATE TABLE IF NOT EXISTS daily_counts (day TEXT NOT NULL, page TEXT NOT NULL, action TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY (day, page, action))")
        except sqlite3.Error:
            connection.close()
            raise
        return connection

    def increment(self, page, action, country=None):
        if page not in PAGE_IDS or action not in ACTIONS:
            raise ValueError("Unknown aggregate counter")
        today = utc_today()
        with closing(self.connect()) as connection, connection:
            connection.execute("DELETE FROM daily_counts WHERE day < ?", (retention_cutoff(today).isoformat(),))
            if action == "pageview" and country:
                from .countries import country_name
                if country_name(country):
                    connection.execute("INSERT INTO country_counts VALUES (?, ?, 1) ON CONFLICT(day,country) DO UPDATE SET count=count+1", (today.isoformat(), country))
            connection.execute("INSERT INTO daily_counts VALUES (?, ?, ?, 1) ON CONFLICT(day, page, action) DO UPDATE SET count = count + 1", (today.isoformat(), page, action))

    def purge(self):
        with closing(self.connect()) as connection, connection:
            result = connection.execute("DELETE FROM daily_counts WHERE day < ?", (retention_cutoff(utc_today()).isoformat(),))
            connection.execute("DELETE FROM country_counts WHERE day < ?", (retention_cutoff(utc_today()).isoformat(),))
            return result.rowcount

    def report(self, days=28):
        if type(days) is not int or not 1 <= days <= 90:
            raise ValueError("Reporting days must be between 1 and 90")
        today = utc_today()
        start = today - timedelta(days=days - 1)
        self.purge()
        with closing(self.connect()) as connection:
            rows = connection.execute("SELECT day,page,action,count FROM daily_counts WHERE day >= ? AND day <= ? AND count >= 20 ORDER BY day,page,action", (start.isoformat(), today.isoformat())).fetchall()
            countries = connection.execute("SELECT day,country,count FROM country_counts WHERE day >= ? AND day <= ? AND count >= 20 ORDER BY day,country", (start.isoformat(), today.isoformat())).fetchall()
        return dict(schema_version=2, grain="day", start=start.isoformat(),
                    end_exclusive=(today + timedelta(days=1)).isoformat(),
                    timezone="UTC", minimum_count=20, current_day_partial=True,
                    note="Events, not people or connected funnels. Cells below 20 omitted. Today is incomplete.",
                    rows=[dict(day=day,page=page,action=action,count=count) for day,page,action,count in rows],
                    countries=[dict(day=day,country=country,count=count) for day,country,count in countries])


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
        or not isinstance(payload["action"], str) or payload["action"] not in CLIENT_ACTIONS):
        return "", 400
    if payload["action"].startswith("feedback_") and payload["page"] != "premium":
        return "", 400
    try:
        current_app.extensions["aggregate_analytics"].increment(payload["page"], payload["action"], request.environ.get("PF_COUNTRY_CODE"))
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
    @click.option("--days", type=click.IntRange(1, 90), default=28, show_default=True)
    def report(days):
        """Print daily UTC counters including today, suppressing counts below twenty."""
        click.echo(json.dumps(app.extensions["aggregate_analytics"].report(days), indent=2))

    @app.cli.command("analytics-export")
    def export():
        """Atomically export suppressed daily counts for the private dashboard."""
        store = app.extensions["aggregate_analytics"]
        report = store.report(90)
        report.update(enabled=app.config["AGGREGATE_ANALYTICS_ENABLED"], updated_day=utc_today().isoformat(), generated_at=datetime.now(timezone.utc).isoformat())
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
        click.echo("Exported suppressed daily analytics report")

    @app.cli.command("analytics-purge")
    def purge():
        """Delete counters older than thirteen calendar months."""
        click.echo(f"Removed {app.extensions['aggregate_analytics'].purge()} expired aggregate cells")


def record_checkout_start(method):
    """Called after server-side validation; never accepts client event names."""
    if (not current_app.config.get("AGGREGATE_ANALYTICS_ENABLED") or not public_origin()
            or is_onion() or request.headers.get("DNT") == "1" or request.headers.get("Sec-GPC") == "1"):
        return
    environment = "sandbox" if current_app.config["NOWPAYMENTS_SANDBOX"] else "production"
    action = f"checkout_valid_{method}_{environment}"
    if action not in SERVER_ACTIONS:
        return
    try:
        current_app.extensions["aggregate_analytics"].increment("checkout", action)
    except (OSError, sqlite3.Error):
        current_app.logger.warning("Aggregate analytics storage unavailable")
