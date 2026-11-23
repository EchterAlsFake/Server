"""Count allowlisted public requests without accepting browser telemetry."""

import json
import os
import sqlite3
import tempfile
from collections import defaultdict
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import click
from flask import Blueprint, abort, current_app, make_response, render_template, request

from .download_pages import PLATFORMS
from .extensions import csrf, limiter
from .guide_content import GUIDES
from .onion import is_onion
from .website_locale import source_path

analytics_bp = Blueprint("aggregate_analytics", __name__)
ENABLED = "WEBSITE_REQUEST_ANALYTICS_ENABLED"
FEEDBACK_ENDPOINT = "/_metrics/feedback"
REPORT_FILE = "website-request-analytics-report.json"
MINIMUM = 20
RETENTION_WEEKS = 26
PAGES = {
    "/": ("home", "pages"),
    "/guides": ("guides", "pages"),
    "/about": ("about", "pages"),
    "/releases": ("releases", "pages"),
    "/porn_fetch": ("premium", "product"),
    "/download": ("download", "product"),
    "/help": ("help", "help"),
    **{f"/guides/download-{key}-videos": (f"guide_{key}", "pages") for key in GUIDES},
    **{f"/download/{key}": (f"download_{key}", "product") for key in PLATFORMS},
}
FEEDBACK = {
    "platform": ("I couldn’t find my platform", "Ich konnte meine Plattform nicht finden"),
    "installation": ("Installation steps were unclear", "Die Installationsschritte waren unklar"),
    "product": ("I needed more product information", "Mir fehlten Informationen zum Produkt"),
    "pricing": ("The price or what’s included was unclear", "Preis oder Leistungsumfang waren unklar"),
    "support": ("I couldn’t find the help I needed", "Ich konnte die passende Hilfe nicht finden"),
}
SERIES = {
    **{key: dict(id=key, category=category, path=path) for path, (key, category) in PAGES.items()},
    **{f"feedback_{key}": dict(id=f"feedback_{key}", category="help", label=labels[0])
       for key, labels in FEEDBACK.items()},
}


def utc_today():
    return datetime.now(UTC).date()


def week_start(day):
    return day - timedelta(days=day.weekday())


def atomic_write(path, content, mode=0o640):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
            os.fchmod(target.fileno(), mode)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class AggregateCounters:
    def __init__(self, path):
        self.path = Path(path)

    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        connection = sqlite3.connect(self.path, timeout=0.25)
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS counts (day TEXT, series TEXT, count INTEGER NOT NULL,"
                " PRIMARY KEY(day,series))"
            )
            connection.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        except sqlite3.Error:
            connection.close()
            raise
        return connection

    def increment(self, series):
        if series not in SERIES:
            raise ValueError("Unknown website counter")
        day = utc_today().isoformat()
        with closing(self.connect()) as db, db:
            db.execute("INSERT OR IGNORE INTO metadata VALUES ('started',?)", (day,))
            db.execute("INSERT INTO counts VALUES (?,?,1) ON CONFLICT DO UPDATE SET count=count+1", (day, series))

    def purge(self):
        cutoff = (week_start(utc_today()) - timedelta(weeks=RETENTION_WEEKS)).isoformat()
        with closing(self.connect()) as db, db:
            return db.execute("DELETE FROM counts WHERE day < ?", (cutoff,)).rowcount

    def report(self, enabled):
        now = datetime.now(UTC)
        end = week_start(now.date())
        start = end - timedelta(weeks=RETENTION_WEEKS)
        self.purge()
        cells = defaultdict(list)
        with closing(self.connect()) as db:
            cutover = db.execute("SELECT value FROM metadata WHERE key='started'").fetchone()
            cutover = cutover[0] if cutover else None
            for raw_day, series, count in db.execute(
                "SELECT day,series,count FROM counts WHERE day>=? AND day<? ORDER BY day,series",
                (start.isoformat(), end.isoformat()),
            ):
                if series in SERIES:
                    cells[(week_start(datetime.fromisoformat(raw_day).date()).isoformat(), series)].append((raw_day, count))
        daily, weekly = [], []
        for (week, series), days in sorted(cells.items()):
            total = sum(count for _, count in days)
            if total < MINIMUM:
                continue
            # Publish no daily breakdown for a series/week with a small positive day.
            # Closed weeks are used everywhere so earlier exports cannot reveal that day.
            daily_visible = all(count >= MINIMUM for _, count in days)
            weekly.append(dict(week=week, series=series, count=total, daily_available=daily_visible))
            if daily_visible:
                daily.extend(dict(day=day, series=series, count=count) for day, count in days)
        return dict(
            schema_version=3, method="public_request_counts", timezone="UTC",
            minimum_count=MINIMUM, start=start.isoformat(), end_exclusive=end.isoformat(),
            generated_at=now.isoformat(), enabled=enabled, cutover=cutover,
            series=list(SERIES.values()), daily=daily, weekly=weekly,
        )


def public_origin():
    return request.host.lower() == urlsplit(current_app.config["APP_DOMAIN"]).netloc.lower()


def collecting():
    return (current_app.config[ENABLED] and public_origin() and not is_onion()
            and request.headers.get("DNT") != "1" and request.headers.get("Sec-GPC") != "1")


def increment(series):
    try:
        current_app.extensions["aggregate_analytics"].increment(series)
        return True
    except (OSError, sqlite3.Error):
        current_app.logger.warning("Website request counters unavailable")
        return False


@analytics_bp.post(FEEDBACK_ENDPOINT)
@csrf.exempt
@limiter.limit("60 per minute", key_func=lambda: "website-feedback-global")
def feedback():
    if not collecting():
        abort(404)
    if (request.headers.get("Origin") != current_app.config["APP_DOMAIN"]
            or request.headers.get("Sec-Fetch-Site") not in {None, "same-origin"}):
        abort(403)
    if (request.query_string or request.mimetype != "application/x-www-form-urlencoded"
            or request.content_length is None or request.content_length > 128):
        abort(400)
    request.max_content_length = 128
    answer = request.form.get("answer")
    locales = request.form.getlist("language")
    if (set(request.form) != {"answer", "language"} or len(request.form.getlist("answer")) != 1
            or answer not in FEEDBACK or locales not in (["de"], ["en"])):
        abort(400)
    saved = increment(f"feedback_{answer}")
    response = make_response(render_template("website_feedback.html", saved=saved, german=locales == ["de"]), 200 if saved else 503)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Robots-Tag"] = "noindex"
    return response


def init_aggregate_analytics(app):
    store = AggregateCounters(Path(app.config["DATA_DIR"]) / "website-request-counts.sqlite3")
    app.extensions["aggregate_analytics"] = store
    app.register_blueprint(analytics_bp)

    @app.context_processor
    def feedback_context():
        show = request.method == "GET" and source_path() in {"/porn_fetch", "/download", "/help"} and collecting()
        return {"website_feedback_choices": FEEDBACK if show else {}}

    @app.after_request
    def count_public_page(response):
        if (request.method != "GET" or response.status_code != 200 or response.mimetype != "text/html"
                or request.url_rule is None or not collecting()
                or any("prefetch" in request.headers.get(header, "").lower()
                       for header in ("Sec-Purpose", "Purpose", "X-Moz"))):
            return response
        page = PAGES.get(source_path())
        if page:
            increment(page[0])
        return response

    @app.cli.command("analytics-report")
    def report():
        """Read the privacy-filtered website report."""
        click.echo(json.dumps(store.report(app.config[ENABLED]), indent=2))

    @app.cli.command("analytics-export")
    def export():
        """Publish the suppressed aggregate snapshot for the dashboard."""
        atomic_write(store.path.parent / REPORT_FILE, json.dumps(store.report(app.config[ENABLED])))
        click.echo("Exported website request counts")

    @app.cli.command("analytics-purge")
    def purge():
        """Remove expired website request counts."""
        click.echo(f"Removed {store.purge()} expired website counter cells")

    from .website_analytics_bundle import register_bundle
    register_bundle(app, store)
