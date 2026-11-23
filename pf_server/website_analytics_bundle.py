"""Build a private weekly bundle from suppressed site counts and settled Search Console data."""

import csv
import io
import json
import re
from collections import defaultdict
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import quote, urlsplit

import click
import httpx

from .aggregate_analytics import MINIMUM, PAGES, atomic_write
from .website_locale import LANGUAGES

PROPERTY = "sc-domain:pornfetch.to"
GSC_SCOPE = "https://www.googleapis.com/auth/webmasters.readonly"
GSC_URL = f"https://www.googleapis.com/webmasters/v3/sites/{quote(PROPERTY, safe='')}/searchAnalytics/query"
SEARCH_DIMENSIONS = {"page": "page", "device": "device", "country": "country", "query_theme": "query"}
GSC_LIMIT = 5000
THEMES = ("installation", "compatibility", "product_name", "download", "other")
DEVICES = {"DESKTOP", "MOBILE", "TABLET"}


def canonical_page(value):
    url = urlsplit(value)
    if url.netloc and (url.scheme != "https" or url.netloc != "pornfetch.to"):
        return None
    path = url.path.rstrip("/") or "/"
    first, _, tail = path[1:].partition("/")
    if first in LANGUAGES:
        path = f"/{tail}"
    return path if path in PAGES else None


def query_theme(value):
    value = value.lower()
    for theme, pattern in (
        ("installation", r"install|setup|einricht"),
        ("compatibility", r"android|iphone|ios|windows|linux|macos|termux"),
        ("product_name", r"porn[ _-]*fetch"),
        ("download", r"download|herunterlad|baixar|descarg|télécharg"),
    ):
        if re.search(pattern, value):
            return theme
    return "other"


def gsc_rows(client, start, end, dimension):
    response = client.post(GSC_URL, json={
        "startDate": start.isoformat(), "endDate": end.isoformat(),
        "type": "web", "dataState": "final", "dimensions": [dimension],
        "rowLimit": GSC_LIMIT,
    })
    response.raise_for_status()
    return response.json().get("rows", [])


def validate_search_value(kind, value):
    if kind == "page":
        return canonical_page(value)
    if kind == "query_theme":
        return value if value in THEMES else None
    value = value.upper()
    if kind == "device":
        return value if value in DEVICES else None
    return value if kind == "country" and re.fullmatch("[A-Z]{3}", value) else None


def add_search_row(rows, kind, name, clicks, impressions, position):
    if not name or clicks < 0 or clicks > impressions or impressions < 1 or not 0 <= position <= 10000:
        return
    group = rows[(kind, name)]
    group[0] += clicks
    group[1] += impressions
    group[2] += position * impressions


def search_result(rows):
    return [
        dict(dimension=kind, value=name, clicks=clicks, impressions=impressions,
             ctr=round(clicks / impressions, 5), position=round(weighted / impressions, 2))
        for (kind, name), (clicks, impressions, weighted) in sorted(rows.items())
        if impressions >= MINIMUM
    ]


def refresh_search_token(path):
    credentials = json.loads(path.read_text(encoding="utf-8"))
    with httpx.Client(timeout=20, trust_env=False) as client:
        response = client.post("https://oauth2.googleapis.com/token", data={
            "grant_type": "refresh_token",
            **{key: credentials[key] for key in ("client_id", "client_secret", "refresh_token")},
        })
        response.raise_for_status()
        token = response.json()["access_token"]
        if not isinstance(token, str) or not token.strip():
            raise ValueError("Invalid OAuth token")
        return token


def fetch_search(weeks, token):
    results = {}
    with httpx.Client(headers={"Authorization": f"Bearer {token}"}, timeout=20, trust_env=False) as client:
        for week in weeks:
            start = date.fromisoformat(week)
            end = start + timedelta(days=6)
            totals = gsc_rows(client, start, date.today(), "date")
            complete = any(row["keys"][0] >= end.isoformat() for row in totals)
            if not complete:
                results[week] = dict(status="unavailable", rows=[])
                continue
            rows = defaultdict(lambda: [0, 0, 0.0])
            limited = []
            for kind, dimension in SEARCH_DIMENSIONS.items():
                source = gsc_rows(client, start, end, dimension)
                if len(source) >= GSC_LIMIT:
                    limited.append(kind)
                for row in source:
                    value = row["keys"][0]
                    name = query_theme(value) if kind == "query_theme" else validate_search_value(kind, value)
                    add_search_row(rows, kind, name, int(row["clicks"]), int(row["impressions"]), float(row["position"]))
            results[week] = dict(status="available", rows=search_result(rows), capped_dimensions=limited)
    return results


def import_search(weeks, source):
    grouped = {week: defaultdict(lambda: [0, 0, 0.0]) for week in weeks}
    if source.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("Search Console import exceeds size limit")
    with source.open(encoding="utf-8-sig", newline="") as file:
        rows = csv.DictReader(file)
        if set(rows.fieldnames or []) != {"week", "dimension", "value", "clicks", "impressions", "position"}:
            raise ValueError("Invalid Search Console CSV columns")
        for row in rows:
            if row["week"] not in grouped:
                continue
            kind = row["dimension"]
            name = validate_search_value(kind, row["value"])
            add_search_row(grouped[row["week"]], kind, name, int(row["clicks"]), int(row["impressions"]), float(row["position"]))
    return {week: dict(status="available" if rows else "unavailable", rows=search_result(rows))
            for week, rows in grouped.items()}


def parse_changes(source, weeks):
    if source is None:
        return []
    if source.stat().st_size > 64 * 1024:
        raise ValueError("Release annotations exceed size limit")
    entries = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError("Expected a list of release annotations")
    start = date.fromisoformat(weeks[0])
    end = date.fromisoformat(weeks[-1]) + timedelta(days=7)
    result = []
    for entry in entries:
        day = date.fromisoformat(entry["date"])
        note = entry["note"]
        if start <= day < end and isinstance(note, str) and 0 < len(note) <= 240 and not any(ord(c) < 32 for c in note):
            result.append(dict(date=day.isoformat(), note=note))
    return sorted(result, key=lambda item: item["date"])


def build_bundle(report, search, annotations):
    end = date.fromisoformat(report["end_exclusive"])
    weeks = [(end - timedelta(weeks=offset)).isoformat() for offset in (2, 1)]
    series = {item["id"]: item for item in report["series"]}
    counts = {(row["week"], row["series"]): row["count"] for row in report["weekly"] if row["week"] in weeks}
    comparable = report["enabled"] and report["cutover"] is not None and report["cutover"] < weeks[0]
    changes = []
    for key, item in series.items():
        previous, current = [counts.get((week, key)) for week in weeks]
        if previous is None and current is None:
            continue
        changes.append(dict(**item, previous=previous, current=current,
                            delta=current - previous if comparable and previous is not None and current is not None else None))
    return dict(
        schema_version=1, weeks=weeks, generated_at=report["generated_at"],
        website=dict(timezone="UTC", scope="Allowlisted public requests and voluntary feedback",
                     enabled=report["enabled"], cutover=report["cutover"], comparable=comparable,
                     minimum_count=report["minimum_count"], series=changes),
        search_console=dict(property=PROPERTY, timezone="America/Los_Angeles", weeks=search,
                            note="Final Web results. Query themes cover visible query rows only."),
        release_annotations=annotations,
    )


def markdown(bundle):
    output = io.StringIO()
    output.write("# PornFetch weekly website analytics\n\n")
    previous, current = bundle["weeks"]
    output.write(f"Weeks beginning {previous} and {current}. On-site counts use UTC. Search Console uses Pacific dates.\n\n")
    output.write("Use the evidence to rank improvement hypotheses and propose a measurable follow-up for each. "
                 "Keep search clicks, website requests and feedback responses distinct. "
                 "Avoid inferring unique visitors, click origins, abandonment or purchase conversion.\n\n")
    website = bundle["website"]
    if not website["comparable"]:
        output.write("The two website weeks lack a shared full measurement baseline. Changes are withheld.\n\n")
    output.write("## Website counts\n\n| Page or feedback | Earlier week | Latest week | Change |\n|---|---:|---:|---:|\n")
    for row in website["series"]:
        values = [str(row[key]) if row[key] is not None else "—" for key in ("previous", "current", "delta")]
        output.write(f"| {row.get('path', row.get('label'))} | {' | '.join(values)} |\n")
    output.write("\nA dash means unavailable, suppressed, or incomparable. Use the JSON file for Search Console tables.\n")
    output.write("\n## Search Console availability\n\n")
    for week, result in bundle["search_console"]["weeks"].items():
        output.write(f"- {week} · {result['status']}\n")
    output.write("\n## Site changes\n\n")
    for item in bundle["release_annotations"]:
        output.write(f"- {item['date']} · {item['note']}\n")
    return output.getvalue()


def register_bundle(app, store):
    @app.cli.command("analytics-weekly")
    @click.option("--output", type=click.Path(path_type=Path), required=True)
    @click.option("--search-csv", type=click.Path(path_type=Path, exists=True, dir_okay=False))
    @click.option("--search-token-file", type=click.Path(path_type=Path, exists=True, dir_okay=False),
                  envvar="WEBSITE_SEARCH_CONSOLE_TOKEN_FILE")
    @click.option("--search-oauth-file", type=click.Path(path_type=Path, exists=True, dir_okay=False),
                  envvar="WEBSITE_SEARCH_CONSOLE_OAUTH_FILE")
    @click.option("--changes", type=click.Path(path_type=Path, exists=True, dir_okay=False),
                  envvar="WEBSITE_ANALYTICS_CHANGES_FILE")
    def weekly(output, search_csv, search_token_file, search_oauth_file, changes):
        """Write a private, aggregate-only weekly review bundle."""
        report = store.report(app.config["WEBSITE_REQUEST_ANALYTICS_ENABLED"])
        end = date.fromisoformat(report["end_exclusive"])
        weeks = [(end - timedelta(weeks=offset)).isoformat() for offset in (2, 1)]
        search = {week: dict(status="unavailable", rows=[]) for week in weeks}
        if search_csv:
            try:
                search = import_search(weeks, search_csv)
            except (OSError, ValueError, csv.Error, TypeError):
                raise click.ClickException("Invalid Search Console CSV import") from None
        elif search_token_file or search_oauth_file:
            try:
                token = (search_token_file.read_text(encoding="utf-8").strip() if search_token_file
                         else refresh_search_token(search_oauth_file))
                search = fetch_search(weeks, token)
            except (OSError, ValueError, KeyError, TypeError, httpx.HTTPError):
                click.echo("Search Console unavailable. Writing the website-only bundle.", err=True)
        try:
            annotations = parse_changes(changes, weeks)
        except (OSError, ValueError, KeyError, TypeError):
            raise click.ClickException("Invalid release annotations") from None
        bundle = build_bundle(report, search, annotations)
        output.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_write(output / "analytics.json", json.dumps(bundle, ensure_ascii=False, indent=2), 0o600)
        atomic_write(output / "summary.md", markdown(bundle), 0o600)
        click.echo("Wrote analytics.json and summary.md")
