"""Persist coarse HTTP counters and log positions in one SQLite transaction."""
import argparse
import json
import os
import re
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

HOSTS = {
    "pornfetch.to", "www.pornfetch.to", "api.pornfetch.to", "licenses.pornfetch.to",
    "downloads.pornfetch.to", "ech.echteralsfake.me", "echteralsfake.me",
    "www.echteralsfake.me", "docs.echteralsfake.me", "vplan.echteralsfake.me",
    "mcp.echteralsfake.me", "translations.echteralsfake.me", "api.echteralsfake.me",
}
ARTIFACT = re.compile(r"\.(?:apk|appimage|exe|msi|dmg|zip|7z|tar\.(?:gz|xz|zst)|deb|rpm)$", re.I)


def endpoint(host, path):
    if path in {"/ping", "/__infra_health", "/__download_health", "/dashboard/healthz", "/healthz"}:
        return "health"
    if path.startswith("/dashboard") or path == "/dashbord":
        return "dashboard"
    if path.startswith(("/_metrics/", "/__eaf/")):
        return "measurement"
    if path.startswith(("/static/", "/assets/")) or path in {"/favicon.ico", "/robots.txt"}:
        return "assets"
    if path.startswith(("/downloads/", "/repo/", "/standalone/")) or (
            host == "downloads.pornfetch.to" and ARTIFACT.search(path)):
        return "download"
    if path.startswith(("/activate", "/license", "/v1/licenses")) or host == "licenses.pornfetch.to":
        return "licensing"
    if path.startswith(("/buy", "/payment", "/checkout", "/webhook")):
        return "payments"
    if path.startswith(("/api/", "/v1/")) or host.startswith("api."):
        return "api"
    if path == "/" or path.startswith(("/guides", "/download", "/help", "/about", "/releases", "/docs", "/porn_fetch")):
        return "pages"
    return "other"


def collect(log, database):
    now = datetime.now(UTC)
    with sqlite3.connect(database) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS cursor (device INTEGER, inode INTEGER, offset INTEGER, PRIMARY KEY(device,inode));
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS daily (
                day TEXT, host TEXT, endpoint TEXT, method TEXT, status TEXT, client TEXT, count INTEGER,
                PRIMARY KEY(day,host,endpoint,method,status,client)
            );
            CREATE TABLE IF NOT EXISTS downloads (
                day TEXT, source TEXT, path TEXT, requests INTEGER, ranges INTEGER, bytes INTEGER,
                PRIMARY KEY(day,source,path)
            );
        """)
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT OR IGNORE INTO metadata VALUES ('started',?)", (now.isoformat(),))
        for candidate in sorted(log.parent.glob(log.stem + "*" + log.suffix)):
            with candidate.open("rb") as stream:
                stat = os.fstat(stream.fileno())
                key = (stat.st_dev, stat.st_ino)
                row = db.execute("SELECT offset FROM cursor WHERE device=? AND inode=?", key).fetchone()
                offset = row[0] if row and row[0] <= stat.st_size else 0
                stream.seek(offset)
                while line := stream.readline():
                    if not line.endswith(b"\n"):
                        break
                    offset = stream.tell()
                    try:
                        event = json.loads(line)
                        req = event["request"]
                        host = req["host"].lower().split(":")[0].rstrip(".")
                        if host not in HOSTS:
                            continue
                        path = req.get("uri", "").partition("?")[0]
                        method = req["method"]
                        method = method if method in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} else "OTHER"
                        code = int(event["status"])
                        status = f"{code // 100}xx" if 100 <= code < 600 else "other"
                        client = "bot" if event.get("pf_client") == "bot" else "other"
                        day = datetime.fromtimestamp(event["ts"], UTC).date().isoformat()
                        group = event.get("pf_route") or endpoint(host, path)
                        db.execute("INSERT INTO daily VALUES (?,?,?,?,?,?,1) ON CONFLICT DO UPDATE SET count=count+1",
                                   (day, host, group, method, status, client))
                        size = event.get("size", 0)
                        source = event.get("pf_product")
                        if source is None and ARTIFACT.search(path) and not path.endswith("/meta.7z") and "/metadata/" not in path:
                            source = (
                                "android" if "/android/" in path else "cli" if "/cli/" in path
                                else "website" if path.startswith("/downloads/")
                                else "qt" if path.startswith("/repo/") else "standalone"
                            )
                        if (group == "download" and method == "GET" and code in {200, 206} and size > 0
                                and source in {"android", "cli", "website", "qt", "standalone"}):
                            # Only the day and product class are stored. Range responses are separate requests.
                            db.execute(
                                "INSERT INTO downloads VALUES (?,?,?,1,?,?) ON CONFLICT DO UPDATE SET "
                                "requests=requests+1,ranges=ranges+excluded.ranges,bytes=bytes+excluded.bytes",
                                (day, source, source, int(code == 206), size),
                            )
                    except (ValueError, OSError, OverflowError, KeyError, TypeError):
                        continue
                db.execute("INSERT OR REPLACE INTO cursor VALUES (?,?,?)", (*key, offset))
        cutoff = (now.date() - timedelta(days=400)).isoformat()
        db.execute("DELETE FROM daily WHERE day<?", (cutoff,))
        db.execute("DELETE FROM downloads WHERE day<?", (cutoff,))
        if log.is_file():
            db.execute("INSERT OR REPLACE INTO metadata VALUES ('generated_at',?)", (now.isoformat(),))


def snapshot(database, days=90):
    cutoff = (datetime.now(UTC).date() - timedelta(days=days - 1)).isoformat()
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        result = dict(db.execute("SELECT key,value FROM metadata"))
        for key, table in (("rows", "daily"), ("downloads", "downloads")):
            result[key] = [dict(row) for row in db.execute(f"SELECT * FROM {table} WHERE day>=? ORDER BY day", (cutoff,))]
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    parser.add_argument("database", type=Path)
    args = parser.parse_args()
    collect(args.log, args.database)
