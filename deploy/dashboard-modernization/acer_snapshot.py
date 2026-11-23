"""Export release inventory and counters for the existing authenticated Acer agent."""
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from traffic import collect, snapshot
import update_admin

BASE = Path("/var/lib/pf-dashboard-reporting")
LOG = Path("/var/lib/caddy/dashboard-traffic-redacted.json")


def write(name, data):
    fd, temporary = tempfile.mkstemp(dir=BASE)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(data, stream, separators=(",", ":"))
        os.replace(temporary, BASE / name)
    finally:
        Path(temporary).unlink(missing_ok=True)


def run():
    database = BASE / "http.sqlite3"
    collect(LOG, database)
    write("traffic.json", snapshot(database))
    try:
        items = update_admin.inventory()
    except (OSError, ValueError, KeyError, TypeError):
        return
    write("inventory.json", dict(items=items, generated_at=datetime.now(UTC).isoformat(), read_only=True))


if __name__ == "__main__":
    run()
