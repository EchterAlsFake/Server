"""Attach read-only report snapshots to the agent's existing authenticated response."""
import sys
from pathlib import Path

path = Path(sys.argv[1])
code = path.read_text()
marker = 'body = json.dumps(collect()).encode("utf-8")'
replacement = '''payload = collect()
        for key, filename in (("dashboard_traffic", "traffic.json"), ("dashboard_inventory", "inventory.json")):
            try:
                snapshot_file = pathlib.Path("/var/lib/pf-dashboard-reporting") / filename
                with snapshot_file.open("rb") as stream:
                    raw = stream.read(2 * 1024 * 1024 + 1)
                if len(raw) <= 2 * 1024 * 1024:
                    payload[key] = json.loads(raw)
            except (ValueError, OSError):
                pass
        body = json.dumps(payload).encode("utf-8")'''
if marker not in code:
    raise SystemExit("Expected Acer agent response construction was not found")
updated = code.replace(marker, replacement, 1)
compile(updated, str(path), "exec")
path.write_text(updated)
