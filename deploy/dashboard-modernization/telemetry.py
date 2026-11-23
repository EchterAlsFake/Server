"""Fetch the existing fleet monitor using its pinned certificate."""
import json
import os
import ssl
import tempfile
from pathlib import Path
from urllib.request import Request, urlopen

BASE = Path("/var/lib/pornfetch/dashboard-reporting")
TARGET = "https://202.181.177.181:8443/v1/health"


def refresh():
    token = Path("/etc/infra-monitor/token").read_text().strip()
    context = ssl.create_default_context(cafile="/etc/infra-monitor/vps-monitor.crt")
    with urlopen(Request(TARGET, headers={"Authorization": f"Bearer {token}"}),
                 context=context, timeout=8) as response:
        raw = response.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("Fleet monitor response too large")
    payload = json.loads(raw)
    if not isinstance(payload.get("timestamp"), int):
        raise ValueError("Invalid fleet snapshot")
    fd, name = tempfile.mkstemp(dir=BASE)
    try:
        with os.fdopen(fd, "w") as target:
            json.dump(payload, target, separators=(",", ":"))
            os.fchown(target.fileno(), BASE.stat().st_uid, BASE.stat().st_gid)
        os.replace(name, BASE / "fleet.json")
    finally:
        Path(name).unlink(missing_ok=True)


if __name__ == "__main__":
    refresh()
