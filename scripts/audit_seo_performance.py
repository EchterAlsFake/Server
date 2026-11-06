"""Record fresh mobile Lighthouse results; does not change website configuration.

Example: python scripts/audit_seo_performance.py --lighthouse /path/to/lighthouse
Set CHROME_PATH to your Chromium executable if it is not discoverable.
The output contains lab observations, not field INP or installation counts.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile

PATHS = ("/", "/guides/download-xvideos-videos", "/guides/download-xhamster-videos",
         "/download", "/download/android", "/download/ios")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", default="https://pornfetch.to")
    parser.add_argument("--lighthouse", default="lighthouse")
    parser.add_argument("--output", type=Path, default=Path("/tmp/pornfetch-seo-performance.json"))
    args = parser.parse_args()
    rows = []
    for path in PATHS:
        with tempfile.TemporaryDirectory(prefix="seo-lighthouse-") as work:
            report = Path(work) / "report.json"
            subprocess.run([args.lighthouse, args.origin.rstrip("/") + path,
                            "--output=json", "--output-path=" + str(report),
                            "--only-categories=performance,accessibility,seo",
                            "--chrome-flags=--headless --no-sandbox", "--quiet"],
                           check=True, timeout=180)
            data = json.loads(report.read_text())
            audits = data["audits"]
            rows.append({"path": path, "finalUrl": data.get("finalDisplayedUrl", data.get("finalUrl")),
                         "scores": {k: v["score"] for k, v in data["categories"].items()},
                         "metrics": {k: audits[k].get("numericValue") for k in (
                             "largest-contentful-paint", "cumulative-layout-shift",
                             "total-blocking-time", "total-byte-weight")},
                         "warnings": data.get("runWarnings", [])})
            result = {"measuredAt": datetime.now(timezone.utc).isoformat(),
                      "origin": args.origin, "lighthouseVersion": data["lighthouseVersion"],
                      "settings": data["configSettings"], "pages": rows}
            args.output.write_text(json.dumps(result, indent=2) + "\n")
            print(path, rows[-1]["scores"], flush=True)


if __name__ == "__main__":
    main()
