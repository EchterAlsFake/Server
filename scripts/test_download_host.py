"""Exercise the actual product Caddy file handler using temporary inert files.

Pass --caddy /path/to/caddy. Does not bind production domains or reload services.
"""

import argparse
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def run(binary):
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="pornfetch-download-host-") as temporary:
        folder = Path(temporary)
        public = folder / "public"
        (public / "3.9.66").mkdir(parents=True)
        content = b"synthetic published binary; no executable content"
        (public / "3.9.66/package.zip").write_bytes(content)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        # Use the unchanged production download handler, with a local address/root.
        site = (root / "deploy/pornfetch-site.caddy").read_text()
        site = site[: site.index("\nwww.pornfetch.to")]
        site = site.replace("pornfetch.to {", f"http://127.0.0.1:{port} {{", 1)
        site = site.replace("/srv/pornfetch-downloads/public", str(public))
        defaults = (
            (root / "deploy/managed-sites.caddy")
            .read_text()
            .split("(application_defaults) {", 1)[1]
            .split("\nechteralsfake.me", 1)[0]
        )
        config = folder / "Caddyfile"
        config.write_text(
            "{\n admin off\n auto_https off\n}\n(application_defaults) {"
            + defaults
            + "\n"
            + site
        )
        log = folder / "caddy.log"
        with log.open("w") as output:
            process = subprocess.Popen(
                [binary, "run", "--adapter", "caddyfile", "--config", str(config)],
                stdout=output,
                stderr=output,
            )
            try:
                url = f"http://127.0.0.1:{port}/downloads/3.9.66/package.zip"
                deadline = time.monotonic() + 10
                while True:
                    try:
                        response = urllib.request.urlopen(url, timeout=1)
                        break
                    except urllib.error.URLError:
                        if process.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError(log.read_text())
                        time.sleep(0.05)
                with response:
                    assert response.read() == content
                    assert response.headers["X-Robots-Tag"] == "noindex"
                    assert "immutable" in response.headers["Cache-Control"]
                    assert response.headers["Content-Disposition"] == "attachment"
                    etag = response.headers["ETag"]
                with urllib.request.urlopen(
                    urllib.request.Request(url, headers={"Range": "bytes=2-8"}),
                    timeout=2,
                ) as response:
                    assert response.status == 206
                    assert response.read() == content[2:9]
                    assert (
                        response.headers["Content-Range"] == f"bytes 2-8/{len(content)}"
                    )
                with urllib.request.urlopen(
                    urllib.request.Request(url, method="HEAD"), timeout=2
                ) as response:
                    assert int(response.headers["Content-Length"]) == len(content)
                    assert response.read() == b""
                try:
                    urllib.request.urlopen(
                        urllib.request.Request(url, headers={"If-None-Match": etag}),
                        timeout=2,
                    )
                except urllib.error.HTTPError as error:
                    assert error.code == 304
                else:
                    raise AssertionError("Conditional download did not return 304")
                for path in ("missing.zip", ""):
                    try:
                        urllib.request.urlopen(
                            f"http://127.0.0.1:{port}/downloads/3.9.66/" + path,
                            timeout=2,
                        )
                    except urllib.error.HTTPError as error:
                        assert error.code == 404
                        assert "immutable" not in error.headers.get("Cache-Control", "")
                    else:
                        raise AssertionError(
                            "Missing files/directories must not be listed"
                        )
            finally:
                process.terminate()
                process.wait(timeout=5)
    print(
        "Caddy: direct binary download, Range, HEAD, conditional caching, noindex, immutable files and 404/no directory browsing passed"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--caddy", default="caddy")
    run(parser.parse_args().caddy)
