"""Exercise the onion Caddy fragment locally without Tor or production services."""
import argparse
import json
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = "pornfetchc5ct7s7uiervf4ziymmus5gy33gyqc6vkdtqyr5pbxrxmid.onion"


def run(binary):
    calls = []

    class Backend(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append((self.path, dict(self.headers)))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"local synthetic backend")

        do_POST = do_GET

        def log_message(self, *_):
            pass

    backend = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    worker = threading.Thread(target=backend.serve_forever, daemon=True)
    worker.start()
    try:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public = root / "public/3.9.77"
            public.mkdir(parents=True)
            (public / "test.zip").write_bytes(b"test download")
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            config = (Path(__file__).resolve().parents[1] / "deploy/pornfetch-onion.caddy").read_text()
            local = f"127.0.0.1:{backend.server_port}"
            config = config.replace(":18081", f":{port}").replace("127.0.0.1:18080", local)
            config = config.replace("https://licenses.pornfetch.to", "http://" + local).replace("https://api.pornfetch.to", "http://" + local)
            config = config.replace("/srv/pornfetch-downloads", str(root))
            path = root / "Caddyfile"
            path.write_text("{\n admin off\n auto_https off\n}\n" + config)
            with (root / "caddy.log").open("w") as log:
                process = subprocess.Popen([binary, "run", "--config", str(path), "--adapter", "caddyfile"], stdout=log, stderr=log)
                try:
                    def request(path, method="GET", host=HOST, **headers):
                        req = urllib.request.Request(f"http://127.0.0.1:{port}" + path, method=method,
                                                     headers={"Host": host, **headers})
                        try:
                            with urllib.request.urlopen(req, timeout=3) as response:
                                return response.status, response.read()
                        except urllib.error.HTTPError as error:
                            return error.code, error.read()

                    deadline = time.monotonic() + 10
                    while True:
                        try:
                            if request("/downloads/3.9.77/test.zip")[0] == 200:
                                break
                        except urllib.error.URLError:
                            pass
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError((root / "caddy.log").read_text())
                        time.sleep(0.1)
                    assert request("/downloads/3.9.77/test.zip", Range="bytes=0-2") == (206, b"tes")
                    assert request("/downloads/3.9.77/test.zip", host="wrong.invalid")[0] == 404
                    assert request("/porn_fetch", method="POST")[0] == 404
                    assert request("/licensing/v1/accounts/abcd/machines", method="POST", Authorization="License synthetic")[0] == 200
                    assert calls[-1][0] == "/v1/accounts/abcd/machines"
                    assert calls[-1][1]["Host"] == "licenses.pornfetch.to"
                    assert request("/licensing/v1/accounts/abcd/users", Authorization="License synthetic")[0] == 404
                    assert request("/licensing/v1/accounts/abcd/machines", method="POST")[0] == 404
                    assert request("/repo/cli/metadata/root.json")[0] == 200
                    assert request("/repo/cli/metadata/root.json", method="POST")[0] == 404
                    assert request("/")[0] == 200
                    assert calls[-1][1]["X-Forwarded-Host"] == HOST
                    assert calls[-1][1]["X-Forwarded-Proto"] == "http"
                    print("Onion host checks passed: host boundary, read-only routes, license allow-list, streaming and Range downloads.")
                finally:
                    process.terminate()
                    process.wait(timeout=10)
    finally:
        backend.shutdown()
        worker.join(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--caddy", required=True)
    run(parser.parse_args().caddy)
