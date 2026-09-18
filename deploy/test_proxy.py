"""Exercise the staged routes on loopback, without touching production Caddy."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
import time


class Backend(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.do_GET()

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Test-Port", str(self.server.server_port))
        self.end_headers()
        self.wfile.write(json.dumps(dict(self.headers)).encode())

    def log_message(self, *args):
        pass


def main():
    servers = [ThreadingHTTPServer(("127.0.0.1", 0), Backend) for _ in range(6)]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    draft = Path(__file__).with_name("managed-sites.caddy").read_text()
    draft = re.sub(r"(?m)^([a-z][a-z0-9., ]*echteralsfake\.me[^\n{]*) \{$",
                   lambda match: ", ".join("http://" + host.strip() + f":{port}"
                                           for host in match[1].split(",")) + " {", draft)
    for original, server in zip((8000, 8001, 8002, 8090, 8010, 8005), servers):
        draft = draft.replace(f"127.0.0.1:{original}", f"127.0.0.1:{server.server_port}")
    draft = "{\n admin off\n auto_https off\n default_bind 127.0.0.1\n}\n" + draft
    try:
        with tempfile.TemporaryDirectory(prefix="eaf-proxy-check-") as directory:
            config = Path(directory) / "Caddyfile"
            config.write_text(draft)
            with (Path(directory) / "caddy.log").open("w+") as log:
                process = subprocess.Popen(
                    ["/usr/local/bin/caddy-desec", "run", "--config", str(config), "--adapter", "caddyfile"],
                    stdout=log, stderr=log,
                    env=os.environ | {"XDG_DATA_HOME": directory, "XDG_CONFIG_HOME": directory},
                )
                try:
                    for _ in range(50):
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                                break
                        except OSError:
                            if process.poll() is not None:
                                log.seek(0)
                                raise RuntimeError(log.read())
                            time.sleep(.1)
                    def request(host, path="/", method="GET", body=None):
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                        connection.request(method, path, body=body, headers={
                            "Host": host, "X-Forwarded-For": "203.0.113.77",
                            "CF-Connecting-IP": "203.0.113.77", "X-Real-IP": "203.0.113.77",
                            "True-Client-IP": "203.0.113.77", "Forwarded": "for=203.0.113.77",
                            "X-Forwarded-Host": "attacker.invalid",
                            "X-Forwarded-Prefix": "/attacker", "X-Forwarded-Proto": "http",
                            "Content-Type": "application/json",
                            "Authorization": "Bearer synthetic-credential",
                            "Cookie": "session=synthetic-cookie",
                            "Origin": "https://private.invalid",
                            "Referer": "https://private.invalid/?secret=synthetic",
                        })
                        response = connection.getresponse()
                        result = response.status, dict(response.getheaders()), response.read()
                        connection.close()
                        return result
                    for host in ("echteralsfake.me", "docs.echteralsfake.me",
                                 "api.echteralsfake.me", "vplan.echteralsfake.me"):
                        status, headers, body = request(host)
                        assert status == 200, (host, status)
                        upstream = {k.lower(): v for k, v in json.loads(body).items()}
                        assert upstream["x-forwarded-for"] == "127.0.0.1", upstream
                        assert upstream["x-forwarded-host"] == host
                        assert upstream["x-forwarded-proto"] == "https"
                        assert upstream["host"] == host
                        for key in ("forwarded", "x-real-ip", "true-client-ip", "x-forwarded-prefix"):
                            assert key not in upstream, key
                        if host.startswith("vplan."):
                            assert upstream["cf-connecting-ip"] == "127.0.0.1"
                        else:
                            assert "cf-connecting-ip" not in upstream
                        assert headers.get("Referrer-Policy") == "no-referrer"
                        assert headers.get("Cache-Control") == "no-store"
                        assert "Server" not in headers
                    assert request("echteralsfake.me", "/killswitch")[0] == 404
                    status, headers, body = request("api.echteralsfake.me", "/error_log", "POST", '{"message":"synthetic"}')
                    assert status == 200
                    assert headers["X-Test-Port"] == str(servers[3].server_port)
                    upstream = {k.lower(): v for k, v in json.loads(body).items()}
                    assert upstream["x-forwarded-for"] == "127.0.0.1"
                    assert upstream["user-agent"] == "EAF-Error-Relay"
                    for key in ("authorization", "cookie", "origin", "referer", "forwarded", "x-real-ip", "cf-connecting-ip"):
                        assert key not in upstream, key
                    for method in ("GET", "OPTIONS", "PUT"):
                        assert request("api.echteralsfake.me", "/error_log", method)[0] == 405
                    for host in ("echteralsfake.me", "docs.echteralsfake.me"):
                        status, headers, _ = request(host, "/error_log", "POST", '{"message":"synthetic"}')
                        assert status == 200
                        assert headers["X-Test-Port"] == str(servers[0].server_port)
                    for host in ("echteralsfake.me", "docs.echteralsfake.me", "vplan.echteralsfake.me"):
                        status, headers, _ = request(host, "/__eaf/visit", "POST", '{"route":"test"}')
                        assert status == 200
                        assert headers["X-Test-Port"] == str(servers[4].server_port)
                    status, headers, _ = request("echteralsfake.me", "/dashboard/")
                    assert status == 200
                    assert headers["X-Test-Port"] == str(servers[4].server_port)
                    status, headers, _ = request("echteralsfake.me", "/dashboard/keygen/licenses")
                    assert status == 200
                    assert headers["X-Test-Port"] == str(servers[5].server_port)
                    status, headers, _ = request("docs.echteralsfake.me", "/dashboard/")
                    assert status == 200
                    assert headers["X-Test-Port"] == str(servers[0].server_port)
                    status, headers, _ = request("www.echteralsfake.me", "/docs/?a=b")
                    assert status == 308
                    assert headers["Location"] == "https://echteralsfake.me/docs/?a=b"
                    assert request("mcp.echteralsfake.me")[0] == 404
                    status, headers, body = request("mcp.echteralsfake.me", "/mcp")
                    assert status == 200
                    upstream = {k.lower(): v for k, v in json.loads(body).items()}
                    assert upstream["x-forwarded-for"] == "127.0.0.1"
                    assert upstream["x-forwarded-host"] == "mcp.echteralsfake.me"
                    assert upstream["x-forwarded-proto"] == "https"
                    assert "cf-connecting-ip" not in upstream
                    assert headers.get("Referrer-Policy") == "no-referrer"
                    assert "Server" not in headers
                    print("Proxy checks passed: app and MCP routes, spoofed headers, security headers, redirect, and killswitch.")
                finally:
                    process.terminate()
                    process.wait(timeout=10)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
