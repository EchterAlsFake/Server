"""Run the PocketBase error-log contract against an isolated temporary database."""

import http.client
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time
import unittest
import itertools
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager


@contextmanager
def database_connection(path):
    connection = sqlite3.connect(path)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


ROOT = Path(__file__).resolve().parent
POCKETBASE_BIN = Path(os.environ.get("POCKETBASE_BIN", "/srv/pocketbase/pocketbase"))


class ErrorLogIntegrationTests(unittest.TestCase):
    clients = itertools.count(1)
    @classmethod
    def setUpClass(cls):
        if not POCKETBASE_BIN.is_file():
            raise unittest.SkipTest(f"PocketBase binary not found: {POCKETBASE_BIN}")

        cls.temporary_directory = tempfile.TemporaryDirectory(prefix="eaf-pocketbase-test-")
        cls.data_directory = Path(cls.temporary_directory.name) / "data"
        cls.data_directory.mkdir()
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            cls.port = probe.getsockname()[1]

        cls.process = subprocess.Popen(
            [
                str(POCKETBASE_BIN),
                "serve",
                f"--http=127.0.0.1:{cls.port}",
                f"--dir={cls.data_directory}",
                f"--hooksDir={ROOT / 'pb_hooks'}",
                f"--migrationsDir={ROOT / 'pb_migrations'}",
                "--automigrate=false",
                "--dev=false",
                "--hooksWatch=false",
                "--indexFallback=false",
                "--origins=https://api.echteralsfake.me",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for _ in range(100):
            try:
                connection = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=0.2)
                connection.request("GET", "/api/health")
                response = connection.getresponse()
                response.read()
                connection.close()
                if response.status == 200:
                    break
            except OSError:
                pass
            if cls.process.poll() is not None:
                raise RuntimeError(cls.process.stdout.read())
            time.sleep(0.05)
        else:
            raise RuntimeError("PocketBase did not become healthy")
        # Health succeeds even if JS hook registration failed.
        status, _ = cls().request('{"invalid":true}', forwarded_for="192.0.2.250")
        if status != 400:
            cls.process.terminate()
            raise RuntimeError(f"Error hook not available: {status} {cls.process.communicate()[0]}")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "process"):
            cls.process.terminate()
            output = cls.process.communicate(timeout=10)[0]
            if "failed to execute" in output or "synthetic-credential" in output:
                raise AssertionError("Hook failure or diagnostic data in process logs")
        if hasattr(cls, "temporary_directory"):
            cls.temporary_directory.cleanup()

    def request(self, body, *, content_type="application/json", forwarded_for=None, chunked=False,
                path="/error_log", extra_headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        forwarded_for = forwarded_for or f"198.51.100.{next(self.clients)}"
        headers = {"Content-Type": content_type, "X-Forwarded-For": forwarded_for}
        headers.update(extra_headers or {})
        if chunked:
            headers["Transfer-Encoding"] = "chunked"
            body = [body.encode() if isinstance(body, str) else body]
        connection.request("POST", path, body=body, headers=headers, encode_chunked=chunked)
        response = connection.getresponse()
        result = response.status, response.read()
        connection.close()
        return result

    def messages(self):
        with database_connection(self.data_directory / "data.db") as database:
            return [row[0] for row in database.execute("SELECT message FROM error_logs ORDER BY created")]

    def test_valid_message_is_redacted_and_nothing_else_is_stored(self):
        message = (
            "failed for person@example.com from 192.0.2.4 and 2001:db8::1 "
            "url=https://example.test/path?token=visible "
            "Authorization: Bearer credential Cookie: session=private secret=visible"
        )
        status, body = self.request(json.dumps({"message": message}))

        self.assertEqual((status, body), (204, b""))
        stored = self.messages()[-1]
        for private_value in (
            "person@example.com",
            "192.0.2.4",
            "2001:db8::1",
            "token=visible",
            "credential",
            "session=private",
            "secret=visible",
        ):
            self.assertNotIn(private_value, stored)
        self.assertIn("[REDACTED_EMAIL]", stored)
        self.assertIn("[REDACTED_IP]", stored)

        with database_connection(self.data_directory / "data.db") as database:
            columns = {row[1] for row in database.execute("PRAGMA table_info(error_logs)")}
            self.assertEqual(columns, {"id", "message", "created", "updated"})
        for database_path in self.data_directory.glob("*.db"):
            self.assertNotIn(b"198.51.100.7", database_path.read_bytes())

    def test_invalid_payloads_are_rejected_without_storage(self):
        before = len(self.messages())
        cases = [
            ("not json", "application/json"),
            (json.dumps({}), "application/json"),
            (json.dumps({"message": 123}), "application/json"),
            (json.dumps({"message": "ok", "telemetry": "forbidden"}), "application/json"),
            (json.dumps({"message": " "}), "application/json"),
            (json.dumps({"message": "x" * 2001}), "application/json"),
            (json.dumps({"message": "ok"}), "text/plain"),
        ]
        for body, content_type in cases:
            with self.subTest(body=body[:40], content_type=content_type):
                status, _ = self.request(body, content_type=content_type)
                self.assertIn(status, {400, 413, 415})
        self.assertEqual(len(self.messages()), before)

    def test_rate_limit_is_per_transient_forwarded_address(self):
        before = len(self.messages())
        statuses = [
            self.request(
                json.dumps({"message": f"rate test {index}"}),
                forwarded_for="203.0.113.88",
            )[0]
            for index in range(11)
        ]

        self.assertEqual(statuses[:10], [204] * 10)
        self.assertEqual(statuses[10], 429)
        self.assertEqual(len(self.messages()), before + 10)
        for database_path in self.data_directory.glob("*.db"):
            self.assertNotIn(b"203.0.113.88", database_path.read_bytes())

    def test_collection_apis_are_not_public(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        connection.request("GET", "/api/collections/error_logs/records")
        response = connection.getresponse()
        response.read()
        connection.close()
        self.assertEqual(response.status, 403)

    def test_quoted_credentials_and_url_credentials_are_redacted(self):
        cases = [
            ('{"password": "synthetic one two"}', "synthetic"),
            ("access_token='synthetic token value'", "synthetic"),
            ('Authorization: Bearer synthetic-value', "synthetic"),
            ('{"Authorization": "Bearer synthetic-value"}', "synthetic"),
            ('license_key=synthetic-license', "synthetic"),
            ('https://synthetic-user:synthetic-password@example.test/private#synthetic-token', "synthetic"),
            ('pa\x00ssword=synthetic-password', "synthetic"),
        ]
        for message, private in cases:
            with self.subTest(message=message):
                self.assertEqual(self.request(json.dumps({"message": message}))[0], 204)
                self.assertNotIn(private, self.messages()[-1])

    def test_redaction_expansion_is_bounded_and_empty_result_rejected(self):
        self.assertEqual(self.request(json.dumps({"message": "a@b.co " * 280}))[0], 204)
        self.assertLessEqual(len(self.messages()[-1]), 2000)
        before = len(self.messages())
        self.assertEqual(self.request('{"message":"\\u0000\\u0001"}')[0], 400)
        self.assertEqual(len(self.messages()), before)

    def test_oversized_chunked_valid_prefix_is_rejected(self):
        prefix = json.dumps({"message": "synthetic oversized body"})
        body = prefix + " " * (4096 - len(prefix)) + "trailing data"
        before = len(self.messages())
        self.assertEqual(self.request(body, chunked=True)[0], 413)
        self.assertEqual(len(self.messages()), before)

    def test_exact_byte_boundary_and_utf8(self):
        body = json.dumps({"message": "boundary"})
        self.assertEqual(self.request(body + " " * (4096 - len(body)), chunked=True)[0], 204)
        self.assertEqual(self.request(body + " " * (4097 - len(body)))[0], 413)
        self.assertEqual(self.request(json.dumps({"message": "é" * 1900}, ensure_ascii=False).encode())[0], 204)
        self.assertEqual(self.request(json.dumps({"message": "漢" * 1500}, ensure_ascii=False).encode())[0], 413)

    def test_queries_and_signups_rejected(self):
        self.assertEqual(self.request('{"message":"synthetic"}', path="/error_log?token=synthetic-credential")[0], 400)
        self.assertEqual(self.request(
            '{"email":"synthetic@example.test","password":"synthetic-password","passwordConfirm":"synthetic-password"}',
            path="/api/collections/users/records",
        )[0], 403)

    def test_storage_capacity_preserves_existing_rows(self):
        # Only this disposable test database is populated/cleared.
        with database_connection(self.data_directory / "data.db") as db:
            trigger = db.execute("SELECT sql FROM sqlite_master WHERE name='error_logs_capacity'").fetchone()[0]
            db.execute("DROP TRIGGER error_logs_capacity")
            db.execute("DELETE FROM error_logs")
            db.execute("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<100000) INSERT INTO error_logs(id,message) SELECT printf('%015d',x),'capacity fixture' FROM n")
            db.execute(trigger)
        try:
            self.assertEqual(self.request('{"message":"synthetic capacity test"}')[0], 503)
            with database_connection(self.data_directory / "data.db") as db:
                self.assertEqual(db.execute("SELECT count(*) FROM error_logs").fetchone()[0], 100000)
        finally:
            with database_connection(self.data_directory / "data.db") as db:
                db.execute("DELETE FROM error_logs")

    def test_z_global_limiter_is_atomic_and_logs_stay_empty(self):
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=16) as pool:
            statuses = list(pool.map(lambda i: self.request(
                '{"invalid":true}', forwarded_for=f"2001:db8::{i:x}",
                extra_headers={"Authorization": "Bearer synthetic-credential", "Cookie": "synthetic-cookie"},
            )[0], range(200)))
        elapsed = time.monotonic() - started
        self.assertTrue(set(statuses) <= {400, 429}, set(statuses))
        self.assertIn(429, statuses)
        self.assertLessEqual(statuses.count(400), 120 + int(elapsed * 2))
        with database_connection(self.data_directory / "auxiliary.db") as db:
            self.assertEqual(db.execute("SELECT count(*) FROM _logs").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
