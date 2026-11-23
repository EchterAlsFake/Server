"""Privacy boundary and aggregate reporting regression tests."""

import json
import sqlite3
import tempfile
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from _support import ServerTestCase, main
from pf_server.aggregate_analytics import AggregateCounters, FEEDBACK_ENDPOINT, week_start, utc_today


class AggregateAnalyticsTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = AggregateCounters(Path(temporary.name) / "counts.sqlite3")
        self.enterContext(patch.dict(main.app.extensions, aggregate_analytics=self.store))
        self.enterContext(patch.dict(main.app.config, WEBSITE_REQUEST_ANALYTICS_ENABLED=True))
        self.browser = main.app.test_client(use_cookies=False)
        self.origin = main.app.config["APP_DOMAIN"]

    def rows(self):
        with closing(self.store.connect()) as db:
            return db.execute("SELECT series,count FROM counts ORDER BY series").fetchall()

    def test_pages_count_without_embedded_analytics(self):
        for path in ("/download", "/de/download", "/download/windows", "/guides/download-xvideos-videos"):
            response = self.browser.get(path, base_url=self.origin, headers={
                "Referer": "https://opaque.invalid/private?account=secret",
                "X-Forwarded-For": "192.0.2.4",
            })
            self.assertEqual(response.status_code, 200)
            self.assertNotIn(b"aggregate-analytics.js", response.data)
            self.assertNotIn(b"/__eaf/visit", response.data)
        self.assertEqual(self.rows(), [("download", 2), ("download_windows", 1), ("guide_xvideos", 1)])
        with closing(sqlite3.connect(self.store.path)) as db:
            self.assertEqual([item[1] for item in db.execute("PRAGMA table_info(counts)")], ["day", "series", "count"])
            self.assertNotIn("192.0.2.4", "\n".join(db.iterdump()))
            self.assertNotIn("account=secret", "\n".join(db.iterdump()))

    def test_excludes_legacy_checkout_files_head_and_prefetch(self):
        self.assertEqual(self.browser.post("/_metrics/event", json={"page": "home"}, base_url=self.origin).status_code, 404)
        for path in ("/buy_license", "/payment-preview/patreon", "/activate", "/static/site.css",
                     "/downloads/missing.exe", "/missing-page", "/guides/unknown"):
            self.browser.get(path, base_url=self.origin)
        for method, header in (
            ("HEAD", {}), ("GET", {"Sec-Purpose": "prefetch"}), ("GET", {"Purpose": "prefetch"}),
            ("GET", {"Sec-GPC": "1"}), ("GET", {"DNT": "1"}),
        ):
            self.browser.open("/download", method=method, base_url=self.origin, headers=header)
        self.browser.get("/download", base_url=main.app.config["ONION_ORIGIN"])
        self.assertFalse(self.store.path.exists())

    def test_disabled_flag_cannot_inherit_legacy_setting(self):
        with patch.dict(main.app.config, WEBSITE_REQUEST_ANALYTICS_ENABLED=False, AGGREGATE_ANALYTICS_ENABLED=True):
            response = self.browser.get("/download", base_url=self.origin)
            self.assertNotIn(b"website-feedback", response.data)
            self.assertEqual(self.send({"answer": "platform", "language": "en"}).status_code, 404)
        self.assertFalse(self.store.path.exists())

    def send(self, data, **kwargs):
        headers = kwargs.pop("headers", {"Origin": self.origin, "Sec-Fetch-Site": "same-origin"})
        return self.browser.post(FEEDBACK_ENDPOINT, data=data, base_url=self.origin, headers=headers, **kwargs)

    def test_feedback_only_counts_explicit_valid_submissions(self):
        self.assertEqual(self.send({"answer": "platform", "language": "en"}, headers={}).status_code, 403)
        self.assertEqual(self.send({"answer": "platform", "language": "en"}, headers={"Origin": self.origin, "DNT": "1"}).status_code, 404)
        for invalid in (
            {"answer": "user@example.invalid", "language": "en"},
            {"answer": ["platform", "support"], "language": "en"},
            {"answer": "installation", "language": ["en", "de"]},
            {"answer": "installation", "language": "en", "comment": "text"},
        ):
            self.assertEqual(self.send(invalid).status_code, 400)
        self.assertFalse(self.store.path.exists())
        response = self.send({"answer": "installation", "language": "de"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Danke", response.data)
        self.assertNotIn("Set-Cookie", response.headers)
        self.assertEqual(self.rows(), [("feedback_installation", 1)])

    def test_closed_week_counts_use_complementary_suppression_and_expire(self):
        this_week = week_start(utc_today())
        last_week = this_week - timedelta(days=7)
        earlier = last_week - timedelta(days=1)
        rows = [(last_week, "download", 56), (last_week + timedelta(days=1), "download", 3),
                (last_week, "premium", 25), (last_week + timedelta(days=1), "premium", 25),
                (last_week, "help", 19), (this_week, "home", 100),
                (earlier - timedelta(weeks=26), "home", 100)]
        with closing(self.store.connect()) as db, db:
            db.executemany("INSERT INTO counts VALUES (?,?,?)",
                           [(day.isoformat(), series, count) for day, series, count in rows])
        report = self.store.report(True)
        self.assertEqual(report["end_exclusive"], this_week.isoformat())
        self.assertEqual({row["series"]: (row["count"], row["daily_available"]) for row in report["weekly"]},
                         {"download": (59, False), "premium": (50, True)})
        self.assertEqual({row["series"] for row in report["daily"]}, {"premium"})
        self.assertNotIn("countries", report)
        self.assertFalse(self.store.purge())
        self.assertEqual(json.loads(json.dumps(report))["schema_version"], 3)
