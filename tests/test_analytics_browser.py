"""Check that rendered website pages do not initiate analytics in the browser."""

import os
from pathlib import Path
from urllib.parse import urlsplit
from tempfile import TemporaryDirectory
from unittest.mock import patch
from pf_server.aggregate_analytics import AggregateCounters

from _support import ServerTestCase, main


class BrowserAnalyticsTest(ServerTestCase):
    def test_public_navigation_has_no_beacons_or_analytics_storage(self):
        from playwright.sync_api import sync_playwright
        origin = main.app.config["APP_DOMAIN"]
        with sync_playwright() as playwright:
            executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE", playwright.chromium.executable_path)
            if not Path(executable).exists():
                self.skipTest("Playwright Chromium is not installed")
            browser = playwright.chromium.launch(executable_path=executable)
            page = browser.new_page()
            requests = []
            client = main.app.test_client(use_cookies=False)

            def serve(route):
                path = urlsplit(route.request.url).path
                response = client.get(path, base_url=origin)
                route.fulfill(status=response.status_code, body=response.data, content_type=response.content_type)

            page.route(f"{origin}/**", serve)
            page.on("request", lambda request: requests.append(urlsplit(request.url).path))
            with TemporaryDirectory() as directory, patch.dict(
                main.app.extensions, aggregate_analytics=AggregateCounters(Path(directory) / "counts.sqlite3")
            ), patch.dict(main.app.config, WEBSITE_REQUEST_ANALYTICS_ENABLED=True):
                page.goto(f"{origin}/download")
                page.get_by_role("link", name="Help", exact=True).last.click()
                page.wait_for_url("**/help")
            self.assertFalse(any(path.startswith(("/_metrics/", "/__eaf/")) for path in requests))
            self.assertEqual(page.evaluate("sessionStorage.length"), 0)
            self.assertEqual(page.evaluate("Object.keys(localStorage).filter(k => /analytics|visit|track/i.test(k))"), [])
