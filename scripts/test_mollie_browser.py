"""HTTPS Mollie tester UX on desktop/mobile; all external operations mocked."""

import re
import sys
import threading
from pathlib import Path
from unittest.mock import patch

from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tests"))
sys.path.insert(0, str(root))
from test_mollie import MollieTests
from _support import main
from pf_server.extensions import db
from pf_server.mollie_models import MollieCheckout
from pf_server import mollie_service


def run():
    fixture = MollieTests()
    fixture.setUp()
    server = make_server(
        "127.0.0.1",
        0,
        main.app,
        ssl_context="adhoc",
        threaded=True,
        request_handler=main.NoIPLoggingHandler,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"https://localhost:{server.server_port}"
    failures = []
    try:
        with (
            patch.dict(main.app.config, WTF_CSRF_ENABLED=True, APP_DOMAIN=origin),
            sync_playwright() as p,
        ):
            browser = p.chromium.launch()
            context = browser.new_context(
                ignore_https_errors=True, viewport={"width": 1440, "height": 1000}
            )

            def route_request(route):
                if route.request.url.startswith(origin + "/mollie/launch?"):
                    response = route.fetch(max_redirects=0)
                    assert response.status == 303
                    assert response.headers["location"].startswith(
                        "https://www.mollie.com/checkout/"
                    )
                    route.fulfill(
                        status=200,
                        body="<h1>Mock Mollie sandbox checkout</h1>",
                        content_type="text/html",
                    )
                elif route.request.url.startswith(origin + "/"):
                    route.continue_()
                else:
                    route.abort()

            context.route("**/*", route_request)
            page = context.new_page()
            page.on("pageerror", lambda error: failures.append(str(error)))
            page.goto(origin + "/porn_fetch")
            page.locator("#adult-confirmed").check()
            page.locator("#age-form button").click()
            expect(page.locator("#method-patreon")).to_be_visible()
            expect(page.locator("#method-crypto")).to_be_visible()
            expect(page.locator("#tester-password")).not_to_be_visible()
            summary = page.get_by_text("Tester access", exact=True)
            summary.focus()
            page.keyboard.press("Enter")
            page.locator("#tester-password").fill("private-test-password")
            page.get_by_role("button", name="Unlock Mollie test checkout").click()
            expect(page).to_have_url(origin + "/mollie/test")
            for width in (1440, 375):
                page.set_viewport_size({"width": width, "height": 1000})
                assert page.evaluate(
                    "document.documentElement.scrollWidth <= innerWidth"
                ), width
                page.screenshot(path=f"/tmp/mollie-review-{width}.png", full_page=True)
            page.locator("#mollie-email").fill("tester@example.com")
            page.locator("#mollie-country").select_option("DE")
            for name in (
                "age_terms_accepted",
                "withdrawal_accepted",
                "test_acknowledged",
            ):
                page.locator(f'input[name="{name}"]').check()
            page.get_by_role("button", name="Create Mollie test checkout").click()
            expect(page.locator("#recovery-link")).to_be_visible()
            expect(page.locator("#payment-details")).to_contain_text(
                "Mollie sandbox checkout"
            )
            with context.expect_page() as popup:
                page.get_by_role("link", name="Open Mollie test checkout").click()
            expect(popup.value.get_by_role("heading")).to_have_text(
                "Mock Mollie sandbox checkout"
            )
            popup.value.close()
            fixture.status = "paid"
            with main.app.app_context():
                row = MollieCheckout.query.one()
                row.next_attempt_at = mollie_service.now().isoformat()
                db.session.commit()
            page.get_by_role("button", name="Refresh status").click()
            expect(page.locator("#success-container")).to_be_visible(timeout=15000)
            expect(page.locator("#crypto-license-key")).to_have_value(
                re.compile(r"^key/")
            )
            expect(page.locator("#crypto-delivery-status")).to_contain_text("emailed")
            with page.expect_download() as download:
                page.get_by_role("link", name="Download License Key File").click()
            assert download.value.suggested_filename == "porn_fetch.license"
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path="/tmp/mollie-license-ready-mobile.png", full_page=True)
            assert not failures, failures
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
        fixture.tearDown()
        fixture.doCleanups()
    print(
        "Passed: keyboard unlock, desktop/mobile layout, CSRF, hosted checkout, recovery, real-license issuance and email, license download."
    )


if __name__ == "__main__":
    run()
