"""Local provider-progress checks using synthetic orders and mocked provider APIs."""

import argparse
import sys
import threading
from pathlib import Path
from unittest.mock import patch

from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tests"))
sys.path.insert(0, str(root))
from test_payment_progress import PaymentProgressTests, main
from pf_server.models import Transaction


def run(browser_name="chromium"):
    fixture = PaymentProgressTests()
    fixture.setUp()
    fixture.add(card=True)
    main.app.config["WTF_CSRF_ENABLED"] = True
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
    errors = []
    try:
        with sync_playwright() as p:
            browser = getattr(p, browser_name).launch()
            context = browser.new_context(
                ignore_https_errors=True, viewport={"width": 1440, "height": 1000}
            )
            context.route(
                "**/*",
                lambda route: (
                    route.continue_()
                    if route.request.url.startswith(origin)
                    else route.abort()
                ),
            )
            page = context.new_page()
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(origin + "/buy_success?session_id=NP-test")
            page.locator("#adult-confirmed").check()
            page.get_by_role("button", name="Confirm & enter").click()
            expect(page.locator("#payment-tracker")).to_have_attribute(
                "data-stage", "provider"
            )
            expect(page.locator("#payment-progress-steps li")).to_have_count(6)
            expect(page.locator("#success-container")).not_to_be_visible()
            fixture.onramp_response = {"status": "paid", "value_coin": "24"}
            fixture.reset_poll()
            page.locator("#refresh-progress").click()
            expect(page.locator("#payment-tracker")).to_have_attribute(
                "data-stage", "onramp"
            )
            expect(page.locator("#payment-progress-title")).to_have_text(
                "Onramp Pay received crypto"
            )
            fixture.onramp_response["txid_out"] = "0x" + "c" * 64
            fixture.reset_poll()
            page.locator("#refresh-progress").click()
            expect(page.locator("#payment-tracker")).to_have_attribute(
                "data-stage", "forwarding"
            )
            page.screenshot(path="/tmp/porn-fetch-payment-progress.png", full_page=True)
            fixture.now_state = "confirming"
            fixture.reset_poll()
            page.locator("#refresh-progress").click()
            expect(page.locator("#payment-tracker")).to_have_attribute(
                "data-stage", "blockchain"
            )
            expect(page.locator('[aria-current="step"]')).to_contain_text(
                "Blockchain confirmations"
            )
            fixture.failure = True
            fixture.reset_poll()
            page.locator("#refresh-progress").click()
            expect(page.locator("#provider-status-note")).to_contain_text(
                "temporarily unavailable"
            )
            expect(page.locator("#payment-tracker")).to_have_attribute(
                "data-stage", "blockchain"
            )
            fixture.failure = False
            fixture.now_state = "finished"
            fixture.reset_poll()
            page.locator("#refresh-progress").click()
            expect(page.locator("#payment-tracker")).to_have_attribute(
                "data-stage", "license"
            )
            expect(page.locator("#success-container")).not_to_be_visible()
            with main.app.app_context():
                assert main.db.session.get(Transaction, "NP-test").status == "pending"
            assert fixture.ipn(fixture.event(state="finished")).status_code == 200
            page.locator("#refresh-progress").click()
            expect(page.locator("#success-container")).to_be_visible()
            expect(page.locator("#payment-tracker")).to_have_attribute(
                "data-stage", "finished"
            )
            expect(page.locator("#card-license-key")).to_contain_text("key/")
            page.set_viewport_size({"width": 390, "height": 844})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path="/tmp/porn-fetch-progress-mobile.png", full_page=True)
            assert not errors, errors
            browser.close()
            print(
                f"{browser_name}: received, forwarded, blockchain, stale provider, API-only completion and signed receipt passed"
            )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        fixture.tearDown()
        fixture.doCleanups()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", default="chromium")
    run(parser.parse_args().browser)
