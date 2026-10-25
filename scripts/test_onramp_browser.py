"""Mocked HTTPS browser smoke test; never creates live provider payments.

Run: uv run --with playwright python scripts/test_onramp_browser.py
Install once: uv run --with playwright python -m playwright install chromium
"""

import argparse
import sys
import threading
from pathlib import Path
from unittest.mock import patch

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tests"))
sys.path.insert(0, str(root))

from playwright.sync_api import sync_playwright, expect
from werkzeug.serving import make_server
from test_onramp import OnrampTests, main, service
from pf_server.models import OnrampCheckout


def run(browser_name="chromium"):
    fixture = OnrampTests()
    fixture.setUp()
    main.app.config["WTF_CSRF_ENABLED"] = True
    server = make_server(
        "127.0.0.1",
        0,
        main.app,
        ssl_context="adhoc",
        threaded=True,
        request_handler=main.NoIPLoggingHandler,
    )
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    origin = f"https://localhost:{server.server_port}"
    try:
        with sync_playwright() as playwright:
            browser = getattr(playwright, browser_name).launch()
            context = browser.new_context(
                ignore_https_errors=True, viewport={"width": 1100, "height": 900}
            )

            # No third-party traffic, including the actual payment tab.
            def route_request(route):
                if route.request.url.startswith(origin):
                    route.continue_()
                elif route.request.url.startswith(service.CHECKOUT_BASE):
                    route.fulfill(
                        body="<h1>Mock Banxa checkout</h1>", content_type="text/html"
                    )
                else:
                    route.abort()

            context.route("**/*", route_request)
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(origin + "/porn_fetch")
            page.locator("#adult-confirmed").check()
            page.get_by_role("button", name="Confirm & enter").click()
            expect(page.locator("#age-overlay")).to_have_count(0)
            expect(page.locator("#site-content")).to_have_css("filter", "none")
            expect(page.locator(".payment-detail:visible")).to_have_count(0)
            page.locator("#method-crypto").check()
            expect(page.locator("#method-crypto")).to_be_checked()
            page.locator("#method-card").check()
            expect(page.locator("#method-card")).to_be_checked()
            expect(page.locator("#method-crypto")).not_to_be_checked()
            assert not fixture.requests, "Selecting a payment method must not create provider transactions"
            page.screenshot(path="/tmp/porn-fetch-payment-card-choice.png", full_page=True)
            page.locator("#checkout-country").select_option("DE")
            for checkbox in ("chk-age-terms", "chk-withdrawal", "chk-test-site"):
                page.locator("#" + checkbox).check()
            page.locator("#checkout-continue").click()
            expect(page.locator("#payment-test-dialog")).to_be_visible()
            page.locator("#payment-test-ack").check()
            page.locator("#payment-test-continue").click()
            expect(page).to_have_url(origin + "/buy_card")
            expect(page.locator("#card-review")).to_be_enabled()
            page.set_viewport_size({"width": 1440, "height": 1050})
            sizes = page.locator(".card-brands img").evaluate_all("els => els.map(el => [el.getBoundingClientRect().width, el.getBoundingClientRect().height])")
            assert sizes == [[72, 48], [72, 48], [72, 48]], sizes
            expect(page.locator("#card-review")).to_have_css("background-color", "rgb(241, 139, 176)")
            page.evaluate('window.scrollTo({top: 0, behavior: "instant"})')
            page.screenshot(path="/tmp/porn-fetch-card-desktop.png", full_page=True)
            expect(page.locator(".nowpayments-amount")).to_have_text("€19.99")
            expect(page.locator("#delivery-email")).to_have_attribute("required", "")
            expect(page.locator(".checkout-tax-id")).to_contain_text("requires your Tax ID")
            expect(page.locator(".checkout-disclosure")).to_contain_text("3% Onramp Pay fee")
            expect(page.locator(".checkout-disclosure")).to_contain_text("final quote in USD")
            expect(page.locator(".checkout-question[open]")).to_have_count(0)
            page.get_by_role("link", name="Verification details", exact=True).click()
            expect(page.locator("#card-verification")).to_have_attribute("open", "")
            expect(page.locator("#card-verification summary")).to_be_focused()
            page.keyboard.press("Space")
            expect(page.locator("#card-verification")).not_to_have_attribute("open", "")
            assert not fixture.requests, "Reading FAQs must not create provider transactions"
            page.locator("#main-content").focus()
            for width in (1440, 768, 390, 375):
                page.set_viewport_size({"width": width, "height": 844})
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
                card = page.locator(".checkout-card").bounding_box()
                assert card["width"] <= 480, card
                assert abs(card["x"] + card["width"] / 2 - width / 2) < 1, card
                if width == 375:
                    page.evaluate('window.scrollTo({top: 0, behavior: "instant"})')
                    page.screenshot(path="/tmp/porn-fetch-card-mobile.png", full_page=True)
            page.set_viewport_size({"width": 1100, "height": 900})
            page.locator("#delivery-email").fill("buyer@example.com")
            page.locator("#card-annual").check()
            page.get_by_role(
                "button", name="Continue to secure checkout"
            ).click()
            expect(page.locator("#kyc-dialog")).to_be_visible()
            page.locator("#card-kyc").check()
            expect(page.locator("#kyc-continue")).to_be_disabled()
            page.keyboard.press("Escape")
            expect(page.locator("#kyc-dialog")).not_to_be_visible()
            page.get_by_role(
                "button", name="Continue to secure checkout"
            ).click()
            expect(page.locator("#card-kyc")).not_to_be_checked()
            page.locator("#card-kyc").check()
            expect(page.locator("#kyc-continue")).to_be_disabled()
            expect(page.locator("#kyc-continue")).to_be_enabled(timeout=8000)
            page.screenshot(path="/tmp/onramp-disclosure.png", full_page=True)
            page.locator("#kyc-continue").click()
            page.wait_for_url("**/buy_success?token=*")
            expect(page.get_by_text("Estimated funding amount:")).to_be_visible()
            original_url = page.url
            page.get_by_role("link", name="Open Banxa payment in a new tab").click()
            expect(page.locator("#payment-test-dialog")).to_be_visible()
            expect(page.locator("#payment-test-continue")).to_be_disabled()
            page.screenshot(path="/tmp/porn-fetch-payment-warning.png")
            page.locator("#payment-test-ack").check()
            with context.expect_page() as popup_event:
                page.locator("#payment-test-continue").click()
            popup = popup_event.value
            expect(
                popup.get_by_role("heading", name="Mock Banxa checkout")
            ).to_be_visible()
            assert page.url == original_url
            popup.close()
            page.bring_to_front()
            with main.app.app_context():
                checkout = OnrampCheckout.query.filter_by(stage="ready").one()
                session_id = checkout.session_id
            # The test fixture signs a mocked receipt; no real money is sent.
            with patch.object(service, "send_license_email") as send:
                response = fixture.post_ipn(fixture.webhook(session_id, paid=22.8))
                assert response.status_code == 200
                assert send.call_count == 1
                assert send.call_args.kwargs["beta"] is False
            expect(page.locator("#success-container")).to_be_visible(timeout=8000)
            expect(page.locator("#card-license-key")).to_contain_text("key/")
            expect(page.locator("#card-delivery-status")).to_contain_text("emailed")
            expect(page.locator("#payment-launch")).not_to_be_visible()
            page.set_viewport_size({"width": 390, "height": 844})
            page.screenshot(path="/tmp/onramp-success-mobile.png", full_page=True)
            assert page.evaluate(
                "document.documentElement.scrollWidth <= window.innerWidth"
            ), "Mobile overflow"
            assert not errors, errors
            browser.close()
        print(
            "Browser smoke passed: CSRF, resettable timer, consent, separate payment tab, signed receipt, license/email status, mobile layout."
        )
    finally:
        server.shutdown()
        worker.join(timeout=5)
        fixture.tearDown()
        fixture.doCleanups()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", default="chromium")
    run(parser.parse_args().browser)
