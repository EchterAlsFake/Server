"""Local crypto checkout browser regression; every provider and email is mocked."""

import argparse
import sys
import threading
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
import httpx
from playwright.sync_api import sync_playwright, expect
from werkzeug.serving import make_server

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tests"))
sys.path.insert(0, str(root))
from _support import ServerTestCase, main
from pf_server import crypto_delivery, nowpayments_service


def run(browser_name="chromium"):
    fixture = ServerTestCase()
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
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"https://localhost:{server.server_port}"
    failures = []
    try:
        with (
            patch.dict(
                main.app.config,
                {
                    "NOWPAYMENTS_API_KEY": "test-key",
                    "NOWPAYMENTS_SANDBOX": True,
                    "LICENSE_DELIVERY_ENCRYPTION_KEY": Fernet.generate_key().decode(),
                    "LICENSE_SMTP_HOST": "localhost",
                    "LICENSE_EMAIL_FROM": "test@example.com",
                },
            ),
            patch.object(
                nowpayments_service.httpx,
                "post",
                side_effect=httpx.ConnectError("Mock sandbox offline"),
            ) as provider,
            patch.object(crypto_delivery, "send_license_email") as send,
            sync_playwright() as p,
        ):
            browser = getattr(p, browser_name).launch()
            context = browser.new_context(
                ignore_https_errors=True, viewport={"width": 1440, "height": 1050}
            )

            def route_request(route):
                if route.request.url.startswith(origin):
                    route.continue_()
                elif route.request.url.startswith(
                    "https://sandbox.nowpayments.io/payment/"
                ):
                    route.fulfill(
                        body="<h1>Mock NOWPayments checkout</h1>",
                        content_type="text/html",
                    )
                else:
                    route.abort()

            context.route("**/*", route_request)
            page = context.new_page()
            page.on("pageerror", lambda error: failures.append(str(error)))
            page.goto(origin + "/porn_fetch")
            page.locator("#adult-confirmed").check()
            page.get_by_role("button", name="Confirm & enter").click()
            expect(page.locator("#site-content")).to_have_css("filter", "none")
            page.get_by_role("button", name="Learn more").click()
            expect(page.locator("#installation-dialog")).to_be_visible()
            expect(page.locator("#installation-dialog")).to_contain_text(
                "not derived from your hardware"
            )
            page.keyboard.press("Escape")
            expect(page.get_by_role("button", name="Learn more")).to_be_focused()
            page.locator(".continuity-button").click()
            expect(page.locator("#continuity-dialog")).to_contain_text(
                "not an automatic feature"
            )
            page.screenshot(path="/tmp/porn-fetch-continuity-dialog.png")
            page.get_by_role("button", name="Got it").last.click()
            page.locator("#method-crypto").check()
            page.locator("#checkout-country").select_option("DE")
            for checkbox in ("chk-age-terms", "chk-withdrawal", "chk-test-site"):
                page.locator("#" + checkbox).check()
            page.locator("#checkout-continue").click()
            expect(page).to_have_url(origin + "/buy_license")
            expect(page.locator(".nowpayments-amount")).to_have_text("€19.99")
            expect(page.locator("#checkout-country")).to_have_count(0)
            expect(page.locator("#chk-age")).to_have_count(0)
            expect(page.locator("#pay-btn")).to_be_enabled()
            expect(page.get_by_role("heading", level=1)).to_have_text("Porn Fetch Premium")
            expect(page.locator("#delivery-email")).not_to_have_attribute("required", "")
            expect(page.locator(".checkout-question[open]")).to_have_count(0)
            fees = page.locator("#crypto-fees summary")
            fees.focus()
            page.keyboard.press("Enter")
            expect(page.locator("#crypto-fees")).to_have_attribute("open", "")
            expect(page.get_by_role("region", name="What fees will I pay?")).to_be_visible()
            expect(page.locator("#crypto-fees .checkout-answer")).to_contain_text("1.5%")
            page.keyboard.press("Space")
            expect(page.locator("#crypto-fees")).not_to_have_attribute("open", "")
            assert provider.call_count == 0
            # FAQs retain native keyboard behavior without the checkout scripts.
            no_js = browser.new_context(
                ignore_https_errors=True, java_script_enabled=False,
                storage_state=context.storage_state(),
                viewport={"width": 375, "height": 844},
            )
            no_js.route("**/*", route_request)
            no_js_page = no_js.new_page()
            no_js_page.goto(origin + "/buy_license")
            no_js_page.locator("#crypto-privacy summary").click()
            expect(no_js_page.get_by_role("region", name="How private is cryptocurrency checkout?")).to_be_visible()
            no_js_page.keyboard.press("Enter")
            expect(no_js_page.locator("#crypto-privacy")).not_to_have_attribute("open", "")
            no_js.close()
            page.emulate_media(reduced_motion="reduce")
            assert page.locator("#crypto-fees").evaluate(
                "el => getComputedStyle(el, '::details-content').transitionDuration"
            ) == "0s"
            page.emulate_media(reduced_motion="no-preference")
            expect(page.locator("#pay-btn")).to_have_css("background-color", "rgb(241, 139, 176)")
            page.locator("#main-content").focus()
            page.evaluate('window.scrollTo({top: 0, behavior: "instant"})')
            page.screenshot(path="/tmp/porn-fetch-crypto-desktop.png", full_page=True)
            for width in (1440, 1280, 900, 768, 390, 375, 360):
                page.set_viewport_size({"width": width, "height": 900})
                assert page.evaluate(
                    "document.documentElement.scrollWidth <= innerWidth"
                ), f"overflow at {width}"
                card = page.locator(".checkout-card").bounding_box()
                assert card["width"] <= 480, card
                assert abs(card["x"] + card["width"] / 2 - width / 2) < 1, card
                if width == 390:
                    page.evaluate('window.scrollTo({top: 0, behavior: "instant"})')
                    page.screenshot(
                        path="/tmp/porn-fetch-crypto-mobile.png", full_page=True
                    )
            page.set_viewport_size({"width": 1440, "height": 1050})
            page.locator("#pay-btn").click()
            expect(page.locator("#no-email-dialog")).to_be_visible()
            assert provider.call_count == 0
            page.keyboard.press("Escape")
            expect(page.locator("#pay-btn")).to_be_focused()
            page.locator("#pay-btn").click()
            page.locator("#add-email").click()
            expect(page.locator("#delivery-email")).to_be_focused()
            page.locator("#delivery-email").fill("invalid")
            page.locator("#pay-btn").click()
            assert provider.call_count == 0
            page.locator("#delivery-email").fill("")
            page.locator("#pay-btn").click()
            expect(page.locator("#no-email-dialog")).to_be_visible()
            page.screenshot(path="/tmp/porn-fetch-no-email-dialog.png")
            page.locator("#continue-without-email").click()
            expect(page.locator("#tx-screen-container")).to_be_visible()
            page.locator("#simulate-success-btn").click()
            expect(page.locator("#success-container")).to_be_visible()
            expect(page.locator("#crypto-license-key")).to_have_value(
                __import__("re").compile("^key/")
            )
            expect(page.locator("#crypto-delivery-status")).to_contain_text(
                "No email delivery requested"
            )
            send.assert_not_called()
            with page.expect_download() as download:
                page.get_by_role("link", name="Download License Key File").click()
            assert download.value.suggested_filename == "porn_fetch.license"
            page.goto(origin + "/porn_fetch")
            expect(page.locator("#checkout-country")).to_have_value("DE")
            expect(page.locator("#chk-age-terms")).to_be_checked()
            page.locator("#checkout-continue").click()
            page.locator("#delivery-email").fill("buyer@example.com")
            page.locator("#pay-btn").click()
            expect(page.locator("#no-email-dialog")).not_to_be_visible()
            expect(page.locator("#tx-screen-container")).to_be_visible()
            page.locator("#simulate-success-btn").click()
            expect(page.locator("#success-container")).to_be_visible()
            expect(page.locator("#crypto-delivery-status")).to_contain_text(
                "Your license was emailed."
            )
            send.assert_called_once()
            assert send.call_args.args[0] == "buyer@example.com"
            # A hosted invoice goes to our tracker first, keeping progress visible.
            provider.side_effect = None
            provider.return_value = httpx.Response(
                200,
                json={
                    "id": "hosted-invoice-test",
                    "invoice_url": "https://sandbox.nowpayments.io/payment/?iid=hosted-invoice-test",
                },
                request=httpx.Request(
                    "POST", "https://api-sandbox.nowpayments.io/v1/invoice"
                ),
            )
            page.goto(origin + "/porn_fetch")
            page.locator("#checkout-continue").click()
            page.locator("#pay-btn").click()
            page.locator("#continue-without-email").click()
            expect(page.locator("#payment-tracker")).to_have_attribute(
                "data-stage", "payment"
            )
            expect(page.locator("#payment-progress-steps li")).to_have_count(4)
            with context.expect_page() as hosted_event:
                page.get_by_role("link", name="Open NOWPayments checkout").click()
            hosted_page = hosted_event.value
            expect(
                hosted_page.get_by_role("heading", name="Mock NOWPayments checkout")
            ).to_be_visible()
            hosted_page.close()
            expect(page.locator("#success-container")).not_to_be_visible()
            assert not failures, failures
            browser.close()
            print(
                f"{browser_name}: shared consent, dialogs, responsive crypto, skipped email, simulation, license recovery and mocked email passed"
            )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        fixture.tearDown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", default="chromium")
    run(parser.parse_args().browser)
