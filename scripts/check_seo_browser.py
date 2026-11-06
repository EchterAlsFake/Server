"""Check guide layouts and keyboard access locally with isolated test state.

Run: uv run --with playwright python scripts/check_seo_browser.py
Screenshots are written to /tmp; no production writes or tracking requests.
"""
from pathlib import Path
import sys
import threading
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tests"), str(ROOT)]
from _support import ServerTestCase, main
from playwright.sync_api import sync_playwright, expect
from werkzeug.serving import make_server


def run():
    fixture = ServerTestCase()
    fixture.setUp()
    server = make_server("127.0.0.1", 0, main.app, threaded=True, ssl_context="adhoc", request_handler=main.NoIPLoggingHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"https://127.0.0.1:{server.server_port}"
    try:
        with patch.dict(main.app.config, APP_DOMAIN=origin), sync_playwright() as p:
            browser = p.chromium.launch()
            for width in (390, 1440):
                context = browser.new_context(ignore_https_errors=True, viewport={"width": width, "height": 900})
                context.route("**/__eaf/*", lambda route: route.fulfill(body=""))
                page = context.new_page()
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                for provider in ("xvideos", "xhamster", "eporner", "pornhub", "thumbzilla", "xfreehd"):
                    page.goto(origin + "/guides/download-" + provider + "-videos")
                    expect(page.locator("h1")).to_have_count(1)
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                    choice = page.locator('.guide-platforms a[href="/download/android"]')
                    choice.focus()
                    expect(choice).to_be_focused()
                    assert choice.bounding_box()["height"] >= 44
                    img = page.locator(".guide-screenshot img")
                    img.scroll_into_view_if_needed()
                    img.evaluate("el => el.decode()")
                    assert img.evaluate("el => el.naturalWidth > 0")
                    account = page.locator(".android-account-screenshot img")
                    if provider in ("xvideos", "xhamster", "pornhub"):
                        account.scroll_into_view_if_needed()
                        account.evaluate("el => el.decode()")
                        assert account.evaluate("el => el.naturalWidth > 0")
                    else:
                        expect(account).to_have_count(0)
                    page.screenshot(path=f"/tmp/seo-{provider}-{width}.png", full_page=True)
                page.goto(origin + "/download/android")
                android = page.locator("#android .android-account-screenshot img")
                android.scroll_into_view_if_needed()
                android.evaluate("el => el.decode()")
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                page.screenshot(path=f"/tmp/seo-android-download-{width}.png", full_page=True)
                assert not errors, errors
                context.close()
            context = browser.new_context(ignore_https_errors=True, java_script_enabled=False, viewport={"width": 390, "height": 900})
            page = context.new_page()
            page.goto(origin + "/guides/download-xvideos-videos")
            page.locator(".site-menu summary").click()
            expect(page.locator('.guide-platforms a[href="/download/android"]')).to_be_visible()
            expect(page.locator('.site-menu nav')).not_to_be_visible()
            browser.close()
        print("Six guides checked at mobile and desktop widths; keyboard, images and no-JS navigation pass.")
    finally:
        server.shutdown()
        fixture.tearDown()
        fixture.doCleanups()


if __name__ == "__main__":
    run()
