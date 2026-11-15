"""Exercise mobile guides with isolated state; screenshots go to /tmp.

Run: uv run python scripts/check_seo_browser.py
No production writes, downloads, purchases, or tracking requests.
"""
from pathlib import Path
import sys
import threading
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tests"), str(ROOT)]
from _support import ServerTestCase, main
from pf_server.guide_content import GUIDES
from playwright.sync_api import sync_playwright, expect
from werkzeug.serving import make_server


def run():
    fixture = ServerTestCase()
    fixture.setUp()
    server = make_server("127.0.0.1", 0, main.app, threaded=True, ssl_context="adhoc", request_handler=main.NoIPLoggingHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"https://127.0.0.1:{server.server_port}"
    try:
        with patch.dict(main.app.config, APP_DOMAIN=origin, NOWPAYMENTS_SANDBOX=False), sync_playwright() as p:
            for engine in (p.chromium, p.webkit):
                browser = engine.launch()
                for width in (320, 360, 390, 430, 768, 1440):
                    context = browser.new_context(ignore_https_errors=True, reduced_motion="reduce", viewport={"width": width, "height": 844})
                    context.route("**/_metrics/**", lambda route: route.fulfill(body=""))
                    page = context.new_page()
                    errors = []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    # All providers at common phone size, representative guides at every size.
                    providers = GUIDES if width == 390 else ("xvideos", "xhamster")
                    for provider in providers:
                        page.goto(origin + "/guides/download-" + provider + "-videos")
                        expect(page.locator("h1")).to_have_count(1)
                        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (engine.name, width, provider)
                        expect(page.locator('#android')).to_be_visible()
                        expect(page.locator('#iphone')).to_be_visible()
                        assert page.locator('#iphone').bounding_box()['y'] < page.locator('#download-steps').bounding_box()['y']
                        choice = page.locator('.guide-platforms a[href="/download/android"]')
                        choice.focus()
                        expect(choice).to_be_focused()
                        assert choice.bounding_box()["height"] >= 44
                        for image in page.locator('.guide-phone-image img').all():
                            image.scroll_into_view_if_needed()
                            page.wait_for_function("img => img.complete && img.naturalWidth > 0", arg=image.element_handle())
                            assert image.evaluate("el => el.naturalWidth > 0")
                        page.locator('#troubleshooting').scroll_into_view_if_needed()
                        expect(page.locator('.guide-bottom-actions')).to_be_visible()
                        page.locator('.guide-comparison .btn').first.scroll_into_view_if_needed()
                        expect(page.locator('.guide-bottom-actions')).to_be_hidden()
                        page.locator('.site-footer').scroll_into_view_if_needed()
                        expect(page.locator('.guide-bottom-actions')).to_be_hidden()
                        page.evaluate('scrollTo(0, 0)')
                        expect(page.locator('.guide-bottom-actions')).to_be_hidden()
                        if provider == 'xvideos':
                            page.screenshot(path=f"/tmp/guide-{engine.name}-{width}.png")
                    page.goto(origin + '/guides')
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                    expect(page.locator('a[href="/download/ios"]').first).to_be_visible()
                    assert not errors, errors
                    context.close()
                for device in ('Pixel 7', 'iPhone 13'):
                    context = browser.new_context(**p.devices[device], ignore_https_errors=True, reduced_motion="reduce")
                    context.route("**/_metrics/**", lambda route: route.fulfill(body=""))
                    page = context.new_page()
                    page.goto(origin + '/guides/download-xvideos-videos')
                    platform = 'android' if device == 'Pixel 7' else 'ios'
                    expect(page.locator('#guide-free-download')).to_have_attribute('href', '/download/' + platform)
                    expect(page.locator('.guide-iphone-note')).to_contain_text('PC for sideloading')
                    page.screenshot(path=f"/tmp/guide-{engine.name}-{platform}.png")
                    context.close()
                context = browser.new_context(ignore_https_errors=True, java_script_enabled=False, viewport={"width": 390, "height": 844})
                page = context.new_page()
                page.goto(origin + '/guides/download-xvideos-videos')
                expect(page.locator('#android')).to_be_visible()
                expect(page.locator('#iphone')).to_be_visible()
                expect(page.locator('#guide-free-download')).to_have_attribute('href', '#mobile-downloads')
                page.locator('#guide-free-download').click()
                expect(page.locator('.guide-platforms a[href="/download/android"]')).to_be_in_viewport()
                expect(page.locator('.guide-platforms a[href="/download/ios"]')).to_be_in_viewport()
                page.locator('.site-menu summary').click()
                expect(page.locator('.site-menu nav')).to_be_visible()
                expect(page.locator('.guide-bottom-actions')).to_be_hidden()
                browser.close()
        print('Chromium + WebKit: all 15 guides, 6 viewport sizes, Android/iPhone suggestions, images, sticky actions, keyboard and no-JS navigation pass.')
    finally:
        server.shutdown()
        fixture.tearDown()
        fixture.doCleanups()


if __name__ == "__main__":
    run()
