"""Exercise responsive guide layouts with isolated state; screenshots go to /tmp.

Run: uv run python scripts/check_seo_browser.py
Tests widths: 360, 390, 768, 1024, 1440.
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
            engines = [p.chromium]
            try:
                wb = p.webkit.launch()
                wb.close()
                engines.append(p.webkit)
            except Exception as e:
                print(f"Note: WebKit not available on host ({e}), running tests with Chromium.")

            for engine in engines:
                browser = engine.launch()
                context = browser.new_context(ignore_https_errors=True)
                context.route("**/_metrics/**", lambda route: route.fulfill(body=""))
                page = context.new_page()
                page.goto(origin + "/es/download?channel=beta")
                page.locator(".device-switcher summary").click()
                page.locator('.device-switcher a[data-platform="android"]').click()
                expect(page).to_have_url(origin + "/es/download/android?channel=beta")
                expect(page.locator("h1")).to_contain_text("Android")
                expect(page.locator("head link[rel=canonical]")).to_have_attribute("href", origin + "/es/download/android")
                page.go_back()
                expect(page.locator("head link[rel=canonical]")).to_have_attribute("href", origin + "/es/download")
                context.close()

                # Test the 5 required widths: 360, 390, 768, 1024, 1440
                for width in (360, 390, 768, 1024, 1440):
                    context = browser.new_context(ignore_https_errors=True, reduced_motion="reduce", viewport={"width": width, "height": 844})
                    context.route("**/_metrics/**", lambda route: route.fulfill(body=""))
                    page = context.new_page()
                    errors = []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    # All providers at 390, representative guides at other sizes
                    providers = GUIDES if width == 390 else ("xvideos", "xhamster")
                    for provider in providers:
                        page.goto(origin + "/guides/download-" + provider + "-videos")
                        expect(page.locator("h1")).to_have_count(1)
                        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (engine.name, width, provider)

                        # Mobile specific validations: header height & duplicate sticky button elimination
                        if width <= 768:
                            header_inner = page.locator('.site-header .header-inner').bounding_box()
                            assert header_inner["height"] <= 54, f"Mobile header height should be reduced, got {header_inner['height']}"
                            expect(page.locator('.site-header .header-premium-cta')).to_be_hidden()

                        # Device selector is near the top and accessible
                        selector = page.locator('#all-platforms')
                        expect(selector).to_be_visible()
                        expect(page.locator('#tab-android')).to_be_visible()
                        expect(page.locator('#tab-ios')).to_be_visible()
                        expect(page.locator('#tab-desktop')).to_be_visible()
                        expect(page.locator('#tab-cli')).to_be_visible()
                        expect(page.locator('#tab-all')).to_be_visible()

                        # Test platform selection: Switch to Android
                        page.locator('#tab-android').click()
                        expect(page.locator('#android')).to_be_visible()
                        expect(page.locator('#iphone')).to_be_hidden()
                        expect(page.locator('#download-steps')).to_be_hidden()

                        # Verify compact tutorial screenshots in mobile steps
                        step_preview = page.locator('#android .guide-phone-image > a').first.bounding_box()
                        assert step_preview["height"] <= 220, f"Tutorial screenshot height should be compact preview <= 220px, got {step_preview['height']}"

                        # Switch to iPhone
                        page.locator('#tab-ios').click()
                        expect(page.locator('#iphone')).to_be_visible()
                        expect(page.locator('#android')).to_be_hidden()
                        expect(page.locator('#download-steps')).to_be_hidden()

                        # Switch to Desktop
                        page.locator('#tab-desktop').click()
                        expect(page.locator('#download-steps')).to_be_visible()
                        expect(page.locator('#android')).to_be_hidden()
                        expect(page.locator('#iphone')).to_be_hidden()

                        # Desktop layout check at 1024 and 1440
                        if width >= 1024:
                            steps_box = page.locator('#download-steps .guide-steps').bounding_box()
                            shot_box = page.locator('#download-steps .guide-screenshot img').bounding_box()
                            assert shot_box["x"] > steps_box["x"] + steps_box["width"], "Desktop columns must not overlap"
                            assert abs(steps_box["y"] - shot_box["y"]) < 60, "Desktop steps and screenshot should be side-by-side in balanced two-column layout"
                            assert shot_box["height"] <= 340, f"Desktop screenshot height should be constrained, got {shot_box['height']}"

                        # CLI and keyboard access to the selector.
                        page.locator('#tab-cli').click()
                        expect(page.locator('#cli')).to_be_visible()
                        expect(page.locator('#download-steps')).to_be_hidden()
                        page.locator('#tab-cli').focus()
                        page.keyboard.press('Home')
                        expect(page.locator('#tab-android')).to_be_focused()
                        expect(page.locator('#android')).to_be_visible()
                        page.keyboard.press('End')
                        expect(page.locator('#tab-all')).to_be_focused()

                        # Switch to All platforms to verify all platforms accessible together
                        page.locator('#tab-all').click()
                        expect(page.locator('#android')).to_be_visible()
                        expect(page.locator('#iphone')).to_be_visible()
                        expect(page.locator('#download-steps')).to_be_visible()
                        assert page.locator('#iphone').bounding_box()['y'] < page.locator('#download-steps').bounding_box()['y']

                        choice = page.locator('.guide-platforms a[href="/download/android"]')
                        choice.focus()
                        expect(choice).to_be_focused()
                        assert choice.bounding_box()["height"] >= 44

                        for image in page.locator('.guide-phone-image img').all():
                            image.scroll_into_view_if_needed()
                            page.wait_for_function("img => img.complete && img.naturalWidth > 0", arg=image.element_handle())
                            assert image.evaluate("el => el.naturalWidth > 0")

                        # Sticky bottom actions test
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

                # Device emulation: Pixel 7 defaults to Android, iPhone 13 defaults to iPhone
                for device in ('Pixel 7', 'iPhone 13'):
                    context = browser.new_context(**p.devices[device], ignore_https_errors=True, reduced_motion="reduce")
                    context.route("**/_metrics/**", lambda route: route.fulfill(body=""))
                    page = context.new_page()
                    page.goto(origin + '/guides/download-xvideos-videos')
                    platform = 'android' if device == 'Pixel 7' else 'ios'
                    tab_id = f'#tab-{platform}'
                    expect(page.locator(tab_id)).to_have_attribute('aria-current', 'true')
                    expect(page.locator('#' + ('android' if platform == 'android' else 'iphone'))).to_be_visible()
                    expect(page.locator('#' + ('iphone' if platform == 'android' else 'android'))).to_be_hidden()
                    expect(page.locator('#guide-free-download')).to_have_js_property('href', origin + '/download/' + platform)
                    if platform == 'ios':
                        expect(page.locator('.guide-iphone-note')).to_contain_text('PC for sideloading')
                    page.screenshot(path=f"/tmp/guide-{engine.name}-{platform}.png")

                    # Anchors into a hidden tutorial must reveal that platform.
                    page.evaluate("location.hash = 'ios-title'" if platform == 'android' else "location.hash = 'android-title'")
                    expect(page.locator('#' + ('iphone' if platform == 'android' else 'android'))).to_be_visible()

                    # Can still switch to other platforms from mobile
                    other_tab = '#tab-ios' if platform == 'android' else '#tab-android'
                    page.locator(other_tab).click()
                    expect(page.locator('#' + ('iphone' if platform == 'android' else 'android'))).to_be_visible()
                    context.close()

                # No-JS fallback: All platforms visible in document order
                context = browser.new_context(ignore_https_errors=True, java_script_enabled=False, viewport={"width": 390, "height": 844})
                page = context.new_page()
                page.goto(origin + '/guides/download-xvideos-videos')
                expect(page.locator('#android')).to_be_visible()
                expect(page.locator('#iphone')).to_be_visible()
                expect(page.locator('#download-steps')).to_be_visible()
                expect(page.locator('#guide-free-download')).to_have_attribute('href', '#mobile-downloads')
                page.locator('#guide-free-download').click()
                expect(page.locator('.guide-platforms a[href="/download/android"]')).to_be_in_viewport()
                expect(page.locator('.guide-platforms a[href="/download/ios"]')).to_be_in_viewport()
                page.locator('.site-menu summary').click()
                expect(page.locator('.site-menu nav')).to_be_visible()
                expect(page.locator('.guide-bottom-actions')).to_be_hidden()
                context.close()
                browser.close()

        print(f'Browser tests passed: all {len(GUIDES)} guides, 5 viewport sizes (360, 390, 768, 1024, 1440), Android/iPhone defaults & switching, compact screenshots, sticky action controls, keyboard navigation, and no-JS fallback.')
    finally:
        server.shutdown()
        fixture.tearDown()
        fixture.doCleanups()


if __name__ == "__main__":
    run()
