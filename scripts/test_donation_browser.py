"""Check consent before any widget request; synthetic provider, no real donation.

Run with .venv/bin/python scripts/test_donation_browser.py
"""
import sys
import threading
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(root / 'tests'), str(root)]
from _support import ServerTestCase, main
from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server


def run():
    fixture = ServerTestCase()
    fixture.setUp()
    server = make_server('127.0.0.1', 0, main.app, ssl_context='adhoc', threaded=True,
                         request_handler=main.NoIPLoggingHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    origin = f'https://localhost:{server.server_port}'
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            for width, javascript in ((1440, True), (390, True), (390, False)):
                requests = []
                errors = []
                def intercept(route):
                    if route.request.url.startswith(origin):
                        route.continue_()
                    else:
                        requests.append(route.request)
                        route.fulfill(body='<p>Mock provider</p>', content_type='text/html')
                context = browser.new_context(ignore_https_errors=True, java_script_enabled=javascript,
                                              viewport={'width': width, 'height': 950})
                context.route('**/*', intercept)
                page = context.new_page()
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.goto(origin + '/donation', wait_until='networkidle')
                expect(page.locator('iframe')).to_have_count(0)
                assert not requests, 'External request before consent'
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                page.locator('#adult-confirmed').check()
                page.get_by_role('button', name='Confirm & enter').click()
                expect(page.locator('#age-overlay')).to_have_count(0)
                if javascript:
                    expect(page.locator('#load-donation-widget')).to_be_disabled()
                    page.locator('#chk-age-donation').check()
                    page.locator('#chk-country-donation').check()
                    expect(page.locator('#load-donation-widget')).to_be_enabled()
                    expect(page.locator('iframe')).to_have_count(0)
                    assert not requests, 'Age/country consent must not load provider'
                    page.locator('#load-donation-widget').click()
                    expect(page.frame_locator('#iframe-wrapper iframe').get_by_text('Mock provider')).to_be_visible()
                    assert len(requests) == 1
                    assert requests[0].url.startswith('https://nowpayments.io/embeds/donation-widget?')
                    assert 'referer' not in requests[0].all_headers()
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                    page.locator('#unload-donation-widget').click()
                    expect(page.locator('iframe')).to_have_count(0)
                    expect(page.locator('#load-donation-widget')).to_be_focused()
                    page.locator('#load-donation-widget').click()
                    expect(page.frame_locator('#iframe-wrapper iframe').get_by_text('Mock provider')).to_be_visible()
                    page.locator('#chk-country-donation').uncheck()
                    expect(page.locator('iframe')).to_have_count(0)
                    expect(page.locator('#load-donation-widget')).to_be_disabled()
                    previous = len(requests)
                    page.reload(wait_until='networkidle')
                    expect(page.locator('iframe')).to_have_count(0)
                    assert len(requests) == previous
                else:
                    expect(page.locator('#load-donation-widget')).to_be_disabled()
                    assert 'JavaScript is required' in page.locator('#widget-consent noscript').text_content()
                    expect(page.locator('iframe')).to_have_count(0)
                    assert not requests
                assert not errors, errors
                context.close()
                print(f'Donation consent passed: width={width}, JavaScript={javascript}', flush=True)
            browser.close()
    finally:
        server.shutdown()
        worker.join(timeout=5)
        fixture.tearDown()


if __name__ == '__main__':
    run()
