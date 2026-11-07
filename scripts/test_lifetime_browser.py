"""Lifetime marketing and purchase checks over isolated HTTPS; no live providers."""
import sys
import threading
from pathlib import Path
from unittest.mock import patch

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'tests'))
sys.path.insert(0, str(root))
from playwright.sync_api import sync_playwright, expect
from werkzeug.serving import make_server
from _support import ServerTestCase, main


def run():
    fixture = ServerTestCase()
    fixture.setUp()
    server = make_server('127.0.0.1', 0, main.app, ssl_context='adhoc', threaded=True,
                         request_handler=main.NoIPLoggingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f'https://localhost:{server.server_port}'
    failures = []
    try:
        with patch.dict(main.app.config, WTF_CSRF_ENABLED=True), sync_playwright() as p:
            browser = p.chromium.launch()
            context = browser.new_context(ignore_https_errors=True)
            context.route('**/*', lambda route: route.continue_() if route.request.url.startswith(origin + '/') else route.abort())
            page = context.new_page()
            page.on('pageerror', lambda error: failures.append(str(error)))
            page.goto(origin + '/porn_fetch')
            page.locator('#adult-confirmed').check()
            page.locator('#age-form button').click()
            for width in (1440, 375, 768):
                page.set_viewport_size({'width': width, 'height': 1000})
                for path in ('/', '/porn_fetch', '/buy_license', '/buy_card', '/terms', '/help', '/about', '/download'):
                    page.goto(origin + path)
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), (width, path)
                    body = page.locator('body').inner_text()
                    assert '19.99' not in body and 'covered year' not in body, path
                    assert '29.99' in body or '29,99' in body or path == '/help', path
                page.goto(origin + '/')
                expect(page.locator('#premium')).to_contain_text('Buy once.')
                expect(page.locator('#premium')).to_contain_text('Every future Porn Fetch update and feature I release is included')
                expect(page.locator('#premium')).to_contain_text('Future development has no guaranteed duration')
                expect(page.locator('#premium')).to_contain_text('offline unlock')
                page.locator('#premium').screenshot(path=f'/tmp/porn-fetch-lifetime-{width}.png')
            page.goto(origin + '/porn_fetch')
            expect(page.locator('#chk-security-updates')).to_have_count(0)
            page.locator('#method-patreon').check()
            for name in ('chk-age-terms', 'chk-refund-method', 'chk-test-site'):
                page.locator('#' + name).check()
            page.locator('#checkout-continue').click()
            expect(page.locator('#payment-test-dialog')).to_be_visible()
            expect(page.locator('#payment-test-continue')).to_be_disabled()
            page.locator('#payment-test-ack').check()
            with context.expect_page() as opened:
                page.locator('#payment-test-continue').click()
            launch = opened.value
            expect(launch.locator('#provider-launch')).to_have_attribute('href', main.app.config['PATREON_SHOP_PRODUCT_URL'])
            assert '/patreon/consent' not in launch.url
            launch.close()
            # Pricing and terms remain available without scripts.
            no_js = browser.new_context(ignore_https_errors=True, java_script_enabled=False)
            no_js.route('**/*', lambda route: route.continue_() if route.request.url.startswith(origin + '/') else route.abort())
            fallback = no_js.new_page()
            fallback.goto(origin + '/')
            expect(fallback.locator('#premium')).to_contain_text('€29.99')
            expect(fallback.locator('#premium')).to_contain_text('perpetual Premium license')
            fallback.goto(origin + '/terms')
            expect(fallback.locator('#de')).to_contain_text('29,99 €')
            expect(fallback.locator('#en')).to_contain_text('EUR 29.99')
            assert not failures, failures
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
        fixture.tearDown()
    print('Passed: lifetime pricing, disclosures, responsive layouts, Patreon launch, no-script terms and JavaScript errors.')


if __name__ == '__main__':
    run()
