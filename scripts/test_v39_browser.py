"""Offline commercial-release UI checks; all purchases and licenses are synthetic."""
import argparse
import logging
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

root = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(root), str(root / 'tests')]
from playwright.sync_api import sync_playwright, expect
from werkzeug.serving import make_server
from _support import ServerTestCase, main
from pf_server import patreon_shop as shop
from pf_server.guide_content import GUIDES


def run(browser_name, executable=None, flows_only=False):
    fixture = ServerTestCase()
    fixture.setUp()
    settings = patch.dict(main.app.config, NOWPAYMENTS_SANDBOX=False,
        NOWPAYMENTS_LOCAL_SIMULATION_ENABLED=False, WTF_CSRF_ENABLED=True,
        PATREON_SHOP_ENABLED=True, PATREON_SHOP_LOOKUP_KEY='b'*32,
        PATREON_SHOP_PRODUCT_URL='https://www.patreon.com/c/echteralsfake/shop/premium-123456',
        LICENSE_SMTP_HOST='localhost', LICENSE_EMAIL_FROM='test@example.com')
    settings.start()
    logging.getLogger('pf_server.access').setLevel(logging.WARNING)
    server = make_server('127.0.0.1', 0, main.app, ssl_context='adhoc', threaded=True,
        request_handler=main.NoIPLoggingHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    origin = f'https://localhost:{server.server_port}'
    errors = []
    checked = 0
    def route_request(route):
        if route.request.url.startswith(origin):
            route.continue_()
        else:
            route.abort()
    def fit(page, label):
        page.wait_for_load_state("load")
        if not page.evaluate('document.documentElement.scrollWidth <= innerWidth'):
            print('Viewport:', page.evaluate('({inner: innerWidth, doc: document.documentElement.scrollWidth, body: document.body.scrollWidth, main: document.querySelector("main").scrollWidth})'), flush=True)
            print('Overflow:', page.evaluate('Array.from(document.querySelectorAll("body *")).filter(el => el.getBoundingClientRect().right > innerWidth).slice(0, 12).map(el => [el.tagName, el.id, el.className, el.getBoundingClientRect().width])'), flush=True)
            page.screenshot(path='/tmp/pornfetch-v39-overflow.png', full_page=True)
            raise AssertionError(label)
        assert page.locator('#main-content').evaluate('el => el.scrollWidth <= el.clientWidth'), label
    def age(page):
        page.goto(origin+'/porn_fetch')
        if page.locator('#age-overlay').count():
            page.locator('#adult-confirmed').check()
            page.locator('#age-form button[type=submit]').click()
            expect(page.locator('#age-overlay')).to_have_count(0)
    try:
        with sync_playwright() as p:
            browser = getattr(p, browser_name).launch(executable_path=executable)
            context = browser.new_context(ignore_https_errors=True, reduced_motion='reduce', accept_downloads=True)
            context.route('**/*', route_request)
            page = context.new_page()
            page.on('pageerror', lambda error: errors.append(str(error)))
            age(page)
            paths = ['/', '/download', '/about', '/help', '/guides', '/terms', '/privacy_policy',
                '/refund_policy', '/impress', '/legal-statement', '/withdrawal', '/releases',
                '/porn_fetch', '/buy_license', '/buy_success', '/buy_cancel', '/donation', '/activate',
                '/download/windows', '/download/linux', '/download/macos', '/download/android',
                '/download/ios', '/download/cli', '/docs/', '/docs/pornhub/', '/docs/transparency/']
            paths += ['/guides/download-'+key+'-videos' for key in GUIDES]
            for width, height in (() if flows_only else ((320, 740), (375, 812), (390, 844), (667, 375), (768, 1024), (1440, 1000))):
                page.set_viewport_size({'width': width, 'height': height})
                for path in paths:
                    response = page.goto(origin+path)
                    assert response.status == 200, (path, response.status)
                    fit(page, (width, path))
                    if path == '/activate':
                        assert page.locator('#lookup-email').evaluate('el => parseFloat(getComputedStyle(el).fontSize) >= 16')
                    if path == '/':
                        assert page.locator('#product-video').evaluate('el => el.paused')
                        expect(page.locator('#product-video source')).not_to_have_attribute('src')
                    checked += 1
                print(f'{browser_name}: {len(paths)} pages fit {width}×{height}', flush=True)
            page.set_viewport_size({'width': 375, 'height': 812})
            page.goto(origin+'/porn_fetch')
            page.locator('#method-patreon').check()
            page.locator('#checkout-continue').click()
            expect(page.locator('#chk-age-terms')).to_be_focused()
            page.locator('#chk-age-terms').check()
            page.locator('#chk-refund-method').check()
            page.locator('#checkout-continue').click()
            expect(page.get_by_role('heading', name='Buy lifetime Premium on Patreon')).to_be_visible()
            expect(page.get_by_role('link', name='Continue to Patreon Shop')).to_have_attribute('href', main.app.config['PATREON_SHOP_PRODUCT_URL'])
            assert 'test preview' not in page.locator('main').inner_text().lower()
            fit(page, 'Patreon live handoff')
            page.screenshot(path=f'/tmp/pornfetch-v39-{browser_name}-patreon-mobile.png', full_page=True)

            page.goto(origin+'/activate')
            page.locator('#lookup-email').fill('browser@example.com')
            page.locator('#lookup-order').fill('RECEIPT-BROWSER-123')
            page.get_by_role('button', name='View my license').click()
            expect(page.locator('[data-patreon-pending]')).to_be_visible()
            with main.app.app_context(), patch.object(shop, 'snapshot', return_value=[
                ('internal-browser', 'browser@example.com', time.time()-60, True, 'RECEIPT-BROWSER-123')]):
                shop.process_claims()
            page.reload()
            expect(page.locator('#patreon-license-key')).to_be_visible()
            fit(page, 'License result with signed key')
            download_responses = []
            page.on('response', lambda response: download_responses.append((response.status, response.headers.get('content-disposition'))) if response.url.endswith('/activate/download') else None)
            try:
                with page.expect_download() as event:
                    page.get_by_role('button', name='Download license file').click()
            except Exception:
                print('License download response:', download_responses, 'page:', page.url, flush=True)
                raise
            assert event.value.suggested_filename == 'porn_fetch.license'
            page.evaluate('window.scrollTo({top: 0, behavior: "instant"})')
            page.screenshot(path=f'/tmp/pornfetch-v39-{browser_name}-license-mobile.png', full_page=True)

            fixture.mock_tor_lookup.return_value = 'tor'
            page.goto(origin+'/porn_fetch?method=crypto')
            expect(page.locator('#method-crypto')).to_be_disabled()
            for path in ('/buy_license', '/buy_card', '/donation'):
                response = page.goto(origin+path)
                assert response.status == 403
                fit(page, 'Tor block '+path)
            fixture.mock_tor_lookup.return_value = 'clear'

            phone = browser.new_context(ignore_https_errors=True, reduced_motion='no-preference',
                viewport={'width': 375, 'height': 812}, has_touch=True)
            phone.route('**/*', route_request)
            phone_page = phone.new_page()
            phone_page.goto(origin+'/')
            expect(phone_page.locator('#product-video source')).not_to_have_attribute('src')
            phone_page.locator('#product-video').focus()
            expect(phone_page.locator('#product-video source')).to_have_attribute('src', '/static/media/porn-fetch-promo.mp4')
            phone.close()

            no_js = browser.new_context(ignore_https_errors=True, java_script_enabled=False,
                viewport={'width': 375, 'height': 812})
            no_js.route('**/*', route_request)
            fallback = no_js.new_page()
            age(fallback)
            fallback.locator('#method-patreon').check()
            fallback.locator('#chk-age-terms').check()
            fallback.locator('#chk-refund-method').check()
            fallback.locator('#checkout-continue').click()
            expect(fallback.get_by_role('heading', name='Buy lifetime Premium on Patreon')).to_be_visible()
            fallback.goto(origin+'/activate')
            fallback.locator('#lookup-email').fill('browser@example.com')
            fallback.locator('#lookup-order').fill('RECEIPT-BROWSER-123')
            fallback.get_by_role('button', name='View my license').click()
            with main.app.app_context(), patch.object(shop, 'snapshot', return_value=[
                ('internal-browser', 'browser@example.com', time.time()-60, True, 'RECEIPT-BROWSER-123')]):
                shop.process_claims()
            fallback.get_by_role('link', name='Refresh purchase status').click()
            expect(fallback.locator('#patreon-license-key')).to_be_visible()
            fit(fallback, 'No-JavaScript license result')
            fallback.set_viewport_size({'width': 1440, 'height': 1000})
            fallback.goto(origin+'/')
            expect(fallback.locator('.site-menu nav a[href="/download"]')).to_be_visible()
            no_js.close()
            context.close()
            browser.close()
        assert not errors, errors
        print(f'Passed {checked} page/viewport checks, live consent/handoff, browser license download, Tor blocks, reduced motion and forms without JavaScript.', flush=True)
    finally:
        server.shutdown()
        worker.join(timeout=5)
        settings.stop()
        fixture.tearDown()
        fixture.doCleanups()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--browser', choices=('chromium', 'firefox', 'webkit'), default='chromium')
    parser.add_argument('--executable', help='Optional compatible browser launcher path')
    parser.add_argument('--flows-only', action='store_true', help='Run only interactive checks')
    args = parser.parse_args()
    run(args.browser, args.executable, args.flows_only)
