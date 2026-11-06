"""Local crypto checkout smoke test with CSRF/CSP and all external I/O blocked."""
import sys
import threading
from pathlib import Path
from unittest.mock import patch

import httpx
from playwright.sync_api import sync_playwright, expect
from werkzeug.serving import make_server

root = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(root / 'tests'), str(root)]
from _support import ServerTestCase, main
from pf_server import nowpayments_service


def run():
    fixture = ServerTestCase()
    fixture.setUp()
    server = make_server('127.0.0.1', 0, main.app, ssl_context='adhoc', threaded=True, request_handler=main.NoIPLoggingHandler)
    origin = f'https://127.0.0.1:{server.server_port}'
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    failures = []
    try:
        with patch.dict(main.app.config, WTF_CSRF_ENABLED=True, NOWPAYMENTS_API_KEY='synthetic', LICENSE_SMTP_HOST='localhost', LICENSE_EMAIL_FROM='test@example.com'), patch.object(nowpayments_service.httpx, 'post', side_effect=httpx.ConnectError('offline')), sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = browser.new_context(ignore_https_errors=True)
            context.route('**/*', lambda route: route.continue_() if route.request.url.startswith(origin + '/') else route.abort())
            page = context.new_page()
            page.on('pageerror', lambda error: failures.append(str(error)))
            page.goto(origin + '/porn_fetch')
            page.locator('#adult-confirmed').check()
            page.locator('#age-form button').click()
            page.locator('#method-crypto').check()
            for name in ('chk-age-terms', 'chk-refund-method', 'chk-test-site'):
                page.locator('#' + name).check()
            page.locator('#checkout-continue').click()
            expect(page).to_have_url(origin + '/buy_license')
            page.locator('#crypto-country').select_option('DE')
            page.locator('#crypto-withdrawal').check()
            page.locator('#delivery-email').fill('synthetic@example.com')
            page.locator('#pay-btn').click()
            expect(page.locator('#simulation-heading')).to_be_visible()
            assert not failures, failures
            browser.close()
        print('Passed: CSP, CSRF, selection, consent, encrypted email and simulated payment creation.')
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        fixture.tearDown()


if __name__ == '__main__':
    run()
