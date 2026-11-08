"""Offline loading-screen checks with real workers paused at slow service calls."""
import argparse
import logging
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

root = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(root), str(root / 'tests')]
from playwright.sync_api import sync_playwright, expect
from werkzeug.serving import make_server
from _support import ServerTestCase, main
from license_fixtures import issuance
from pf_server import licensing, nowpayments_service as payments, patreon_shop as shop
from pf_server.models import Transaction, PaymentProgress, PatreonShopLookup
from pf_server.webhook_models import NowPaymentsWebhook


def run(browser_name):
    fixture = ServerTestCase()
    fixture.setUp()
    settings = patch.dict(main.app.config, WTF_CSRF_ENABLED=True,
                          NOWPAYMENTS_API_KEY='', PATREON_SHOP_ENABLED=True,
                          PATREON_SHOP_LOOKUP_KEY='p' * 32)
    settings.start()
    logging.getLogger('pf_server.access').setLevel(logging.WARNING)
    server = make_server('127.0.0.1', 0, main.app, ssl_context='adhoc', threaded=True,
                         request_handler=main.NoIPLoggingHandler)
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    origin = f'https://localhost:{server.server_port}'
    errors, jobs, gates = [], [], []

    def start(job):
        def work():
            try:
                with main.app.app_context():
                    job()
            except Exception as error:
                errors.append(repr(error))
        thread = threading.Thread(target=work, daemon=True)
        thread.start()
        jobs.append(thread)
        return thread

    def paused(result):
        entered, release = threading.Event(), threading.Event()
        gates.append(release)
        def call(*args, **kwargs):
            entered.set()
            if not release.wait(45):
                raise TimeoutError('Browser did not release the test service')
            return result(*args, **kwargs) if callable(result) else result
        return call, entered, release

    def fits(page):
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')

    try:
        with sync_playwright() as p:
            browser = getattr(p, browser_name).launch()
            context = browser.new_context(ignore_https_errors=True, viewport={'width': 1280, 'height': 960})
            context.route('**/*', lambda route: route.continue_() if route.request.url.startswith(origin) else route.abort())
            page = context.new_page()
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(origin + '/porn_fetch')
            page.locator('#adult-confirmed').check()
            page.locator('#age-form button[type="submit"]').click()
            expect(page.locator('#age-overlay')).to_have_count(0)

            with main.app.app_context():
                main.db.session.add(Transaction(session_id='NP-progress', provider_payment_id='mock-progress',
                    provider_reference_type='payment', expected_price_amount='29.99', expected_price_currency='eur',
                    customer_country='Germany', country_evidence='test', geolocation_database='test',
                    status='pending', created_at=datetime.now(timezone.utc).isoformat()))
                main.db.session.add(PaymentProgress(session_id='NP-progress', nowpayments_state='finished'))
                main.db.session.commit()
            event = NowPaymentsWebhook.from_mapping(dict(order_id='NP-progress', payment_id='mock-progress',
                payment_status='finished', price_amount=29.99, price_currency='eur', pay_currency='btc',
                pay_amount=0.001, actually_paid=0.001))
            generate, generating, license_done = paused(issuance)
            invoice, invoicing, invoice_done = paused(payments.build_invoice)
            with patch.object(licensing, 'ensure_license', side_effect=generate), patch.object(payments, 'build_invoice', side_effect=invoice):
                job = start(lambda: payments.complete_payment(event))
                assert generating.wait(10)
                page.goto(origin + '/buy_success?session_id=NP-progress')
                expect(page.locator('#payment-progress-title')).to_contain_text('Generating your license')
                expect(page.locator('#loading-container')).to_have_attribute('aria-busy', 'true')
                expect(page.locator('#success-container')).not_to_be_visible()
                expect(page.locator('.purchase-spinner')).to_have_css('animation-name', 'purchase-spin')
                page.screenshot(path='/tmp/purchase-crypto-loading.png', full_page=True)
                page.emulate_media(reduced_motion='reduce')
                expect(page.locator('.purchase-spinner')).to_have_css('animation-name', 'none')
                page.emulate_media(reduced_motion='no-preference')
                page.set_viewport_size({'width': 375, 'height': 812})
                fits(page)
                license_done.set()
                assert invoicing.wait(10)
                page.locator('#refresh-progress').click()
                expect(page.locator('#payment-progress-title')).to_contain_text('Preparing your invoice')
                invoice_done.set()
                job.join(10)
                page.locator('#refresh-progress').click()
                expect(page.locator('#success-container')).to_be_visible()
                expect(page.locator('#payment-success-heading')).to_be_focused()
                expect(page.locator('#crypto-license-key')).to_have_value(re.compile('^key/'))
                assert page.locator('#success-container').evaluate('el => el.compareDocumentPosition(document.querySelector("#payment-details")) & Node.DOCUMENT_POSITION_FOLLOWING')
                expect(page.locator('#payment-success-heading')).to_be_in_viewport()
                fits(page)
                page.screenshot(path='/tmp/purchase-crypto-ready-mobile.png', full_page=True)

            # Email-only processing shows actual work without returning a key.
            page.goto(origin + '/activate')
            page.locator('#activation-email').fill('email-progress@example.com')
            page.get_by_role('button', name='Email my license').click()
            panel = page.locator('#patreon-email-progress')
            expect(panel).to_contain_text('Starting purchase verification')
            sales = [('email-order', 'email-progress@example.com', time.time() - 60, True, 'EMAIL-RECEIPT')]
            fetch, fetching, fetched = paused(sales)
            send, sending, sent = paused(None)
            with patch.object(shop, 'snapshot', side_effect=fetch), patch.object(shop, 'send_license_email', side_effect=send):
                job = start(shop.process_claims)
                assert fetching.wait(10)
                panel.locator('[data-progress-refresh]').click()
                expect(panel).to_contain_text('Reading Patreon purchase data')
                fits(page)
                page.screenshot(path='/tmp/purchase-patreon-loading-mobile.png', full_page=True)
                # A dropped connection remains retryable without losing progress.
                page.route('**/activate/status?**', lambda route: route.abort())
                panel.locator('[data-progress-refresh]').click()
                expect(panel.locator('[data-progress-connection]')).to_contain_text('Connection interrupted')
                page.unroute('**/activate/status?**')
                fetched.set()
                assert sending.wait(10)
                panel.locator('[data-progress-refresh]').click()
                expect(panel).to_contain_text('Preparing email delivery')
                sent.set()
                job.join(10)
                panel.locator('[data-progress-refresh]').click()
                expect(panel).to_contain_text('Request processed. Check your email.')
                expect(panel).to_have_attribute('aria-busy', 'false')
                assert page.locator('#patreon-license-key').count() == 0

            # Receipt proof enables automatic navigation to a prominent license.
            page.locator('#lookup-email').fill('receipt-progress@example.com')
            page.locator('#lookup-order').fill('RECEIPT-PROGRESS')
            page.get_by_role('button', name='View my license').click()
            panel = page.locator('#patreon-lookup-progress')
            expect(panel).to_contain_text('Starting purchase verification')
            build, building, built = paused(shop.build_license_file)
            sales = [('receipt-order', 'receipt-progress@example.com', time.time()-60, True, 'RECEIPT-PROGRESS')]
            with patch.object(shop, 'snapshot', return_value=sales), patch.object(shop, 'build_license_file', side_effect=build):
                job = start(shop.process_claims)
                assert building.wait(10)
                panel.locator('[data-progress-refresh]').click()
                expect(panel).to_contain_text('Preparing your license')
                built.set()
                job.join(10)
                panel.locator('[data-progress-refresh]').click()
                expect(page.locator('#patreon-license-key')).to_be_visible()
                expect(page.locator('#patreon-license-heading')).to_be_focused()
                expect(page.locator('#patreon-license-heading')).to_be_in_viewport()
                fits(page)
                page.screenshot(path='/tmp/purchase-patreon-ready-mobile.png', full_page=True)
            page.locator('.purchase-resubmit summary').click()
            page.locator('#lookup-email').fill('receipt-progress@example.com')
            page.locator('#lookup-order').fill('RECEIPT-PROGRESS')
            with page.expect_navigation(wait_until='load'):
                page.get_by_role('button', name='View my license').click()
            panel = page.locator('#patreon-lookup-progress')
            expect(panel).to_be_visible()
            with main.app.app_context():
                lookup = PatreonShopLookup.query.filter_by(status='pending').first()
                lookup.created_at = time.time() - 901
                main.db.session.commit()
            panel.locator('[data-progress-refresh]').click()
            expect(panel).to_contain_text('Browser status access expired')
            expect(panel).to_have_attribute('aria-busy', 'false')
            page.get_by_role('button', name='Enter purchase details again').click()
            expect(page.locator('#lookup-email')).to_be_visible()

            # Enable the real intake wakeup. No timer, CLI call or manual
            # refresh participates in either of these end-to-end purchases.
            fixture.patreon_wakeup.stop()
            for email_only in (False, True):
                buyer = f'immediate-{email_only}@example.com'
                sales = [(f'immediate-{email_only}', buyer, time.time()-60, True, 'IMMEDIATE-RECEIPT')]
                fetch, fetching, fetched = paused(sales)
                with patch.object(shop, 'fetch_sales', side_effect=fetch), patch.object(shop, 'send_license_email'):
                    page.goto(origin + '/activate')
                    if email_only:
                        # A fresh browser session has no earlier delivery panel.
                        context.clear_cookies()
                        page.goto(origin + '/activate')
                        page.locator('#activation-email').fill(buyer)
                        submit = page.get_by_role('button', name='Email my license')
                    else:
                        page.locator('#lookup-email').fill(buyer)
                        page.locator('#lookup-order').fill('IMMEDIATE-RECEIPT')
                        submit = page.get_by_role('button', name='View my license')
                    started_at = time.monotonic()
                    with page.expect_navigation(wait_until='load'):
                        submit.click()
                    assert fetching.wait(2), 'Intake did not start scraping immediately'
                    state = main.app.extensions['patreon_shop_worker']
                    if state.thread:
                        jobs.append(state.thread)
                    active_panel = '#patreon-email-progress' if email_only else '#patreon-lookup-progress'
                    expect(page.locator(active_panel + ' [data-progress-title]')).to_contain_text('Reading Patreon purchase data', timeout=3000)
                    fetched.set()
                    if email_only:
                        expect(page.locator('#patreon-email-progress')).to_contain_text('Request processed. Check your email.', timeout=4000)
                    else:
                        expect(page.locator('#patreon-license-key')).to_be_visible(timeout=4000)
                        expect(page.locator('#patreon-license-heading')).to_be_focused()
                    elapsed = time.monotonic() - started_at
                    assert elapsed < 8, f'Unexpected wait after immediate wakeup: {elapsed:.2f}s'
                    print(f'{browser_name}: {"email" if email_only else "browser"} intake started immediately; result appeared in {elapsed:.2f}s', flush=True)
            assert not errors, errors
            browser.close()
            print(f'{browser_name}: real worker stages, animations, reduced motion, connection recovery, focused licenses and mobile layout passed')
    finally:
        for gate in gates:
            gate.set()
        for job in jobs:
            job.join(5)
        server.shutdown()
        serving.join(5)
        settings.stop()
        fixture.tearDown()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--browser', default='chromium')
    run(parser.parse_args().browser)
