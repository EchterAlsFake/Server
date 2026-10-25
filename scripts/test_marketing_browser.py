"""Local HTTPS browser checks. No external requests or real payments.

Run with: uv run --with playwright python scripts/test_marketing_browser.py
"""
import argparse
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


def run(browser_name='chromium'):
    fixture = ServerTestCase()
    fixture.setUp()
    main.app.config['WTF_CSRF_ENABLED'] = True
    server = make_server('127.0.0.1', 0, main.app, ssl_context='adhoc', threaded=True, request_handler=main.NoIPLoggingHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    origin = f'https://localhost:{server.server_port}'
    def route_request(route):
        if route.request.url.startswith(origin):
            route.continue_()
        elif route.request.url.startswith('https://www.patreon.com/'):
            route.fulfill(body='<h1>Mock Patreon page</h1>', content_type='text/html')
        else:
            route.abort()
    failures = []
    try:
        with patch.dict(main.app.config, {'CHECKLIST_AUTH': 'mobile-checklist-test'}), sync_playwright() as p:
            browser = getattr(p, browser_name).launch()
            context = browser.new_context(ignore_https_errors=True, viewport={'width': 1440, 'height': 1100})
            context.route('**/*', route_request)
            page = context.new_page()
            page.on('pageerror', lambda error: failures.append(str(error)))
            page.goto(origin + '/porn_fetch')
            expect(page.locator('#age-overlay')).to_be_visible()
            assert page.locator('#site-content').evaluate('(el) => el.inert')
            assert page.locator('#product-video').count() == 0
            page.keyboard.press('Escape')
            expect(page.locator('#age-overlay')).to_be_visible()
            for _ in range(12):
                page.keyboard.press('Tab')
                assert page.locator('.age-dialog').evaluate('(el) => el.contains(document.activeElement)')
            page.screenshot(path='/tmp/porn-fetch-age-desktop.png')
            page.get_by_role('link', name='Privacy / Datenschutz', exact=True).last.click()
            expect(page.locator('#en')).to_be_visible()
            expect(page.locator('#de')).to_be_visible()
            expect(page.locator('#age-overlay')).to_have_count(0)
            page.goto(origin + '/porn_fetch')
            page.locator('#adult-confirmed').check()
            page.get_by_role('button', name='Confirm & enter').click()
            expect(page.locator('#age-overlay')).to_have_count(0)
            expect(page.locator('#site-content')).not_to_have_attribute('inert')
            page.goto(origin + '/')
            page.wait_for_function('() => document.querySelector("video").readyState >= 2')
            page.wait_for_function('() => document.querySelector("video").currentTime > 0')
            page.locator('#platforms').scroll_into_view_if_needed()
            expect(page.locator('video')).to_have_js_property('paused', True)
            page.locator('video').scroll_into_view_if_needed()
            expect(page.locator('video')).to_have_js_property('paused', False)
            page.locator('video').evaluate('(el) => el.pause()')
            for image in page.locator('.screenshot-frame img').all():
                image.scroll_into_view_if_needed()
                image.evaluate('(el) => { el.loading = "eager"; }')
                expect(image).to_have_js_property('complete', True)
                image.evaluate('(el) => el.decode()')
            page.evaluate('window.scrollTo({top: 0, behavior: "instant"})')
            page.screenshot(path='/tmp/porn-fetch-home-desktop.png', full_page=True)
            page.screenshot(path='/tmp/porn-fetch-hero-desktop.png')
            assert page.locator('.capability-table tbody tr').count() == 15
            assert page.locator('.site-menu nav').is_visible()
            assert page.locator('.product-hero .product-actions a').count() == 4
            expect(page.locator('.product-hero .btn-source')).to_have_attribute('href', 'https://github.com/EchterAlsFake/Porn_Fetch')
            expect(page.locator('.site-menu .github-nav')).to_be_visible()
            expect(page.locator('.site-footer a[href="https://github.com/EchterAlsFake/Porn_Fetch"]')).to_be_visible()
            expect(page.locator('.site-menu a[href="/download"]')).to_be_visible()
            page.goto(origin + '/porn_fetch')
            expect(page.locator('.payment-detail:visible')).to_have_count(0)
            assert page.evaluate('Array.from(document.querySelectorAll(".payment-brand-strip img, .provider-brand img")).every(img => img.complete && img.naturalWidth > 0)'), 'Payment brand artwork failed to decode'
            for method in ('crypto', 'patreon', 'card', 'crypto'):
                expect(page.locator(f'#method-{method}')).to_be_enabled()
                page.locator(f'#method-{method}').check()
                expect(page.locator(f'#method-{method}')).to_be_checked()
            page.locator('#method-patreon').check()
            page.locator('#checkout-country').select_option('DE')
            for checkbox in ('chk-age-terms', 'chk-withdrawal', 'chk-test-site'):
                page.locator('#' + checkbox).check()
            page.locator('#checkout-continue').click()
            expect(page.locator('#payment-test-dialog')).to_be_visible()
            expect(page.locator('#payment-test-continue')).to_be_disabled()
            page.locator('#payment-test-cancel').click()
            expect(page.locator('#payment-test-dialog')).not_to_be_visible()
            page.locator('#checkout-country').select_option('DE')
            for checkbox in ('chk-age-terms', 'chk-withdrawal', 'chk-test-site'):
                page.locator('#' + checkbox).check()
            page.locator('#checkout-continue').click()
            expect(page.locator('#payment-test-ack')).not_to_be_checked()
            page.locator('#payment-test-ack').check()
            with context.expect_page() as preview_event:
                page.locator('#payment-test-continue').click()
            preview = preview_event.value
            expect(preview.get_by_role('heading', name='Mock Patreon page')).to_be_visible()
            preview.close()
            page.locator('#method-card').check()
            page.locator('#checkout-continue').click()
            expect(page.locator('#payment-test-dialog')).to_be_visible()
            expect(page.locator('#payment-test-ack')).not_to_be_checked()
            page.locator('#payment-test-ack').check()
            page.locator('#payment-test-continue').click()
            expect(page).to_have_url(origin + '/buy_card')
            expect(page.locator('#onramp-form')).to_be_visible()
            page.goto(origin + '/porn_fetch')
            page.locator('#method-crypto').check()
            expect(page.locator('#checkout-continue')).to_have_text('Continue to crypto checkout')
            page.screenshot(path='/tmp/porn-fetch-payment-desktop.png', full_page=True)
            page.goto(origin + '/')
            page.get_by_role('link', name='Supported Platforms', exact=True).click()
            expect(page).to_have_url(origin + '/#platforms')
            page.goto(origin + '/download')
            expect(page.locator('#age-overlay')).to_have_count(0)
            expect(page.get_by_text('The first website-hosted release', exact=False)).to_be_visible()
            for path in ('/impress', '/privacy_policy', '/terms', '/porn_fetch', '/buy_license', '/buy_card', '/refund_policy', '/about'):
                page.goto(origin + path)
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), path
                if path in ('/impress', '/privacy_policy', '/terms'):
                    page.locator('.language-nav a[href="#de"]').click()
                    assert page.url.endswith('#de')
                if path == '/porn_fetch':
                    page.screenshot(path='/tmp/porn-fetch-license-desktop.png', full_page=True)
                if path == '/privacy_policy':
                    page.evaluate('window.scrollTo({top: 0, behavior: "instant"})')
                    page.screenshot(path='/tmp/porn-fetch-privacy-desktop.png')
                if path == '/buy_license':
                    page.screenshot(path='/tmp/porn-fetch-checkout-desktop.png', full_page=True)
                    expect(page.locator('#pay-btn')).to_be_enabled()
            mobile_paths = (
                '/', '/download', '/privacy_policy', '/terms', '/impress',
                '/porn_fetch', '/buy_license', '/buy_card', '/buy_success',
                '/buy_cancel', '/refund_policy', '/legal-statement', '/about',
                '/donation', '/stats', '/checklist/login', '/checklist',
                '/payment-preview/card', '/payment-preview/patreon', '/help', '/releases',
                '/download/windows', '/download/linux', '/download/macos', '/download/android', '/download/ios', '/download/cli',
                '/docs/', '/docs/transparency/', '/docs/eaf_base_api/', '/docs/pornhub/',
            )
            for width, height in ((375, 812), (768, 1024), (667, 375)):
                page.set_viewport_size({'width': width, 'height': height})
                for path in mobile_paths:
                    response = page.goto(origin + path)
                    assert response.status == 200, (path, response.status)
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), f'mobile overflow at {width}: {path}'
                    assert page.locator('#main-content').evaluate('el => el.scrollWidth <= el.clientWidth'), f'content overflow at {width}: {path}'
                    if path == '/porn_fetch' and width == 375:
                        page.locator('#method-crypto').check()
                        page.evaluate('window.scrollTo({top: 0, behavior: "instant"})')
                        page.screenshot(path='/tmp/porn-fetch-payment-mobile.png', full_page=True)
                print(f'Public pages fit {width}×{height}.', flush=True)
            page.set_viewport_size({'width': 375, 'height': 812})
            page.goto(origin + '/checklist/login')
            page.locator('#checklist-password').fill('mobile-checklist-test')
            page.get_by_role('button', name='Login', exact=True).click()
            expect(page.locator('#add-task-form')).to_be_visible()
            task = 'Review ' + 'license_delivery_' * 8
            page.locator('#new-task-input').fill(task)
            page.get_by_role('button', name='Add Task', exact=True).click()
            item = page.locator('.task-item').filter(has_text=task)
            expect(item).to_be_visible()
            assert page.locator('.checklist-container').evaluate('el => el.scrollWidth <= el.clientWidth'), 'Long task overflow'
            item.get_by_role('checkbox').check()
            expect(item.locator('.task-text')).to_have_class('task-text done')
            page.evaluate('window.scrollTo({top: 0, behavior: "instant"})')
            page.screenshot(path='/tmp/porn-fetch-checklist-mobile.png', full_page=True)
            item.get_by_role('button', name='Remove task: ' + task, exact=True).click()
            expect(item).to_have_count(0)
            page.goto(origin + '/donation')
            expect(page.locator('#donation-options')).to_have_attribute('inert', '')
            page.locator('#chk-age-donation').check()
            page.locator('#chk-country-donation').check()
            expect(page.locator('#donation-options')).not_to_have_attribute('inert')
            expect(page.locator('#iframe-overlay')).to_be_hidden()
            page.locator('a[href="#crypto-widget"]').click()
            expect(page).to_have_url(origin + '/donation#crypto-widget')
            page.locator('#chk-country-donation').uncheck()
            expect(page.locator('#donation-options')).to_have_attribute('inert', '')
            page.goto(origin + '/docs/')
            package_count = page.locator('.api-card').count()
            page.locator('#apiSearch').fill('pornhub')
            expect(page.locator('.api-card:visible')).to_have_count(1)
            page.get_by_role('button', name='Clear search', exact=True).click()
            expect(page.locator('.api-card:visible')).to_have_count(package_count)
            page.get_by_role('button', name='Open navigation', exact=True).click()
            expect(page.locator('#sidebar')).to_have_class('sidebar open')
            expect(page.locator('#mobileToggle')).to_have_attribute('aria-expanded', 'true')
            page.keyboard.press('Escape')
            expect(page.locator('#mobileToggle')).to_have_attribute('aria-expanded', 'false')
            page.goto(origin + '/')
            for image in page.locator('.screenshot-frame img').all():
                image.scroll_into_view_if_needed()
                image.evaluate('(el) => { el.loading = "eager"; }')
                expect(image).to_have_js_property('complete', True)
                image.evaluate('(el) => el.decode()')
            page.evaluate('window.scrollTo({top: 0, behavior: "instant"})')
            page.screenshot(path='/tmp/porn-fetch-home-mobile.png', full_page=True)
            page.screenshot(path='/tmp/porn-fetch-hero-mobile.png')
            page.locator('.site-menu summary').click()
            expect(page.get_by_role('link', name='Supported Websites', exact=True)).to_be_visible()
            page.keyboard.press('Escape')
            assert not page.locator('.site-menu').evaluate('(el) => el.open')
            page.goto(origin + '/leave')
            expect(page.get_by_role('heading', name="You're all set.")).to_be_visible()
            page.goto(origin + '/')
            expect(page.locator('#age-overlay')).to_have_count(0)
            page.goto(origin + '/porn_fetch')
            page.screenshot(path='/tmp/porn-fetch-age-mobile.png')
            expect(page.locator('#age-overlay')).to_be_visible()
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            context.close()

            reduced = browser.new_context(ignore_https_errors=True, reduced_motion='reduce')
            reduced.route('**/*', route_request)
            reduced_page = reduced.new_page()
            reduced_page.goto(origin + '/')
            expect(reduced_page.locator('#age-overlay')).to_have_count(0)
            assert reduced_page.locator('video').evaluate('(el) => el.paused')
            assert reduced_page.locator('.brand-name').first.evaluate('(el) => getComputedStyle(el).animationName') == 'none'
            reduced.close()

            no_js = browser.new_context(ignore_https_errors=True, java_script_enabled=False)
            no_js.route('**/*', route_request)
            fallback = no_js.new_page()
            fallback.goto(origin + '/buy_license')
            fallback.locator('#adult-confirmed').check()
            fallback.get_by_role('button', name='Confirm & enter').click()
            expect(fallback).to_have_url(origin + '/buy_license')
            expect(fallback.locator('#age-overlay')).to_have_count(0)
            fallback.goto(origin + '/')
            expect(fallback.locator('.site-menu nav')).to_be_visible()
            expect(fallback.get_by_role('link', name='Watch the 40-second product tour')).to_be_visible()
            fallback.goto(origin + '/porn_fetch')
            expect(fallback.locator('#checkout-continue')).to_be_visible()
            fallback.locator('#method-crypto').check()
            fallback.locator('#checkout-country').select_option('DE')
            for checkbox in ('chk-age-terms', 'chk-withdrawal', 'chk-test-site'):
                fallback.locator('#' + checkbox).check()
            fallback.locator('#checkout-continue').click()
            expect(fallback).to_have_url(origin + '/buy_license')
            expect(fallback.get_by_text('Enable JavaScript to create a cryptocurrency payment.')).to_be_visible()
            fallback.goto(origin + '/porn_fetch')
            fallback.locator('#method-patreon').check()
            fallback.locator('#checkout-continue').click()
            expect(fallback.locator('.payment-preview-page')).to_contain_text('Do not send money')
            fallback.locator('.payment-preview-page input[name="confirm_no_payment"]').check()
            with no_js.expect_page() as fallback_event:
                fallback.get_by_role('button', name='I understand. Continue to preview').click()
            launched = fallback_event.value
            expect(launched.locator('#provider-launch')).to_be_visible()
            launched.locator('#provider-launch').click()
            expect(launched.get_by_role('heading', name='Mock Patreon page')).to_be_visible()
            no_js.close()
            browser.close()
        assert not failures, failures
        print('Passed: age session, legal access, video playback, navigation, release fallback, public pages at phone/tablet/landscape widths, checklist editing, donation controls, docs search, reduced motion and no-JavaScript form.')
        print('Screenshots: /tmp/porn-fetch-{home,age}-{desktop,mobile}.png')
    finally:
        server.shutdown()
        worker.join(timeout=5)
        fixture.tearDown()
        fixture.doCleanups()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--browser', choices=('chromium', 'firefox', 'webkit'), default='chromium')
    run(parser.parse_args().browser)
