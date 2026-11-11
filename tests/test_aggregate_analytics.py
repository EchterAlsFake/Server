"""Synthetic privacy boundary and aggregate reporting regression tests."""
import json
from contextlib import closing
import unittest
import sqlite3
import tempfile
from datetime import date
from pathlib import Path
from unittest.mock import patch

from _support import ServerTestCase, main
from pf_server.aggregate_analytics import AggregateCounters, ENDPOINT, retention_cutoff


class AggregateAnalyticsTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = AggregateCounters(Path(self.directory.name) / 'counts.sqlite3')
        self.old_store = main.app.extensions['aggregate_analytics']
        main.app.extensions['aggregate_analytics'] = self.store
        self.addCleanup(lambda: main.app.extensions.update(aggregate_analytics=self.old_store))
        self.config = patch.dict(main.app.config, AGGREGATE_ANALYTICS_ENABLED=True)
        self.config.start()
        self.addCleanup(self.config.stop)
        self.browser = main.app.test_client(use_cookies=False)
        self.headers = {'Origin': main.app.config['APP_DOMAIN'], 'Sec-Fetch-Site': 'same-origin'}

    def send(self, payload=None, **kwargs):
        return self.browser.post(ENDPOINT, base_url=main.app.config['APP_DOMAIN'],
                                 json=payload or {'page': 'home', 'action': 'pageview'},
                                 headers=kwargs.pop('headers', self.headers), **kwargs)

    def test_csrf_exempt_without_session(self):
        with patch.dict(main.app.config, WTF_CSRF_ENABLED=True):
            self.assertEqual(self.send().status_code, 204)

    def test_counts_only_and_no_cookie(self):
        response = self.send(headers=dict(self.headers, Referer='https://example.org/?email=private@example.org',
                                         **{'User-Agent': 'sensitive-test-agent', 'X-Forwarded-For': '192.0.2.111'}))
        self.assertEqual(response.status_code, 204)
        self.assertNotIn('Set-Cookie', response.headers)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(self.send().status_code, 204)
        with closing(sqlite3.connect(self.store.path)) as connection:
            self.assertEqual([row[1] for row in connection.execute('PRAGMA table_info(daily_counts)')],
                             ['day', 'page', 'action', 'count'])
            self.assertEqual(connection.execute('SELECT page, action, count FROM daily_counts').fetchall(),
                             [('home', 'pageview', 2)])
            dump = '\n'.join(connection.iterdump())
        for secret in ('private@example.org', 'sensitive-test-agent', '192.0.2.111'):
            self.assertNotIn(secret, dump)

    def test_reject_sensitive_and_malformed_events(self):
        for payload in (
            {'page': 'home', 'action': 'pageview', 'email': 'private@example.org'},
            {'page': '/buy_success?session_id=secret', 'action': 'pageview'},
            {'page': 'home', 'action': 'license_bought'},
            {'page': [], 'action': 'pageview'}, ['private@example.org'],
        ):
            self.assertEqual(self.send(payload).status_code, 400)
        self.assertEqual(self.send(headers=dict(self.headers, Cookie='session=secret')).status_code, 400)
        self.assertEqual(self.send(headers=dict(self.headers, Authorization='Bearer secret')).status_code, 400)
        self.assertEqual(self.send(headers={'Origin': 'https://other.example'}).status_code, 403)
        self.assertEqual(self.send(headers={}).status_code, 403)
        self.assertEqual(self.send(query_string={'secret': 'value'}).status_code, 400)
        self.assertEqual(self.send({'page': 'x' * 300, 'action': 'pageview'}).status_code, 413)
        response = self.browser.post(ENDPOINT, base_url=main.app.config['APP_DOMAIN'], data='{}', headers=self.headers)
        self.assertEqual(response.status_code, 415)
        self.assertFalse(self.store.path.exists())

    def test_privacy_signals_and_disabled(self):
        for header in ('DNT', 'Sec-GPC'):
            self.assertEqual(self.send(headers=dict(self.headers, **{header: '1'})).status_code, 204)
        self.assertFalse(self.store.path.exists())
        with patch.dict(main.app.config, AGGREGATE_ANALYTICS_ENABLED=False):
            self.assertEqual(self.send().status_code, 404)
            response = self.browser.get('/', base_url=main.app.config['APP_DOMAIN'])
            self.assertNotIn(b'aggregate-analytics.js', response.data)
        self.assertEqual(self.browser.post(ENDPOINT, base_url=main.app.config['ONION_ORIGIN'], json={}).status_code, 404)

    def test_template_whitelist_and_no_legacy_script(self):
        origin = main.app.config['APP_DOMAIN']
        response = self.browser.get('/guides/download-xvideos-videos?email=private@example.org', base_url=origin)
        self.assertIn(b'data-page="guide_xvideos"', response.data)
        self.assertNotIn(b'/__eaf/visit.js', response.data)
        for path in ('/privacy_policy', '/buy_success?session_id=secret', '/missing'):
            response = self.browser.get(path, base_url=origin)
            self.assertNotIn(b'aggregate-analytics.js', response.data)
        response = self.browser.get('/', base_url=main.app.config['ONION_ORIGIN'])
        self.assertNotIn(b'aggregate-analytics.js', response.data)

    def test_dashboard_export_is_suppressed_and_private(self):
        self.store.increment('home', 'pageview')
        result = main.app.test_cli_runner().invoke(args=['analytics-export'])
        self.assertEqual(result.exit_code, 0, result.output)
        target = self.store.path.parent / 'aggregate-analytics-report.json'
        report = json.loads(target.read_text())
        self.assertEqual(report['rows'], [])
        self.assertTrue(report['enabled'])
        self.assertEqual(target.stat().st_mode & 0o777, 0o640)
        self.assertEqual(list(target.parent.glob('.analytics-report-*')), [])

    def test_unavailable_storage_is_contained(self):
        with patch.object(self.store, 'increment', side_effect=sqlite3.OperationalError('private@example.org')):
            with self.assertLogs(main.app.logger, level='WARNING') as logs:
                self.assertEqual(self.send().status_code, 503)
            self.assertNotIn('private@example.org', ''.join(logs.output))
        self.assertEqual(self.browser.get('/', base_url=main.app.config['APP_DOMAIN']).status_code, 200)

    def test_retention_completed_weeks_and_suppression(self):
        self.assertEqual(retention_cutoff(date(2026, 3, 31)), date(2025, 2, 28))
        with closing(self.store.connect()) as connection, connection:
            connection.executemany('INSERT INTO daily_counts VALUES (?, ?, ?, ?)', [
                ('2025-01-01', 'home', 'pageview', 100),
                ('2026-11-02', 'home', 'pageview', 12),
                ('2026-11-03', 'home', 'pageview', 9),
                ('2026-11-03', 'home', 'open_download', 19),
                ('2026-11-10', 'home', 'pageview', 100),
            ])
        with patch('pf_server.aggregate_analytics.utc_today', return_value=date(2026, 11, 11)):
            report = self.store.report(4)
        self.assertEqual(report['rows'], [dict(week='2026-11-02', page='home', action='pageview', count=21)])
        with closing(sqlite3.connect(self.store.path)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM daily_counts WHERE day='2025-01-01'").fetchone()[0], 0)
        # CLI has no raw event view or business-data join.
        with patch('pf_server.aggregate_analytics.utc_today', return_value=date(2026, 11, 11)):
            result = main.app.test_cli_runner().invoke(args=['analytics-report', '--weeks', '4'])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(json.loads(result.output)['rows'], report['rows'])


class AnalyticsBrowserTests(unittest.TestCase):
    def test_chromium_click_payloads_and_privacy_signals(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest('Playwright is not installed in this runtime')
        script = (Path(__file__).parents[1] / 'static/aggregate-analytics.js').read_text()
        html = '''<!doctype html><a id="download" href="/download/android?email=private@example.org">Android</a>
            <a id="package" data-metric="download_click" href="https://direct6.pornfetch.to/downloads/private-token.zip">Download</a>
            <button id="checkout" data-metric="checkout_continue">Continue</button>
            <script src="/static/aggregate-analytics.js" data-page="guide_xvideos"></script>'''
        with sync_playwright() as playwright:
            if not Path(playwright.chromium.executable_path).exists():
                self.skipTest('Install Playwright Chromium to run the browser privacy check')
            browser = playwright.chromium.launch(headless=True)
            try:
                for privacy in (None, 'dnt', 'gpc'):
                    context = browser.new_context()
                    context.add_cookies([dict(name='session', value='private-session', domain='metrics.invalid', path='/', secure=True)])
                    if privacy:
                        property_name = 'doNotTrack' if privacy == 'dnt' else 'globalPrivacyControl'
                        value = "'1'" if privacy == 'dnt' else 'true'
                        context.add_init_script(f"Object.defineProperty(navigator, '{property_name}', {{get: () => {value}}});")
                    requests = []

                    def route_request(route):
                        if route.request.url.endswith('/static/aggregate-analytics.js'):
                            route.fulfill(content_type='application/javascript', body=script)
                        elif '/_metrics/event' in route.request.url:
                            requests.append((route.request.post_data_json, route.request.all_headers()))
                            route.fulfill(status=204)
                        else:
                            route.fulfill(content_type='text/html', body=html)

                    context.route('**/*', route_request)
                    page = context.new_page()
                    page.goto('https://metrics.invalid/?license=private-license')
                    page.wait_for_load_state('networkidle')
                    page.evaluate("document.addEventListener('click', event => event.preventDefault())")
                    for selector in ('#download', '#package', '#checkout'):
                        if privacy:
                            page.click(selector)
                        else:
                            with page.expect_response('**/_metrics/event'):
                                page.click(selector)
                    page.wait_for_load_state('networkidle')
                    if privacy:
                        self.assertEqual(requests, [])
                    else:
                        self.assertEqual([payload for payload, _headers in requests], [
                            dict(page='guide_xvideos', action=action)
                            for action in ('pageview', 'choose_android', 'download_click', 'checkout_continue')])
                        for _payload, headers in requests:
                            self.assertNotIn('cookie', headers)
                            self.assertNotIn('referer', headers)
                        self.assertNotIn('private', json.dumps([payload for payload, _ in requests]))
                        self.assertEqual(page.evaluate('localStorage.length + sessionStorage.length'), 0)
                    context.close()
            finally:
                browser.close()
