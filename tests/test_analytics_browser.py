"""Synthetic browser check of anonymous events and optional feedback."""
import json
import unittest
from pathlib import Path


class BrowserAnalyticsTests(unittest.TestCase):
    def test_events_visibility_feedback_and_privacy(self):
        try:
            from playwright.sync_api import sync_playwright
        except ModuleNotFoundError as error:
            if error.name != 'playwright':
                raise
            self.skipTest('Playwright is optional; install the dev dependencies to run browser checks')
        script = (Path(__file__).parents[1] / 'static/aggregate-analytics.js').read_text()
        html = '''<header class="site-header"><a href="/porn_fetch" id="premium">Premium</a></header>
            <a id="package" data-metric="download_click" href="/downloads/file.zip">Get app</a>
            <a id="checksum" href="/downloads/file.zip.sha256">Checksum</a>
            <section id="premium-feedback" hidden><button data-feedback="price">Lower price</button>
            <p id="premium-feedback-status" role="status"></p></section>
            <script src="/static/aggregate-analytics.js" data-page="premium"></script>'''
        with sync_playwright() as p:
            if not Path(p.chromium.executable_path).exists():
                self.skipTest('Playwright Chromium is not installed')
            browser = p.chromium.launch()
            try:
                for privacy in (None, 'doNotTrack', 'globalPrivacyControl'):
                    context = browser.new_context()
                    context.add_cookies([dict(name='session',value='private',domain='analytics.invalid',path='/')])
                    if privacy:
                        value = "'1'" if privacy == 'doNotTrack' else 'true'
                        context.add_init_script(f"Object.defineProperty(navigator,'{privacy}',{{get:()=>{value}}})")
                    events=[]
                    def route(r):
                        if r.request.url.endswith('aggregate-analytics.js'):
                            r.fulfill(content_type='application/javascript',body=script)
                        elif '/_metrics/event' in r.request.url:
                            events.append((r.request.post_data_json,r.request.all_headers()))
                            r.fulfill(status=204)
                        else:r.fulfill(content_type='text/html',body=html)
                    context.route('**/*',route)
                    page=context.new_page()
                    page.goto('https://analytics.invalid/?email=private@example.org')
                    page.wait_for_load_state('networkidle')
                    page.evaluate("document.addEventListener('click', e=>e.preventDefault())")
                    page.click('#premium');page.click('#package');page.click('#checksum')
                    if privacy:
                        self.assertTrue(page.locator('#premium-feedback').is_hidden())
                    else:
                        page.click('[data-feedback]')
                        page.wait_for_function("document.querySelector('[data-feedback]').disabled")
                        page.evaluate('window.scrollTo(0,0)')
                    page.wait_for_load_state('networkidle')
                    actions=[e[0]['action'] for e in events]
                    if privacy:self.assertEqual(events,[])
                    else:
                        self.assertEqual(actions.count('visible_premium_header'),1)
                        self.assertEqual(actions.count('download_click'),1)
                        self.assertEqual(actions.count('feedback_price'),1)
                        self.assertIn('click_premium_header',actions)
                        for payload,headers in events:
                            self.assertEqual(set(payload),{'page','action'})
                            self.assertNotIn('cookie',headers)
                            self.assertNotIn('referer',headers)
                        self.assertNotIn('private',json.dumps([e[0] for e in events]))
                        self.assertEqual(page.evaluate('localStorage.length+sessionStorage.length'),0)
                    context.close()
            finally:browser.close()
