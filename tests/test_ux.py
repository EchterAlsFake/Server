"""Essential product choices remain accurate in the simplified presentation."""
from html.parser import HTMLParser
from unittest.mock import patch
from _support import ServerTestCase
from pf_server.product_catalog import WEBSITES

class Cards(HTMLParser):
    def __init__(self):
        super().__init__()
        self.cards = {}
        self.current = None
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'article' and attrs.get('class') == 'website-result':
            self.current = attrs['id']
            self.cards[self.current] = ''
    def handle_endtag(self, tag):
        if tag == 'article': self.current = None
    def handle_data(self, data):
        if self.current: self.cards[self.current] += data

class SimplifiedUXTests(ServerTestCase):
    def test_each_compatibility_card_preserves_catalog_limits(self):
        parser = Cards()
        parser.feed(self.client.get('/').text)
        self.assertEqual(len(parser.cards), len(WEBSITES))
        labels = {'Yes': 'Supported', '—': 'Not available', 'Account only': 'Requires a connected account', 'CLI only': 'Command line only'}
        for website in WEBSITES:
            card = parser.cards['support-' + website[0].lower()]
            for value in set(website[1:]):
                self.assertIn(labels[value], card)

    def test_free_start_and_essential_disclosures_are_available_without_scripts(self):
        page = self.client.get('/').text
        for text in ('Download Free', 'up to 720p', 'One active download', '5-video preview',
                     'within 1 year of first activation', 'periodic online validation',
                     'No automatic renewal', 'none guarantees anonymity', 'IP-derived check values'):
            self.assertIn(text, page)
        self.assertLess(page.index('id="features"'), page.index('id="websites"'))
        self.assertLess(page.index('id="websites"'), page.index('id="premium"'))
        self.assertLess(page.index('id="premium"'), page.index('id="advanced-title"'))
        self.assertIn('Preview Premium Checkout', page)
        with patch.dict(__import__('_support').main.app.config, NOWPAYMENTS_SANDBOX=False):
            self.assertIn('Get Premium', self.client.get('/').text)

    def test_premium_summary_explains_the_same_entitlement_in_both_places(self):
        for path in ('/', '/porn_fetch'):
            page = self.client.get(path).text
            for text in ('within 1 year of first activation', 'not the date you buy',
                         'Keep Premium in eligible releases afterwards',
                         'periodic online validation', 'No automatic renewal',
                         'Up to 10 active installations'):
                self.assertIn(text, page)

    def test_simple_opening_and_advanced_depth_are_available_without_scripts(self):
        page = self.client.get('/').text
        self.assertIn('Free to start. No account needed for the app.', page)
        self.assertIn('Simple by default.', page)
        self.assertIn('Control local database writing', page)
        self.assertIn('History and statistics are unavailable on Android', page)
        self.assertIn('data-tour-time="0"', page)
        self.assertIn('data-tour-time="17"', page)
