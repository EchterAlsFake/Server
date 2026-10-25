"""Crawlability, metadata consistency, and the public guide surface."""

import json
from html.parser import HTMLParser
from urllib.parse import urlsplit
from unittest.mock import patch
from xml.etree import ElementTree

from _support import ServerTestCase, main
from pf_server.guide_content import GUIDES, GUIDE_DATE, guide_path
from pf_server.product_catalog import WEBSITES


class Page(HTMLParser):
    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.meta = {}
        self.links = []
        self.ids = set()
        self.title = ""
        self.h1s = []
        self.structured = []
        self.canonical = None
        self._tag = None
        self._text = ""
        self.feed(html)

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if tag == "meta":
            self.meta[attrs.get("name", attrs.get("property"))] = attrs.get("content")
        if tag == "a" and "href" in attrs:
            self.links.append(attrs["href"])
        if tag == "link" and attrs.get("rel") == "canonical":
            self.canonical = attrs["href"]
        if tag in {"title", "h1"} or (tag == "script" and attrs.get("type") == "application/ld+json"):
            self._tag, self._text = tag, ""

    def handle_data(self, data):
        if self._tag:
            self._text += data

    def handle_endtag(self, tag):
        if tag != self._tag:
            return
        if tag == "title":
            self.title = self._text
        elif tag == "h1":
            self.h1s.append(self._text)
        else:
            self.structured.append(json.loads(self._text))
        self._tag = None


class SEOTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.origin = "https://pornfetch.to"
        self.config = patch.dict(main.app.config, {
            "APP_DOMAIN": self.origin, "SEO_INDEXING_ENABLED": True,
            "NOWPAYMENTS_SANDBOX": True,
        })
        self.config.start()
        self.addCleanup(self.config.stop)

    def get(self, path, **kwargs):
        return self.client.get(path, base_url=self.origin, **kwargs)

    def test_public_indexing_is_independent_of_payment_testing(self):
        for sandbox in (True, False):
            with self.subTest(sandbox=sandbox), patch.dict(main.app.config, {"NOWPAYMENTS_SANDBOX": sandbox}):
                response = self.get("/")
                self.assertEqual(Page(response.text).meta["robots"], "index, follow")
                self.assertEqual(response.headers["X-Robots-Tag"], "index, follow")
                self.assertEqual(self.get("/sitemap.xml").status_code, 200)
                self.assertIn("Sitemap: https://pornfetch.to/sitemap.xml", self.get("/robots.txt").text)

    def test_staging_remains_crawlable_so_noindex_can_be_seen(self):
        with patch.dict(main.app.config, {"SEO_INDEXING_ENABLED": False}):
            for path in ("/", "/download", "/guides", guide_path("pornhub")):
                response = self.get(path)
                self.assertEqual(response.headers["X-Robots-Tag"], "noindex, nofollow")
                self.assertEqual(Page(response.text).meta["robots"], "noindex, nofollow")
            self.assertEqual(self.get("/sitemap.xml").status_code, 404)
            robots = self.get("/robots.txt").text
            self.assertIn("Allow: /", robots)
            self.assertNotIn("Disallow: /", robots)
            self.assertNotIn("Sitemap:", robots)

    def test_every_supported_provider_has_an_accessible_accurate_guide(self):
        self.assertEqual({row[0] for row in WEBSITES}, {guide["name"] for guide in GUIDES.values()})
        titles, descriptions = set(), set()
        hub = Page(self.get("/guides").text)
        for provider, guide in GUIDES.items():
            with self.subTest(provider=provider):
                path = guide_path(provider)
                self.assertIn(path, hub.links)
                response = self.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertNotIn('id="age-overlay"', response.text)
                page = Page(response.text)
                self.assertEqual(len(page.h1s), 1)
                self.assertIn(guide["name"], page.h1s[0])
                self.assertEqual(page.canonical, self.origin + path)
                self.assertEqual(page.meta["robots"], "index, follow")
                self.assertEqual(page.meta["rating"], "adult")
                self.assertEqual(page.title, page.meta["og:title"])
                self.assertEqual(page.title, page.meta["twitter:title"])
                self.assertNotIn(page.title, titles)
                self.assertNotIn(page.meta["description"], descriptions)
                titles.add(page.title)
                descriptions.add(page.meta["description"])
                graph = page.structured[0]["@graph"]
                article = next(item for item in graph if item["@type"] == "Article")
                self.assertEqual(article["dateModified"], GUIDE_DATE)
                self.assertEqual(article["mainEntityOfPage"], page.canonical)
                crumbs = next(item for item in graph if item["@type"] == "BreadcrumbList")
                self.assertEqual(len(crumbs["itemListElement"]), 3)
                for link in page.links:
                    if link.startswith("#"):
                        self.assertIn(link[1:], page.ids)

    def test_sitemap_only_lists_indexable_successful_pages(self):
        root = ElementTree.fromstring(self.get("/sitemap.xml").data)
        namespace = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        locations = [item.text for item in root.findall("s:url/s:loc", namespace)]
        self.assertEqual(len(locations), len(set(locations)))
        for provider in GUIDES:
            self.assertIn(self.origin + guide_path(provider), locations)
        for url in locations:
            with self.subTest(url=url):
                response = self.get(urlsplit(url).path)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers["X-Robots-Tag"], "index, follow")
                self.assertEqual(Page(response.text).canonical, url)
        for private in ("/porn_fetch", "/buy_license", "/buy_card", "/download_license", "/checklist", "/download/catalog.json"):
            self.assertNotIn(self.origin + private, locations)

    def test_canonicals_drop_query_strings_and_ignore_forwarded_host_input(self):
        response = self.get(guide_path("pornhub") + "?utm_source=test", headers={"Host": "other.example"})
        page = Page(response.text)
        self.assertEqual(page.canonical, self.origin + guide_path("pornhub"))
        self.assertEqual(page.meta["robots"], "noindex, nofollow")

    def test_www_redirect_preserves_path_and_query_only_for_safe_requests(self):
        path = guide_path("pornhub") + "?utm_source=test"
        response = self.client.get(path, base_url="https://www.pornfetch.to")
        self.assertEqual(response.status_code, 308)
        self.assertEqual(response.headers["Location"], self.origin + path)
        response = self.client.post("/checkout/start", base_url="https://www.pornfetch.to", json={})
        self.assertNotEqual(response.status_code, 308)

    def test_private_and_unknown_pages_are_not_indexable(self):
        for path in ("/porn_fetch", "/buy_license", "/download/catalog.json", "/ping"):
            response = self.get(path)
            self.assertIn("noindex", response.headers["X-Robots-Tag"])
        for path in (guide_path("missav"), guide_path("hqporner"), "/guides/download-PornHub-videos"):
            response = self.get(path)
            self.assertEqual(response.status_code, 404)
            self.assertIn("noindex", response.headers["X-Robots-Tag"])

    def test_guides_are_linked_from_existing_entry_pages(self):
        for path in ("/", "/help", "/download/windows"):
            self.assertIn("/guides", Page(self.get(path).text).links)
        home = Page(self.get("/").text)
        for provider in GUIDES:
            self.assertIn(guide_path(provider), home.links)

    def test_empty_and_unavailable_catalogs_do_not_invent_downloads(self):
        for unavailable, expected in ((False, "first website-hosted packages"), (True, "temporarily unavailable")):
            with patch("pf_server.guide_routes.load_catalog", return_value={"releases": [], "unavailable": unavailable}):
                response = self.get(guide_path("pornhub"))
                self.assertIn(expected, response.text)
                self.assertNotIn('/downloads/3.9', response.text)

    def test_onion_guides_remain_public_read_only_and_unindexed(self):
        response = self.client.get(guide_path("pornhub"), base_url=main.app.config["ONION_ORIGIN"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Robots-Tag"], "noindex, follow")
        self.assertEqual(Page(response.text).meta["robots"], "noindex, follow")
        self.assertEqual(Page(response.text).canonical, self.origin + guide_path("pornhub"))
