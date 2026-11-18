"""Crawlability, metadata consistency, and the public guide surface."""

import json
import re
from collections import Counter
from html import unescape
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
        self.language = None
        self.alternates = {}
        self._tag = None
        self._text = ""
        self.feed(html)

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if tag == "meta":
            self.meta[attrs.get("name", attrs.get("property"))] = attrs.get("content")
        if tag == "html":
            self.language = attrs.get("lang")
        if tag == "a" and "href" in attrs:
            self.links.append(attrs["href"])
        if tag == "link" and attrs.get("rel") == "canonical":
            self.canonical = attrs["href"]
        if tag == "link" and attrs.get("rel") == "alternate" and "hreflang" in attrs:
            self.alternates[attrs["hreflang"]] = attrs["href"]
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
            for path in ("/", "/download", "/guides", guide_path("pornhub"), "/hi" + guide_path("pornhub")):
                response = self.get(path)
                self.assertEqual(response.headers["X-Robots-Tag"], "noindex, nofollow")
                self.assertEqual(Page(response.text).meta["robots"], "noindex, nofollow")
                self.assertFalse(Page(response.text).alternates)
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
                self.assertNotIn("rating", page.meta)
                self.assertEqual(page.title, page.meta["og:title"])
                self.assertEqual(page.title, page.meta["twitter:title"])
                self.assertNotIn(page.title, titles)
                self.assertNotIn(page.meta["description"], descriptions)
                titles.add(page.title)
                descriptions.add(page.meta["description"])
                graph = page.structured[0]["@graph"]
                article = next(item for item in graph if item["@type"] == "Article")
                self.assertEqual(article["dateModified"], guide.get("updated", guide.get("published", GUIDE_DATE)))
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
            for prefix in ("", "/de", "/es", "/hi", "/zh-hans"):
                self.assertIn(self.origin + prefix + guide_path(provider), locations)
        page_titles = {}
        page_descriptions = {}
        for url in locations:
            with self.subTest(url=url):
                response = self.get(urlsplit(url).path)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers["X-Robots-Tag"], "index, follow")
                page = Page(response.text)
                self.assertEqual(page.canonical, url)
                self.assertNotIn("rating", page.meta)
                self.assertEqual(len(page.h1s), 1)
                for value, seen in ((page.title, page_titles), (page.meta["description"], page_descriptions)):
                    self.assertTrue(value.strip())
                    localized_values = seen.setdefault(page.language, set())
                    self.assertNotIn(value, localized_values)
                    localized_values.add(value)
                self.assertEqual(page.meta["description"], page.meta["og:description"])
                self.assertEqual(page.meta["description"], page.meta["twitter:description"])
        for private in ("/porn_fetch", "/buy_license", "/buy_card", "/download_license", "/checklist", "/download/catalog.json"):
            self.assertNotIn(self.origin + private, locations)

    def test_priority_guides_show_localized_opening_steps_and_search_descriptions(self):
        from pf_server.website_locale import LANGUAGES, catalog_for, path_in_language

        sitemap = ElementTree.fromstring(self.get("/sitemap.xml").data)
        last_modified = {
            entry.findtext("{*}loc"): entry.findtext("{*}lastmod")
            for entry in sitemap.findall("{*}url")
        }
        for provider in ("eporner", "xhamster"):
            guide = GUIDES[provider]
            for locale in LANGUAGES:
                with self.subTest(provider=provider, locale=locale):
                    catalog = catalog_for(locale)
                    path = path_in_language(guide_path(provider), locale)
                    html = self.get(path).text
                    page = Page(html)
                    rendered = unescape(html)
                    intro = guide["intro"] if locale == "en" else catalog[guide["intro"]]
                    description = guide["description"] if locale == "en" else catalog[guide["description"]]
                    self.assertIn(f'<p class="guide-lead">{intro}</p>', rendered)
                    self.assertEqual(rendered.count(intro), 1)
                    self.assertEqual(page.meta["description"], description)
                    self.assertEqual(page.meta["og:description"], description)
                    self.assertEqual(page.meta["twitter:description"], description)
                    self.assertEqual(last_modified[self.origin + path], guide["updated"])

    def test_download_pages_identify_the_platform_and_keep_channel_urls_canonical(self):
        expectations = {
            "/download": ("Download Porn Fetch", "SHA-256"),
            "/download/windows": ("Windows", "x64"),
            "/download/linux": ("Linux", "Wayland"),
            "/download/macos": ("macOS", "Apple Silicon"),
            "/download/android": ("Android", "APK"),
            "/download/ios": ("iPhone & iPad", "IPA"),
            "/download/cli": ("CLI", "terminal"),
        }
        hub = Page(self.get("/download").text)
        for prefix in ("", "/es"):
            for path, (heading, detail) in expectations.items():
                with self.subTest(path=prefix + path):
                    page = Page(self.get(prefix + path + "?channel=beta").text)
                    self.assertEqual(page.canonical, self.origin + prefix + path)
                    self.assertIn(prefix + "/guides", page.links)
                    self.assertIn(path, hub.links)
                    if not prefix:
                        self.assertIn(heading, page.h1s[0])
                    self.assertIn(detail.lower(), page.meta["description"].lower())

    def test_every_localized_guide_has_translated_content_and_reciprocal_seo(self):
        from pf_server.website_locale import catalog_for

        locales = {"de": "de", "es": "es", "hi": "hi", "zh-hans": "zh-Hans"}
        hub_html = {code: self.get(f"/{code}/guides").text for code in locales}
        hubs = {code: Page(html) for code, html in hub_html.items()}
        homes = {code: Page(self.get(f"/{code}/").text) for code in locales}
        for provider, guide in GUIDES.items():
            path = guide_path(provider)
            english = Page(self.get(path, headers={"Accept-Language": "de,es,hi,zh-Hans"}).text)
            self.assertEqual(english.language, "en")
            self.assertEqual(english.alternates, {
                "en": self.origin + path, "x-default": self.origin + path,
                **{tag: f"{self.origin}/{code}{path}" for code, tag in locales.items()},
            })
            for code, tag in locales.items():
                with self.subTest(provider=provider, locale=code):
                    prefix = f"/{code}"
                    localized_path = prefix + path
                    self.assertIn(localized_path, hubs[code].links)
                    self.assertIn(localized_path, homes[code].links)
                    response = self.get(localized_path + "?utm_source=test")
                    self.assertEqual(response.status_code, 200)
                    self.assertIn('class="guide-surface guide-detail"', response.text)
                    page = Page(response.text)
                    self.assertEqual(page.language, tag)
                    self.assertEqual(page.canonical, self.origin + localized_path)
                    self.assertEqual(page.alternates, english.alternates)
                    self.assertIn(path, page.links)
                    self.assertIn(prefix + "/download/android", page.links)
                    self.assertIn(prefix + "/help", page.links)
                    self.assertIn(guide["name"], page.h1s[0])
                    self.assertNotEqual(page.h1s, english.h1s)
                    self.assertNotEqual(page.meta["description"], english.meta["description"])
                    self.assertNotIn("rating", page.meta)
                    article = next(item for item in page.structured[0]["@graph"] if item["@type"] == "Article")
                    self.assertEqual(article["inLanguage"], tag)
                    self.assertEqual(article["mainEntityOfPage"], page.canonical)
                    translations = catalog_for(code)
                    self.assertIn(translations[guide["summary"]], unescape(hub_html[code]))
                    rendered = unescape(response.text)
                    self.assertIn(f'<p class="guide-lead">{translations[guide["intro"]]}</p>', rendered)
                    if "description" not in guide:
                        self.assertIn(translations[guide["summary"]], page.meta["description"])
                    for message in (guide["intro"], guide["question"], guide["answer"],
                                    *(text for heading, paragraphs in guide["sections"] for text in (heading, *paragraphs))):
                        self.assertNotEqual(translations[message], message)
                        self.assertIn(translations[message], rendered)

    def test_release_note_alternates_require_localized_content(self):
        release = {"version": "4.0.0", "notes": "Original notes", "channel": "stable",
                   "artifacts": [], "commit": "abcdef", "published_at": "2026-11-18"}
        data = {"releases": [release], "unavailable": False}
        with patch("pf_server.download_pages.load_catalog", return_value=data):
            self.assertEqual(self.get("/de/releases/4.0.0").status_code, 404)
            self.assertNotIn("de", Page(self.get("/releases/4.0.0").text).alternates)
            self.assertNotIn("/de/releases/4.0.0", self.get("/sitemap.xml").text)
            self.assertNotIn("Original notes", self.get("/de/releases").text)
            release["notes_i18n"] = {"de": "Deutsche Versionshinweise"}
            response = self.get("/de/releases/4.0.0")
            self.assertEqual(response.status_code, 200)
            self.assertIn("Deutsche Versionshinweise", response.text)
            page = Page(response.text)
            self.assertEqual(page.alternates["de"], self.origin + "/de/releases/4.0.0")
            self.assertEqual(set(page.alternates), {"en", "de", "x-default"})
            self.assertIn("2026-11-18", page.meta["description"])
            self.assertIn("Versionshinweise", page.meta["description"])
            self.assertIn("/de/releases/4.0.0", self.get("/sitemap.xml").text)

    def test_translation_catalogs_preserve_interpolation(self):
        from pf_server.website_locale import LANGUAGES, catalog_for

        pattern = re.compile(r"%\((\w+)\)s|%%")
        for locale in LANGUAGES:
            for source, translation in catalog_for(locale).items():
                with self.subTest(locale=locale, source=source):
                    self.assertTrue(translation.strip())
                    self.assertEqual(Counter(pattern.findall(translation)), Counter(pattern.findall(source)))
                    self.assertNotIn("%", pattern.sub("", translation))

    def test_canonicals_drop_query_strings_and_ignore_forwarded_host_input(self):
        response = self.get(guide_path("pornhub") + "?utm_source=test", headers={"Host": "other.example"})
        self.assertEqual(response.status_code, 400)
        response = self.get(guide_path("pornhub") + "?utm_source=test", headers={"X-Forwarded-Host": "attacker.invalid"})
        self.assertEqual(Page(response.text).canonical, self.origin + guide_path("pornhub"))

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
        for unavailable, expected in ((False, "No website-hosted packages"), (True, "temporarily unavailable")):
            with patch("pf_server.guide_routes.load_catalog", return_value={"releases": [], "unavailable": unavailable}):
                response = self.get(guide_path("pornhub"))
                self.assertIn(expected, response.text)
                self.assertNotIn('/downloads/3.9', response.text)

    def test_guides_offer_platforms_relevant_links_and_consistent_images(self):
        from pathlib import Path
        from pf_server.guide_content import RELATED_GUIDES, GUIDE_PUBLISHED
        for provider in GUIDES:
            response = self.get(guide_path(provider))
            page = Page(response.text)
            self.assertIn("Porn Fetch 3.9.1", response.text)
            self.assertNotIn("published beta", response.text)
            self.assertNotIn("old 3.8 release", response.text)
            self.assertIn('Download for Free', response.text)
            self.assertIn('Get Premium (lifetime)', response.text)
            self.assertNotIn('Get Porn Fetch for your device', response.text)
            self.assertNotIn("?channel=beta", response.text)
            for platform in ("windows", "macos", "linux", "android", "ios", "cli"):
                self.assertIn("/download/" + platform, page.links)
            related = RELATED_GUIDES[provider]
            self.assertEqual(len(set(related)), 4)
            self.assertNotIn(provider, related)
            for key in related:
                self.assertIn(guide_path(key), page.links)
            article = next(row for row in page.structured[0]["@graph"] if row["@type"] == "Article")
            self.assertEqual(article["datePublished"], GUIDES[provider].get("published", GUIDE_PUBLISHED))
            self.assertEqual(article["image"], page.meta["og:image"])
            self.assertEqual(page.meta["og:image"], page.meta["twitter:image"])
            self.assertIn('media/guide-desktop-3.9.1.png', response.text)
            image_path = Path(main.app.static_folder) / urlsplit(article["image"]).path.removeprefix("/static/")
            self.assertTrue(image_path.is_file())

    def test_android_screenshot_and_current_release_instructions(self):
        from pathlib import Path
        screenshot = "/static/media/android-account.jpg"
        for provider in GUIDES:
            response = self.get(guide_path(provider))
            self.assertIn("Porn Fetch 3.9.1", response.text)
            self.assertNotIn("published beta", response.text)
            self.assertNotIn("old 3.8 release", response.text)
            self.assertIn('Download for Free', response.text)
            self.assertIn('Get Premium (lifetime)', response.text)
            self.assertNotIn('Get Porn Fetch for your device', response.text)
            self.assertIn("saved to your selected folder automatically", response.text)
            self.assertNotIn("A completed card also has", response.text)
            self.assertNotIn(screenshot, response.text)
            for platform in ("android", "ios"):
                for stage in ("start", "add", "ready", "downloading"):
                    filename = f"web/guide-{platform}-{stage}-3.9.1-720.webp"
                    self.assertIn(filename, response.text)
                    self.assertTrue((Path(main.app.static_folder) / "media" / filename).is_file())
        android = self.get("/download/android")
        self.assertIn(screenshot, android.text)
        for filename in ("android-account.jpg", "web/android-account-360.webp", "web/android-account-720.webp"):
            self.assertTrue((Path(main.app.static_folder) / "media" / filename).is_file())
        self.assertIn("first five videos", self.get(guide_path("xvideos")).text)

    def test_mobile_guides_preserve_search_content_and_explain_iphone_setup_before_purchase(self):
        for provider in GUIDES:
            response = self.get(guide_path(provider))
            html = response.text
            self.assertLess(html.index('id="android"'), html.index('id="download-steps"'))
            self.assertLess(html.index('id="iphone"'), html.index('id="download-steps"'))
            opening = html[html.index('<header class="guide-hero">'):html.index('id="mobile-downloads"')]
            self.assertLess(opening.index("iPhone requires a PC"), opening.index('href="/porn_fetch"'))
            self.assertIn("Up to 10 active installations", html)
            self.assertIn("On My iPhone", html)
            self.assertIn("not automatically added to Photos", html)
            self.assertIn("Download in progress. Wait for completion", html)
            for heading, paragraphs in GUIDES[provider]["sections"]:
                self.assertIn(heading, html)
            metadata = Page(html)
            self.assertIn("Android", metadata.meta["description"])
            self.assertIn("iPhone", metadata.meta["description"])
            self.assertIn("iPhone", metadata.meta["og:image:alt"])
        home = self.get("/").text
        self.assertNotIn('class="guide-surface', home)
        self.assertNotIn('/static/guides.js', home)
        self.assertNotIn('/static/guides.css', home)

    def test_mobile_availability_is_checked_for_each_platform(self):
        def artifacts(releases, platform, kinds):
            return [{"experimental": False}] if platform == "android" else []

        with patch("pf_server.guide_routes.latest_artifacts", side_effect=artifacts):
            html = self.get(guide_path("xvideos")).text
            self.assertNotIn("No Android APK is currently listed", html)
            self.assertIn("No iPhone IPA is currently listed", html)
        with patch("pf_server.guide_routes.latest_artifacts", return_value=[{"experimental": True}]):
            html = self.get(guide_path("xvideos")).text
            self.assertIn("No Android APK is currently listed", html)
            self.assertIn("No iPhone IPA is currently listed", html)

    def test_legal_pages_have_one_heading_and_transparency_redirect_works(self):
        for path in ("/privacy_policy", "/terms"):
            self.assertEqual(len(Page(self.get(path).text).h1s), 1)
        response = self.get("/transparency")
        self.assertEqual(response.status_code, 301)
        self.assertEqual(response.headers["Location"], "https://docs.echteralsfake.me/transparency/")
        self.assertIn(response.headers["Location"], Page(self.get("/").text).links)

    def test_onion_guides_remain_public_read_only_and_unindexed(self):
        response = self.client.get(guide_path("pornhub"), base_url=main.app.config["ONION_ORIGIN"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Robots-Tag"], "noindex, follow")
        self.assertEqual(Page(response.text).meta["robots"], "noindex, follow")
        self.assertEqual(Page(response.text).canonical, self.origin + guide_path("pornhub"))
