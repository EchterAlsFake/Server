"""Onion is a read-only mirror; no checkout or publisher bypass is introduced."""
from _support import ServerTestCase, main


class OnionTests(ServerTestCase):
    def test_onion_links_and_read_only_boundary(self):
        origin = main.app.config["ONION_ORIGIN"]
        page = self.client.get("/", base_url=origin)
        self.assertEqual(page.status_code, 200)
        self.assertIn(origin.encode(), page.data)
        self.assertNotIn(b'/__eaf/visit.js', page.data)
        self.assertEqual(page.headers["X-Robots-Tag"], "noindex, follow")
        self.assertNotIn("Strict-Transport-Security", page.headers)
        for path in ("/create-crypto-payment", "/ci/website-releases", "/ci/android-updates"):
            self.assertEqual(self.client.post(path, base_url=origin, json={}).status_code, 404)
        self.assertEqual(self.client.get("/checklist", base_url=origin).status_code, 404)
        purchase = self.client.get("/porn_fetch", base_url=origin)
        self.assertIn(b"Continue on the regular website", purchase.data)
        self.assertNotIn(b'id="age-overlay"', purchase.data)

    def test_https_discovery_does_not_advertise_checkout_queries(self):
        page = self.client.get("/download?channel=beta", base_url="https://pornfetch.to")
        self.assertEqual(page.headers["Onion-Location"], main.app.config["ONION_ORIGIN"] + "/download")
        private = self.client.get("/buy_success?session_id=private", base_url="https://pornfetch.to")
        self.assertNotIn("Onion-Location", private.headers)
