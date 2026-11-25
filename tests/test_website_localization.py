"""Coverage of the localized visitor journey and the consent recorded by checkout."""

import json
import re
from collections import Counter
from html import unescape
from pathlib import Path
from unittest.mock import patch

from _support import ServerTestCase, main
from pf_server.contracts import AGE_TERMS, IMMEDIATE_EN, REFUND_EN, TEST_NOTICE, localized_agreement
from pf_server.docs_locale import DocumentationHTML, docs_catalog
from pf_server.invoice_service import build_simulated_invoice, render_invoice_pdf
from pf_server.models import CheckoutAgreement
from pf_server.website_locale import LANGUAGES, browser_message_keys, catalog_for, language_tag, use_language
from pf_server.withdrawal_service import STATEMENT


NON_ENGLISH = tuple(locale for locale in LANGUAGES if locale != "en")


class LocalizedWebsiteTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        config = patch.dict(main.app.config, {
            "PATREON_SHOP_ENABLED": True,
            "PAYWARP_ENABLED": True,
            "NOWPAYMENTS_SANDBOX": True,
            "LICENSE_SMTP_HOST": "localhost",
            "LICENSE_EMAIL_FROM": "licenses@example.invalid",
        })
        config.start()
        self.addCleanup(config.stop)

    def test_purchase_and_recovery_pages_have_the_selected_locale(self):
        for locale in NON_ENGLISH:
            catalog = catalog_for(locale)
            for path, title in {
                "/porn_fetch": "Choose your license — Porn Fetch",
                "/buy_license": "Crypto checkout — Porn Fetch",
                "/buy_success": "Track your payment — Porn Fetch",
                "/activate": "Activate your Patreon purchase — Porn Fetch",
                "/donation": "Donate - Support Development",
                "/withdrawal": "Withdraw from contract — Porn Fetch",
            }.items():
                with self.subTest(locale=locale, path=path):
                    page = self.client.get(f"/{locale}{path}")
                    self.assertEqual(page.status_code, 200)
                    self.assertIn(f'lang="{language_tag(locale)}"', page.text)
                    self.assertIn("noindex", page.headers["X-Robots-Tag"])
                    self.assertIn(catalog[title], unescape(page.text))

    def test_checkout_displays_and_saves_the_same_localized_declarations(self):
        for locale in NON_ENGLISH:
            with self.subTest(locale=locale):
                catalog = catalog_for(locale)
                prefix = "/" + locale
                confirmed = self.client.post(prefix + "/confirm-age", data={
                    "adult_confirmed": "yes", "next": prefix + "/porn_fetch?method=crypto",
                })
                self.assertEqual(confirmed.location, prefix + "/porn_fetch?method=crypto")
                page = unescape(self.client.get(prefix + "/porn_fetch").text)
                age_text = catalog[AGE_TERMS] % {
                    "terms": '<a href="/terms" target="_blank" rel="noopener noreferrer">' + catalog["Terms of Service"] + "</a>",
                }
                self.assertIn(age_text, page)
                self.assertIn(catalog[REFUND_EN], page)
                self.assertIn(catalog[TEST_NOTICE], page)
                shared = {
                    "payment_method": "crypto", "age_terms_accepted": "yes",
                    "refund_method_accepted": "yes", "test_acknowledged": "yes",
                    "offer_digest": self.offer_digest(),
                }
                missing_refund = dict(shared, refund_method_accepted="no")
                self.assertEqual(self.client.post(prefix + "/checkout/start", json=missing_refund).status_code, 400)
                selection = self.client.post(prefix + "/checkout/start", json=shared)
                self.assertEqual(selection.json["next"], prefix + "/buy_license")
                self.assertIn(catalog[IMMEDIATE_EN], unescape(self.client.get(selection.json["next"]).text))
                supply = dict(country="DE", withdrawal_accepted=False, offer_digest=self.offer_digest())
                self.assertEqual(self.client.post(prefix + "/checkout/crypto-confirm", json=supply).status_code, 400)
                supply["withdrawal_accepted"] = True
                self.assertEqual(self.client.post(prefix + "/checkout/crypto-confirm", json=supply).status_code, 200)
                with self.client.session_transaction() as session:
                    identifier = session["checkout_consent"]["agreement_id"]
                with main.app.app_context():
                    saved = json.loads(main.db.session.get(CheckoutAgreement, identifier).snapshot)
                    presented = saved["presentation"]
                    self.assertEqual(presented["language"], locale)
                    self.assertEqual(presented["supply_language"], locale)
                    self.assertEqual(presented["refund"], catalog[REFUND_EN])
                    self.assertEqual(presented["immediate"], catalog[IMMEDIATE_EN])
                    self.assertIn(catalog[IMMEDIATE_EN], localized_agreement(saved, identifier))
                receipt = self.client.get(prefix + "/checkout/agreement")
                self.assertEqual(receipt.status_code, 200)
                self.assertTrue(receipt.data.startswith(b"%PDF"))
                self.assertIn("no-store", receipt.headers["Cache-Control"])

    def test_paywarp_preserves_locale_through_form_and_provider_return(self):
        from pf_server import paywarp_service

        self.client.post("/hi/confirm-age", data={"adult_confirmed": "yes"})
        select = self.client.post("/hi/checkout/start", json={
            "payment_method": "paywarp", "age_terms_accepted": True,
            "refund_method_accepted": True, "test_acknowledged": True,
            "offer_digest": self.offer_digest(),
        })
        self.assertEqual(select.json["next"], "/hi/buy_paywarp")
        page = self.client.get(select.json["next"])
        self.assertIn(catalog_for("hi")[IMMEDIATE_EN], unescape(page.text))
        form = {"delivery_email": "buyer@example.com", "withdrawal_accepted": "yes"}

        def fake_provider(_method, _path, *, json, **_kwargs):
            self.assertIn("/hi/buy_success?", json["return_url"])
            return dict(id="pl_payment_test", checkout_url="https://paywarp.app/pay/test",
                        amount=json["amount_minor"], currency=json["currency"],
                        reference=json["reference"], status="pending")

        with patch("pf_server.keygen_service.verify_lifetime_policy"), patch.object(
            paywarp_service, "api", side_effect=fake_provider,
        ) as api:
            missing = self.client.post("/hi/create-paywarp-payment", data=form | {"withdrawal_accepted": ""})
            self.assertEqual(missing.status_code, 400)
            api.assert_not_called()
            redirect = self.client.post("/hi/create-paywarp-payment", data=form)
        self.assertEqual(redirect.status_code, 303)
        self.assertTrue(redirect.location.startswith("/hi/buy_success?"))

    def test_withdrawal_receipt_contains_the_declaration_shown_in_preview(self):
        prefix = "/zh-hans/withdrawal"
        catalog = catalog_for("zh-hans")
        preview = self.client.post(prefix + "/preview", data={
            "name": "Example buyer", "email": "buyer@example.com", "contract": "Order 123",
        })
        self.assertEqual(preview.status_code, 200)
        self.assertIn(catalog[STATEMENT], preview.text)
        draft = re.search(r'name="draft" value="([^"]+)"', preview.text).group(1)
        with patch("pf_server.withdrawal_service.deliver_received"):
            confirmation = self.client.post(prefix + "/confirm", data={"draft": draft, "confirm": "withdraw"})
        self.assertEqual(confirmation.status_code, 200)
        receipt = self.client.post(prefix + "/receipt", data={"draft": draft})
        self.assertIn(catalog[STATEMENT], receipt.get_data(as_text=True))

    def test_localized_checkout_uses_existing_tor_guard(self):
        self.mock_tor_lookup.return_value = "tor"
        response = self.client.get("/es/buy_license", environ_overrides={"REMOTE_ADDR": "8.8.8.8"})
        message = "Cryptocurrency payments are unavailable over Tor. Use a direct connection to purchase."
        self.assertEqual(response.status_code, 403)
        self.assertIn(catalog_for("es")[message], unescape(response.text))

    def test_browser_message_inventory_includes_all_locales(self):
        for locale in NON_ENGLISH:
            catalog = catalog_for(locale)
            self.assertFalse(set(browser_message_keys()) - catalog.keys(), locale)
            for key in browser_message_keys():
                with self.subTest(locale=locale, key=key):
                    self.assertEqual(Counter(re.findall(r"%\(\w+\)s", key)),
                                     Counter(re.findall(r"%\(\w+\)s", catalog[key])))

    def test_non_exempt_template_messages_are_in_every_catalog(self):
        exempt = {"terms", "terms_en", "terms_de", "privacy_policy", "privacy_policy_en",
                  "privacy_policy_de", "privacy_en", "privacy_de", "impress"}
        messages = set()
        for template in Path("templates").rglob("*.html"):
            if template.stem in exempt:
                continue
            for _, _, source in main.app.jinja_env.extract_translations(
                template.read_text(), gettext_functions=("_", "site_text", "gettext", "ngettext")
            ):
                sources = (source,) if isinstance(source, str) else source or ()
                messages.update(key for key in sources if isinstance(key, str))
        for locale in NON_ENGLISH:
            self.assertEqual(messages - catalog_for(locale).keys(), set(), locale)

    def test_invoices_render_with_each_website_language(self):
        invoice = build_simulated_invoice()
        with main.app.app_context():
            for locale in NON_ENGLISH:
                with self.subTest(locale=locale), use_language(locale):
                    localized = render_invoice_pdf(invoice)
                    self.assertTrue(localized.startswith(b"%PDF"))
        self.assertEqual(invoice["Base Price in EUR"], "29.99 EUR")

    def test_localized_docs_preserve_code_and_use_the_catalog(self):
        english = self.client.get("/docs/").text
        for locale in NON_ENGLISH:
            translated = self.client.get(f"/{locale}/docs/")
            self.assertEqual(translated.status_code, 200)
            self.assertIn(f'lang="{language_tag(locale)}"', translated.text)
            self.assertIn('class="docs-languages"', translated.text)
            self.assertEqual(re.findall(r"<code>(.*?)</code>", translated.text),
                             re.findall(r"<code>(.*?)</code>", english))
        keys = set()
        for page in Path("docs/dist").rglob("*.html"):
            parser = DocumentationHTML(lambda key: keys.add(key) or key, "de")
            parser.feed(page.read_text())
            parser.close()
        keys = {key for key in keys if any(char.isalpha() for char in key)} - {"Johannes Habel"}
        for locale in NON_ENGLISH:
            self.assertEqual(keys - docs_catalog(locale).keys(), set(), locale)
