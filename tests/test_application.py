"""Application factory, public feature, update, and operations tests."""

import os
import re
from datetime import datetime
from unittest.mock import patch

from _support import ServerTestCase, main
from sqlalchemy import inspect

import pf_server.operations_routes as operations_routes
import pf_server.update_routes as update_routes
from pf_server.ci_routes import generate_ci_badge_svg, set_ci_status
from pf_server.docs_routes import serve_docs_file
from pf_server.models import CiStatus, Stats


class ApplicationTests(ServerTestCase):
    def test_root_requires_explicit_age_confirmation(self):
        gate = self.client.get("/")
        rejected = self.client.post("/", data={})
        accepted = self.client.post("/", data={"adult_confirmed": "yes"})

        self.assertEqual(gate.status_code, 200)
        self.assertIn(b'name="adult_confirmed"', gate.data)
        self.assertIn(b"at least 18 years old", gate.data)
        self.assertIn("noindex", gate.headers["X-Robots-Tag"])
        self.assertEqual(rejected.status_code, 400)
        self.assertIn(b'role="alert"', rejected.data)
        self.assertEqual(accepted.status_code, 303)
        self.assertEqual(accepted.headers["Location"], "/porn_fetch")
        self.assertIn("no-store", accepted.headers["Cache-Control"])

        with patch.dict(main.app.config, {"WTF_CSRF_ENABLED": True}):
            csrf_rejected = self.client.post("/", data={"adult_confirmed": "yes"})
            token = re.search(
                rb'name="csrf_token" value="([^"]+)"', self.client.get("/").data
            ).group(1)
            csrf_accepted = self.client.post(
                "/", data={"adult_confirmed": "yes", "csrf_token": token.decode()}
            )
        self.assertEqual(csrf_rejected.status_code, 400)
        self.assertEqual(csrf_accepted.status_code, 303)

    def test_commercial_seo_exposes_only_the_product_page(self):
        commercial_host = "https://echteralsfake.me"
        with patch.dict(main.app.config, {"NOWPAYMENTS_SANDBOX": False}):
            product = self.client.get("/porn_fetch", base_url=commercial_host)
            sitemap = self.client.get("/sitemap.xml", base_url=commercial_host)
            robots = self.client.get("/robots.txt", base_url=commercial_host)
            docs_sitemap = self.client.get("/sitemap.xml", base_url="https://docs.echteralsfake.me")

        self.assertEqual(product.status_code, 200)
        self.assertIn(b'<meta name="robots" content="index, follow">', product.data)
        self.assertIn(b'<link rel="canonical" href="https://echteralsfake.me/porn_fetch">', product.data)
        self.assertIn(b'<meta name="description"', product.data)
        self.assertEqual(sitemap.status_code, 200)
        self.assertIn(b"https://echteralsfake.me/porn_fetch", sitemap.data)
        self.assertNotIn(b"<loc>https://echteralsfake.me/</loc>", sitemap.data)
        self.assertIn(b"Sitemap: https://echteralsfake.me/sitemap.xml", robots.data)
        self.assertEqual(docs_sitemap.status_code, 404)

        with patch.dict(main.app.config, {"NOWPAYMENTS_SANDBOX": True}):
            test_product = self.client.get("/porn_fetch", base_url=commercial_host)
            test_sitemap = self.client.get("/sitemap.xml", base_url=commercial_host)
        self.assertIn(b'<meta name="robots" content="noindex, nofollow">', test_product.data)
        self.assertEqual(test_sitemap.status_code, 404)

    def test_purchase_pages_show_current_payment_options_and_accessible_checkout(self):
        options = self.client.get("/porn_fetch")
        checkout = self.client.get("/buy_license")

        self.assertEqual(options.status_code, 200)
        self.assertEqual(checkout.status_code, 200)
        self.assertIn(b"NOWPayments", options.data)
        self.assertIn(b"Patreon", options.data)
        self.assertIn(b"214243387", options.data)
        self.assertIn("€19.99".encode(), options.data)
        self.assertNotIn(b"SubscribeStar", options.data)
        self.assertNotIn(b"Transak", checkout.data)
        self.assertNotIn(b"pay-fiat-btn", checkout.data)
        self.assertIn(b'<fieldset class="checkout-agreements">', checkout.data)
        self.assertIn(b'role="alert"', checkout.data)
        self.assertIn(b'Skip to main content', checkout.data)
        self.assertIn(b'Test site', checkout.data)
        self.assertIn(b'id="chk-test-site"', checkout.data)

        with patch.dict(main.app.config, {"NOWPAYMENTS_SANDBOX": False}):
            live_checkout = self.client.get("/buy_license")
        self.assertNotIn(b'id="chk-test-site"', live_checkout.data)
        self.assertNotIn(b'class="test-site-banner"', live_checkout.data)

    def test_root_age_gate_does_not_require_the_checklist_password(self):
        former_password_page = self.client.get("/access")
        self.assertEqual(former_password_page.status_code, 302)
        self.assertEqual(former_password_page.headers["Location"], "/")
        with patch.dict(main.app.config, {"CHECKLIST_AUTH": "site-password"}):
            landing_page = self.client.get("/", base_url="https://localhost")
        self.assertEqual(landing_page.status_code, 200)
        self.assertIn(b'name="adult_confirmed"', landing_page.data)
        with patch.dict(main.app.config, {"CHECKLIST_AUTH": "rotated-password"}):
            after_rotation = self.client.get("/", base_url="https://localhost")
        self.assertEqual(after_rotation.status_code, 200)

    def test_vplan_referral_blocks_commercial_site_for_the_browser(self):
        host = "https://echteralsfake.me"
        blocked = self.client.get(
            "/", base_url=host,
            headers={"Referer": "https://vplan.echteralsfake.me/school/plan?private=1"},
        )
        self.assertEqual(blocked.status_code, 403)
        self.assertIn(b"Access unavailable", blocked.data)
        self.assertNotIn(b"Porn Fetch is intended for adults", blocked.data)
        self.assertIn("Secure", blocked.headers["Set-Cookie"])
        self.assertIn("HttpOnly", blocked.headers["Set-Cookie"])
        self.assertIn("SameSite=Lax", blocked.headers["Set-Cookie"])
        self.assertIn("no-store", blocked.headers["Cache-Control"])

        self.assertEqual(self.client.get("/porn_fetch", base_url=host).status_code, 403)
        self.assertEqual(self.client.get("/buy_license", base_url=host).status_code, 403)
        self.assertEqual(self.client.post("/", base_url=host, data={"adult_confirmed": "yes"}).status_code, 403)
        self.assertEqual(main.app.test_client().get("/", base_url=host).status_code, 200)
        self.assertNotEqual(self.client.get("/docs/", base_url=host).status_code, 403)
        self.assertNotEqual(self.client.get("/", base_url="https://docs.echteralsfake.me").status_code, 403)

        with patch.dict(main.app.extensions, {"vplan_referral_key": b"new-app-lifetime-key"}):
            after_restart = self.client.get("/", base_url=host)
        self.assertEqual(after_restart.status_code, 200)

    def test_vplan_referral_host_match_is_exact(self):
        host = "https://echteralsfake.me"
        for referer in (
            "https://vplan.echteralsfake.me.evil.example/",
            "https://vplan.echteralsfake.me@evil.example/",
            "http://vplan.echteralsfake.me/",
            "https://other.example/",
        ):
            response = self.client.get("/", base_url=host, headers={"Referer": referer})
            self.assertEqual(response.status_code, 200, referer)

    def test_updated_privacy_pages_render_in_both_languages(self):
        with patch.dict(
            main.app.config, {"LICENSE_MAIL_PROVIDER_NAME": "Example Mail"}
        ):
            english = self.client.get("/privacy_policy")
            german = self.client.get("/datenschutz")

        self.assertEqual(english.status_code, 200)
        self.assertEqual(german.status_code, 200)
        self.assertIn(b"Patreon Membership and License Delivery", english.data)
        self.assertIn(b"Privex VPS &amp; WireGuard Transport", english.data)
        self.assertIn(b"Google Pixel 7 Pro", english.data)
        self.assertIn(
            "Patreon-Mitgliedschaft und Lizenzzustellung".encode(), german.data
        )
        self.assertIn("Privex-VPS &amp; WireGuard-Transport".encode(), german.data)
        self.assertIn("Acer Swift 3".encode(), german.data)
        self.assertIn(b"Example Mail", english.data)
        self.assertIn(b"Example Mail", german.data)

    def test_documentation_paths_cannot_escape_the_generated_site(self):
        target, status = serve_docs_file("assets/../../main.py")

        self.assertIsNone(target)
        self.assertEqual(status, "404")

    def test_api_timestamps_are_valid_rfc3339_values(self):
        with main.app.app_context():
            ci_status = set_ci_status("timestamp-test", "pass")

        stats = self.client.get("/stats?format=json").get_json()
        for timestamp in (ci_status["updated_at"], stats["server_started_at"]):
            self.assertNotIn("+00:00Z", timestamp)
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            self.assertIsNotNone(parsed.tzinfo)

    def test_release_lookup_degrades_cleanly_when_github_is_unavailable(self):
        update_routes.update_cache.update(last_checked=0, data=None)
        with patch.object(
            update_routes.httpx,
            "get",
            side_effect=update_routes.httpx.ConnectError("offline"),
        ):
            with main.app.app_context():
                release = update_routes.get_update_information()

        self.assertEqual(release["version"], "unavailable")
        self.assertIsNone(release["macos_universal"])

    def test_release_lookup_ignores_malformed_assets(self):
        update_routes.update_cache.update(last_checked=0, data=None)
        with patch.object(update_routes.httpx, "get") as github_get:
            github_get.return_value.json.return_value = {
                "tag_name": "v1.2.3",
                "assets": [
                    None,
                    {
                        "name": "PornFetch_macOS_GUI_Universal.dmg",
                        "browser_download_url": "https://downloads.example/app.dmg",
                    },
                ],
            }
            with main.app.app_context():
                release = update_routes.get_update_information()

        self.assertEqual(release["version"], "v1.2.3")
        self.assertIsNotNone(release["macos_universal"])

    def test_update_download_link_uses_the_configured_public_origin(self):
        with (
            patch.dict(main.app.config, {"APP_DOMAIN": "https://public.example"}),
            patch.object(
                update_routes,
                "get_update_information",
                return_value={"version": "v1.2.3"},
            ),
        ):
            response = self.client.get("/update")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["anonymous_download"],
            "https://public.example/download",
        )

    def test_ci_mutations_fail_closed_without_a_token(self):
        with patch.dict(main.app.config, {"CI_TOKEN": None}):
            response = self.client.post("/ci/build", json={"status": "pass"})

        self.assertEqual(response.status_code, 503)

    def test_ci_structured_details_are_stored_safely_as_text(self):
        with patch.dict(main.app.config, {"CI_TOKEN": "ci-secret"}):
            response = self.client.post(
                "/ci/build",
                json={"status": "pass", "details": {"suite": "webhooks"}},
                headers={"X-CI-TOKEN": "ci-secret"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["details"], "{'suite': 'webhooks'}")
        with main.app.app_context():
            self.assertEqual(
                main.db.session.get(CiStatus, "build").details,
                "{'suite': 'webhooks'}",
            )

    def test_ci_badge_escapes_user_controlled_test_names(self):
        with main.app.app_context():
            response = generate_ci_badge_svg("<script>alert(1)</script>", "pass")

        self.assertNotIn(b"<script>", response.data)
        self.assertIn(b"&lt;script&gt;", response.data)

    def test_checklist_blueprint_auth_and_password_rotation(self):
        with patch.dict(main.app.config, {"CHECKLIST_AUTH": "first-password"}):
            login = self.client.post(
                "/checklist/login",
                data={"password": "first-password"},
                base_url="https://localhost",
            )
            added = self.client.post(
                "/checklist/api/add",
                json={"task": "  Ship Blueprint refactor  "},
                base_url="https://localhost",
            )
            tasks = self.client.get(
                "/checklist/api/tasks", base_url="https://localhost"
            ).get_json()

        self.assertEqual(login.status_code, 302)
        self.assertEqual(added.status_code, 200)
        self.assertEqual(tasks[0]["task"], "Ship Blueprint refactor")

        with patch.dict(main.app.config, {"CHECKLIST_AUTH": "rotated-password"}):
            after_rotation = self.client.post(
                "/checklist/api/add",
                json={"task": "Must authenticate again"},
                base_url="https://localhost",
            )
        self.assertEqual(after_rotation.status_code, 401)

    def test_appcast_reports_a_missing_signature_without_crashing(self):
        release = {
            "version": "v1.2.3",
            "macos_universal": {
                "browser_download_url": "https://downloads.example/app.dmg",
                "size": 123,
            },
            "published_at": "2026-01-01T00:00:00Z",
        }
        with (
            patch.object(update_routes, "get_update_information", return_value=release),
            patch.object(
                update_routes,
                "load_signature_for_version",
                side_effect=FileNotFoundError,
            ),
        ):
            response = self.client.get("/appcast.xml")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.get_json(),
            {"error": "Release signature is unavailable"},
        )

    def test_appcast_tolerates_invalid_release_date_and_size(self):
        release = {
            "version": "v1.2.3",
            "macos_universal": {
                "browser_download_url": "https://downloads.example/app.dmg",
                "size": "not-an-integer",
            },
            "published_at": "not-a-timestamp",
        }
        with (
            patch.object(update_routes, "get_update_information", return_value=release),
            patch.object(
                update_routes,
                "load_signature_for_version",
                return_value="signature",
            ),
        ):
            response = self.client.get("/appcast.xml")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'length="0"', response.data)

    def test_killswitch_uses_its_own_token_instead_of_browser_csrf(self):
        with (
            patch.dict(
                main.app.config,
                {"KILL_TOKEN": "kill-secret", "WTF_CSRF_ENABLED": True},
            ),
            patch.object(operations_routes, "initiate_poweroff") as poweroff,
        ):
            response = self.client.post(
                "/killswitch", headers={"X-KILL-TOKEN": "kill-secret"}
            )

        self.assertEqual(response.status_code, 200)
        poweroff.assert_called_once_with()

    def test_request_stats_initialize_before_the_first_request(self):
        isolated_app = main.create_app(
            {
                "TESTING": True,
                "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
                "RATELIMIT_ENABLED": False,
                "WTF_CSRF_ENABLED": False,
            }
        )
        with isolated_app.app_context():
            main.db.create_all()
            table_names = set(inspect(main.db.engine).get_table_names())
            self.assertNotIn("report", table_names)
            self.assertNotIn("write_log", table_names)
            transaction_columns = {
                column["name"]
                for column in inspect(main.db.engine).get_columns("transaction")
            }
            self.assertEqual(
                transaction_columns,
            {
                "session_id",
                "provider_payment_id",
                "provider_reference_type",
                "environment",
                "renewal_license_id",
                "expected_price_amount",
                "expected_price_currency",
                "expected_pay_amount",
                "expected_pay_currency",
                "customer_country",
                "country_evidence",
                "geolocation_database",
                "status",
                "processing_started_at",
                "finished_at",
                "created_at",
            },
        )

        response = isolated_app.test_client().get("/ping")

        self.assertEqual(response.status_code, 200)
        with isolated_app.app_context():
            stats = main.db.session.get(Stats, 1)
            self.assertEqual(stats.total_requests, 1)
            self.assertGreaterEqual(stats.total_bytes_out, len(response.data))

    def test_application_factory_builds_an_independent_blueprint_app(self):
        with patch.dict(os.environ, {"CHECKLIST_AUTH": "fresh-factory-secret"}):
            isolated_app = main.create_app(
                {
                    "TESTING": True,
                    "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
                    "RATELIMIT_ENABLED": False,
                    "WTF_CSRF_ENABLED": False,
                },
                initialize_runtime=False,
            )

        self.assertIsNot(isolated_app, main.app)
        self.assertEqual(isolated_app.config["CHECKLIST_AUTH"], "fresh-factory-secret")
        endpoints = {rule.endpoint for rule in isolated_app.url_map.iter_rules()}
        self.assertIn("pages.landing_page", endpoints)
        self.assertIn("docs.serve_docs_subpath", endpoints)
        self.assertIn("payments.nowpayments_ipn", endpoints)
        self.assertIn("ci.ci_update", endpoints)
        self.assertIn("checklist.add_task", endpoints)
        self.assertIn("updates.appcast", endpoints)
        self.assertIn("operations.stats_endpoint", endpoints)
        with isolated_app.app_context():
            self.assertEqual(inspect(main.db.engine).get_table_names(), [])
