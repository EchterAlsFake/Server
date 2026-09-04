"""Application factory, public feature, update, and operations tests."""

import os
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
    def test_landing_page_auth_uses_application_configuration(self):
        with patch.dict(main.app.config, {"CHECKLIST_AUTH": "site-password"}):
            login = self.client.post(
                "/access",
                data={"password": "site-password", "next": "/"},
                base_url="https://localhost",
            )
            landing_page = self.client.get("/", base_url="https://localhost")

        self.assertEqual(login.status_code, 302)
        self.assertEqual(landing_page.status_code, 200)

        with patch.dict(main.app.config, {"CHECKLIST_AUTH": "rotated-password"}):
            after_rotation = self.client.get("/", base_url="https://localhost")
        self.assertEqual(after_rotation.status_code, 302)

    def test_updated_privacy_pages_render_in_both_languages(self):
        english = self.client.get("/privacy_policy")
        german = self.client.get("/datenschutz")

        self.assertEqual(english.status_code, 200)
        self.assertEqual(german.status_code, 200)
        self.assertIn(b"Patreon Membership and License Delivery", english.data)
        self.assertIn(
            "Patreon-Mitgliedschaft und Lizenzzustellung".encode(), german.data
        )

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
