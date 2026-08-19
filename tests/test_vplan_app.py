import os
import re
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


os.environ["VPLAN_SYNC_ENABLED"] = "false"
os.environ["VPLAN_SCHOOL_ID"] = "424242"
os.environ["CHECKLIST_AUTH"] = "test-only-very-strong-password"

import main  # noqa: E402


class VPlanSubdomainTests(unittest.TestCase):
    def setUp(self):
        self.client = main.app.test_client()

    def test_subdomain_root_renders_plan(self):
        response = self.client.get("/", headers={"Host": "vplan.echteralsfake.me"})

        self.assertEqual(response.status_code, 200)
        self.assertIn("Vertretungsplan", response.get_data(as_text=True))
        self.assertNotIn("LiGyDe.", response.get_data(as_text=True))

    def test_plan_renders_local_subject_rename_controls(self):
        plan = {
            "meta": {"stand": "2026-08-19 06:00:00"},
            "tage": [
                {
                    "DATUM": "Mittwoch, 19. August 2026",
                    "EINTRAEGE_KLASSEN": [
                        {
                            "STUNDE": "08:35 - 09:20",
                            "NEU": "Ausfall: Mathematik",
                            "BEMERKUNGEN": "",
                            "KLASSE": "12_mat1",
                        }
                    ],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            plan_path = Path(temporary_directory) / "vplan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")

            with patch.object(main, "VPLAN_JSON_PATH", plan_path):
                response = self.client.get(
                    "/", headers={"Host": "vplan.echteralsfake.me"}
                )

        html = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('data-plan-code="12_mat1"', html)
        self.assertIn("data-subject-edit", html)
        self.assertIn("Neuer Name", html)
        self.assertIn("Lehrer <small>(optional)</small>", html)
        self.assertIn('rel="manifest"', html)
        self.assertIn("data-install-app", html)
        self.assertEqual(html.count('class="quick-action"'), 3)
        self.assertLess(html.index("Mein Plan"), html.index("App installieren"))
        self.assertLess(html.index("App installieren"), html.index("Fehler melden"))
        self.assertIn('class="utility-header"', html)
        self.assertIn('data-info-open="controller-dialog"', html)
        self.assertIn('data-info-open="privacy-dialog"', html)
        self.assertIn('data-info-open="credits-dialog"', html)
        self.assertIn("Codex 5.6 SOL", html)
        self.assertIn("Mara Rosenberg", html)
        self.assertIn("Richard Lewerenz", html)

    def test_feedback_validation_accepts_plain_text_and_rejects_contact_data(self):
        message, error = main.validate_vplan_feedback(
            "  Beim Wechsel auf Donnerstag bleibt der Mittwoch sichtbar.\r\nBitte prüfen.  "
        )

        self.assertIsNone(error)
        self.assertEqual(
            message,
            "Beim Wechsel auf Donnerstag bleibt der Mittwoch sichtbar.\nBitte prüfen.",
        )

        invalid_messages = (
            "Bitte antwortet an max@example.org, der Fehler tritt täglich auf.",
            "Weitere Details stehen unter https://example.org/fehlerbericht.",
            "Meine Nummer ist 0176 12345678, bitte dort zurückrufen.",
            "Dieser <strong>Fehler</strong> betrifft den Donnerstag.",
        )
        for invalid_message in invalid_messages:
            with self.subTest(message=invalid_message):
                validated, validation_error = main.validate_vplan_feedback(invalid_message)
                self.assertIsNone(validated)
                self.assertIsNotNone(validation_error)

    def test_feedback_endpoint_stores_only_message_and_timestamp(self):
        with main.app.app_context():
            with (
                patch.object(main.VPlanFeedback, "query") as feedback_query,
                patch.object(main.db.session, "add") as add,
                patch.object(main.db.session, "commit"),
                patch.object(main.db.session, "rollback") as rollback,
            ):
                response = self.client.post(
                    "/vplan/feedback",
                    headers={
                        "Host": "vplan.echteralsfake.me",
                        "X-VPlan-Request": "feedback",
                    },
                    json={
                        "message": "Am Donnerstag öffnet der zweite Tab nicht richtig.",
                        "privacy_confirmed": True,
                    },
                )

        stored_reports = [
            call.args[0]
            for call in add.call_args_list
            if call.args and isinstance(call.args[0], main.VPlanFeedback)
        ]
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.get_json(), {"ok": True})
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(len(stored_reports), 1)
        self.assertEqual(
            stored_reports[0].message,
            "Am Donnerstag öffnet der zweite Tab nicht richtig.",
        )
        self.assertIsNotNone(stored_reports[0].created_at)
        self.assertEqual(set(main.VPlanFeedback.__table__.columns.keys()), {"id", "message", "created_at"})
        feedback_query.filter.return_value.delete.assert_called_once_with(
            synchronize_session=False
        )
        rollback.assert_not_called()

    def test_feedback_endpoint_requires_privacy_confirmation_and_request_marker(self):
        missing_confirmation = self.client.post(
            "/vplan/feedback",
            headers={
                "Host": "vplan.echteralsfake.me",
                "X-VPlan-Request": "feedback",
            },
            json={"message": "Der Donnerstag wird nicht richtig angezeigt."},
        )
        missing_marker = self.client.post(
            "/vplan/feedback",
            headers={"Host": "vplan.echteralsfake.me"},
            json={
                "message": "Der Donnerstag wird nicht richtig angezeigt.",
                "privacy_confirmed": True,
            },
        )

        self.assertEqual(missing_confirmation.status_code, 400)
        self.assertEqual(missing_marker.status_code, 400)
        self.assertEqual(missing_confirmation.headers["Cache-Control"], "no-store")
        self.assertEqual(missing_marker.headers["Cache-Control"], "no-store")

    def test_regular_class_codes_can_be_customized_too(self):
        response = self.client.get(
            "/static/vplan.js", headers={"Host": "vplan.echteralsfake.me"}
        )

        javascript = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            'const isEditableSubject = (code) => Boolean(String(code || "").trim());',
            javascript,
        )
        self.assertIn('id: "eng", name: "Englisch"', javascript)
        self.assertIn('id: "ges", name: "Geschichte"', javascript)
        self.assertIn('key: `${normalize(code)}::${subjectId}`', javascript)
        response.close()

    def test_disclaimer_confirmation_is_remembered_locally(self):
        response = self.client.get(
            "/static/vplan.js", headers={"Host": "vplan.echteralsfake.me"}
        )

        javascript = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('DISCLAIMER_ACCEPTED_KEY = "vplan-disclaimer-accepted-v1"', javascript)
        self.assertIn('safeStorage.get(DISCLAIMER_ACCEPTED_KEY) === "true"', javascript)
        self.assertIn('safeStorage.set(DISCLAIMER_ACCEPTED_KEY, "true")', javascript)
        response.close()

    def test_pwa_is_enabled_on_local_test_host(self):
        plan = {
            "meta": {"stand": "2026-08-19 06:00:00"},
            "tage": [],
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            plan_path = Path(temporary_directory) / "vplan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")

            with patch.object(main, "VPLAN_JSON_PATH", plan_path):
                response = self.client.get("/vplan", base_url="http://localhost")

        html = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('data-pwa-enabled="true"', html)
        self.assertIn('rel="manifest"', html)
        self.assertIn("data-install-app", html)

    def test_pwa_manifest_and_root_service_worker_are_available(self):
        manifest_response = self.client.get(
            "/static/manifest.webmanifest",
            headers={"Host": "vplan.echteralsfake.me"},
        )
        worker_response = self.client.get(
            "/sw.js", headers={"Host": "vplan.echteralsfake.me"}
        )

        manifest = json.loads(manifest_response.get_data(as_text=True))
        self.assertEqual(manifest_response.status_code, 200)
        self.assertEqual(manifest["display"], "standalone")
        self.assertEqual(manifest["start_url"], "/vplan?source=pwa")
        self.assertTrue(any("maskable" in icon["purpose"] for icon in manifest["icons"]))
        self.assertEqual(worker_response.status_code, 200)
        self.assertEqual(worker_response.headers["Service-Worker-Allowed"], "/")
        self.assertIn("Planseiten bleiben immer netzwerkaktuell", worker_response.get_data(as_text=True))
        manifest_response.close()
        worker_response.close()

    def test_missing_plan_file_is_downloaded_before_rendering(self):
        plan = {
            "meta": {"stand": "2026-08-19 06:00:00"},
            "tage": [],
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            plan_path = Path(temporary_directory) / "vplan.json"

            def create_plan(*, force=False):
                self.assertTrue(force)
                plan_path.write_text(json.dumps(plan), encoding="utf-8")
                return {"status": "updated"}

            with (
                patch.object(main, "VPLAN_JSON_PATH", plan_path),
                patch.object(main, "VPLAN_SYNC_CONFIG", SimpleNamespace(enabled=True)),
                patch.object(
                    main.vplan_synchronizer,
                    "sync_if_due",
                    side_effect=create_plan,
                ) as sync,
            ):
                response = self.client.get(
                    "/", headers={"Host": "vplan.echteralsfake.me"}
                )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Keine Änderungen", response.get_data(as_text=True))
        sync.assert_called_once_with(force=True)

    def test_missing_plan_and_failed_download_returns_service_unavailable(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            plan_path = Path(temporary_directory) / "vplan.json"
            with (
                patch.object(main, "VPLAN_JSON_PATH", plan_path),
                patch.object(main, "VPLAN_SYNC_CONFIG", SimpleNamespace(enabled=True)),
                patch.object(
                    main.vplan_synchronizer,
                    "sync_if_due",
                    return_value={"status": "error", "error": "upstream unavailable"},
                ),
            ):
                response = self.client.get(
                    "/", headers={"Host": "vplan.echteralsfake.me"}
                )

        self.assertEqual(response.status_code, 503)
        self.assertIn("Plan momentan nicht verfügbar", response.get_data(as_text=True))

    def test_worker_forwarded_host_routes_without_trusting_forwarded_ip(self):
        response = self.client.get(
            "/",
            headers={
                "Host": "origin.internal",
                "X-Forwarded-Host": "vplan.echteralsfake.me",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-For": "203.0.113.50",
                "CF-Connecting-IP": "203.0.113.50",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Vertretungsplan", response.get_data(as_text=True))

    def test_subdomain_does_not_expose_unrelated_server_routes(self):
        response = self.client.get("/stats", headers={"Host": "vplan.echteralsfake.me"})

        self.assertEqual(response.status_code, 404)

    def test_primary_hostname_redirects_to_neutral_access_gate(self):
        response = self.client.get("/", headers={"Host": "echteralsfake.me"})

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/access?next=/")

        login = self.client.get("/access?next=/", headers={"Host": "echteralsfake.me"})
        html = login.get_data(as_text=True)
        self.assertEqual(login.status_code, 200)
        self.assertIn("Geschützter Bereich", html)
        self.assertNotIn("Porn Fetch", html)
        self.assertNotIn("Adult", html)

    def test_correct_checklist_password_unlocks_the_landing_page(self):
        login = self.client.get(
            "/access?next=/", base_url="https://echteralsfake.me"
        )
        token_match = re.search(r'name="csrf_token" value="([^"]+)"', login.get_data(as_text=True))
        self.assertIsNotNone(token_match)

        authenticated = self.client.post(
            "/access",
            base_url="https://echteralsfake.me",
            data={
                "csrf_token": token_match.group(1),
                "password": "test-only-very-strong-password",
                "next": "/",
            },
        )
        self.assertEqual(authenticated.status_code, 302)
        self.assertEqual(authenticated.headers["Location"], "/")

        landing = self.client.get("/", base_url="https://echteralsfake.me")
        self.assertEqual(landing.status_code, 200)
        self.assertIn("private, no-store", landing.headers["Cache-Control"])
        self.assertEqual(landing.headers["X-Robots-Tag"], "noindex, nofollow, noarchive")

    def test_missing_password_configuration_fails_closed(self):
        with patch.dict(os.environ, {"CHECKLIST_AUTH": ""}):
            response = self.client.get(
                "/access", base_url="https://echteralsfake.me"
            )

        self.assertEqual(response.status_code, 503)
        self.assertIn("Zugriff ist momentan deaktiviert", response.get_data(as_text=True))

    def test_external_post_login_redirect_is_rejected(self):
        login = self.client.get(
            "/access?next=https://example.org", base_url="https://echteralsfake.me"
        )
        html = login.get_data(as_text=True)
        self.assertIn('name="next" value="/"', html)


class VisitorIPMiddlewareTests(unittest.TestCase):
    def test_removes_ip_headers_but_keeps_proxy_host_and_scheme(self):
        captured = {}

        def application(environ, start_response):
            captured.update(environ)
            start_response("204 No Content", [])
            return [b""]

        middleware = main.StripVisitorIPHeaders(application)
        environ = {
            "HTTP_CF_CONNECTING_IP": "203.0.113.50",
            "HTTP_CF_CONNECTING_IPV6": "2001:db8::50",
            "HTTP_X_FORWARDED_FOR": "203.0.113.50",
            "HTTP_X_REAL_IP": "203.0.113.50",
            "HTTP_TRUE_CLIENT_IP": "203.0.113.50",
            "HTTP_FORWARDED": "for=203.0.113.50",
            "HTTP_X_FORWARDED_HOST": "vplan.echteralsfake.me",
            "HTTP_X_FORWARDED_PROTO": "https",
            "REMOTE_ADDR": "127.0.0.1",
        }

        list(middleware(environ, lambda status, headers: None))

        for key in main.StripVisitorIPHeaders.ENVIRONMENT_KEYS:
            self.assertNotIn(key, captured)
        self.assertEqual(captured["REMOTE_ADDR"], "127.0.0.1")
        self.assertEqual(captured["HTTP_X_FORWARDED_HOST"], "vplan.echteralsfake.me")
        self.assertEqual(captured["HTTP_X_FORWARDED_PROTO"], "https")


if __name__ == "__main__":
    unittest.main()
