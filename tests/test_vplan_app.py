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
