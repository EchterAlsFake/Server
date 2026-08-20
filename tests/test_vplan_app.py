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

main.app.config["TESTING"] = True


class VPlanSubdomainTests(unittest.TestCase):
    def setUp(self):
        self.client = main.app.test_client()

    def tearDown(self):
        with main.app.app_context():
            main.db.session.remove()

    def test_subdomain_root_renders_plan(self):
        response = self.client.get("/", headers={"Host": "vplan.echteralsfake.me"})

        self.assertEqual(response.status_code, 200)
        self.assertIn("Vertretungsplan", response.get_data(as_text=True))
        self.assertNotIn("LiGyDe.", response.get_data(as_text=True))

    def test_vplan_request_detection_does_not_capture_other_site_roots(self):
        with main.app.test_request_context("/", base_url="https://localhost"):
            self.assertFalse(main._is_vplan_request())
        with main.app.test_request_context(
            "/", base_url="https://vplan.echteralsfake.me"
        ):
            self.assertTrue(main._is_vplan_request())
        with main.app.test_request_context("/vplan", base_url="http://localhost"):
            self.assertTrue(main._is_vplan_request())

    def test_plan_day_dates_are_normalized_for_local_browser_selection(self):
        self.assertEqual(
            main._parse_vplan_day_iso("Donnerstag, 20. August 2026"),
            "2026-08-20",
        )
        self.assertEqual(main._parse_vplan_day_iso("21.08.2026"), "2026-08-21")
        self.assertEqual(main._parse_vplan_day_iso("2026-08-22"), "2026-08-22")
        self.assertEqual(main._parse_vplan_day_iso("31. Februar 2026"), "")
        self.assertEqual(main._parse_vplan_day_iso("Unbekannter Tag"), "")

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
        self.assertIn('data-i18n="subject.teacher"', html)
        self.assertIn('data-i18n="subject.color"', html)
        self.assertEqual(html.count("data-subject-color-choice"), 9)
        self.assertIn('rel="manifest"', html)
        self.assertIn("data-install-app", html)
        self.assertEqual(html.count('class="quick-action"'), 3)
        self.assertLess(html.index("Mein Plan"), html.index("App installieren"))
        self.assertLess(html.index("App installieren"), html.index("Fehler melden"))
        self.assertIn('class="utility-header"', html)
        self.assertIn('data-day-date="2026-08-19"', html)

    def test_learned_courses_are_available_even_when_not_in_current_plan(self):
        with patch.object(
            main,
            "load_vplan_learning",
            return_value={
                "school_year": "2026-2027",
                "teacher_codes": [],
                "course_codes": ["12_che1"],
            },
        ):
            response = self.client.get(
                "/", headers={"Host": "vplan.echteralsfake.me"}
            )

        html = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('data-learned-plan-code="12_che1"', html)

    def test_cached_notice_teacher_codes_are_redacted_before_rendering(self):
        plan = {
            "meta": {"stand": "2026-08-20 06:00:00"},
            "tage": [
                {
                    "DATUM": "Donnerstag, 20. August 2026",
                    "WICHTIGE_HINWEISE": [
                        ["Klassentag 5b", "Abc und Def in B204"]
                    ],
                    "WEITERE_HINWEISE": [],
                    "EINTRAEGE_KLASSEN": [],
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
        self.assertIn("Lehrkräfte in B204", html)
        self.assertNotIn("Abc und Def", html)
        self.assertIn('data-info-open="controller-dialog"', html)
        self.assertIn('data-info-open="privacy-dialog"', html)
        self.assertIn('data-info-open="credits-dialog"', html)
        self.assertIn('data-info-open="changelog-dialog"', html)
        self.assertIn('id="changelog-dialog"', html)
        self.assertIn("Änderungsprotokoll", html)
        for commit in ("c6375f0", "431d281", "791ce5a", "b8b865f", "6f60944", "c6dc4bd", "276b94a", "d2b2cc4"):
            self.assertIn(commit, html)
        self.assertIn("Zuverlässigkeit und App-Installation verbessert", html)
        self.assertIn("Die Oberfläche kann jetzt übersetzt", html)
        self.assertIn("Ab 15 Uhr öffnet sich automatisch", html)
        self.assertIn("Codex 5.6 SOL", html)
        self.assertIn("Anonym", html)
        self.assertIn("Richard Lewerenz", html)

    def test_cached_full_teacher_name_is_redacted_before_rendering(self):
        plan = {
            "meta": {"stand": "2026-08-20 06:00:00"},
            "tage": [
                {
                    "DATUM": "Donnerstag, 20. August 2026",
                    "WICHTIGE_HINWEISE": [],
                    "WEITERE_HINWEISE": [],
                    "EINTRAEGE_KLASSEN": [
                        {
                            "STUNDE": "08:35 - 09:20",
                            "NEU": "Ausfall: Englisch",
                            "BEMERKUNGEN": "Frau Beispiel kommt mit dem Zug verspätet.",
                            "KLASSE": "8c",
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
        self.assertIn("Lehrkraft kommt mit dem Zug verspätet.", html)
        self.assertNotIn("Frau Beispiel", html)

    def test_private_teacher_name_table_stores_no_plan_or_contact_data(self):
        self.assertEqual(
            set(main.VPlanTeacherName.__table__.columns.keys()),
            {"id", "name", "created_at"},
        )

    def test_private_teacher_names_can_be_exported_and_reimported(self):
        runner = main.app.test_cli_runner()
        with tempfile.TemporaryDirectory() as temporary_directory:
            export_path = Path(temporary_directory) / "vplan-teachers-export.txt"
            with patch.object(
                main,
                "load_vplan_teacher_names",
                return_value=("Herr Muster", "Frau Beispiel"),
            ):
                result = runner.invoke(
                    args=["export-vplan-teachers", str(export_path)]
                )

            exported_text = export_path.read_text(encoding="utf-8")
            extracted_names = main.extract_teacher_names(exported_text)
            file_mode = export_path.stat().st_mode & 0o777

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(exported_text, "Frau Beispiel\nHerr Muster\n")
        self.assertEqual(extracted_names, ("Frau Beispiel", "Herr Muster"))
        self.assertEqual(file_mode, 0o600)

    def test_teacher_name_export_does_not_overwrite_an_existing_file(self):
        runner = main.app.test_cli_runner()
        with tempfile.TemporaryDirectory() as temporary_directory:
            export_path = Path(temporary_directory) / "existing.txt"
            export_path.write_text("bestehender Inhalt\n", encoding="utf-8")
            with patch.object(
                main,
                "load_vplan_teacher_names",
                return_value=("Frau Beispiel",),
            ):
                result = runner.invoke(
                    args=["export-vplan-teachers", str(export_path)]
                )
            preserved_text = export_path.read_text(encoding="utf-8")

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("existiert bereits", result.output)
        self.assertEqual(preserved_text, "bestehender Inhalt\n")

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

    def test_feedback_endpoint_returns_stable_error_codes_and_shared_limit(self):
        with patch.object(
            main,
            "consume_vplan_feedback_rate_limit",
            return_value=(False, main.VPLAN_FEEDBACK_RATE_LIMIT + 1),
        ):
            response = self.client.post(
                "/vplan/feedback",
                headers={
                    "Host": "vplan.echteralsfake.me",
                    "X-VPlan-Request": "feedback",
                },
                json={
                    "message": "Der Donnerstag wird nicht richtig angezeigt.",
                    "privacy_confirmed": True,
                },
            )

        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.get_json(), {"error": "rate_limited"})
        self.assertEqual(response.headers["Retry-After"], "60")

    def test_sql_control_characters_are_plain_feedback_text_not_sql(self):
        message = "Anzeige falsch'); DROP TABLE vplan_feedback; --"
        validated, error = main.validate_vplan_feedback(message)

        self.assertEqual(validated, message)
        self.assertIsNone(error)

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
        self.assertIn('id: "eng", name: t("course.eng", {}, "Englisch")', javascript)
        self.assertIn('id: "ges", name: t("course.ges", {}, "Geschichte")', javascript)
        self.assertIn('key: `${normalize(code)}::${subjectId}`', javascript)
        self.assertIn('"violet", "blue", "cyan", "green"', javascript)
        self.assertIn("color: validSubjectColor(value.color)", javascript)
        self.assertIn("element.dataset.subjectAccent = validColor", javascript)
        self.assertNotIn("element.style.setProperty", javascript)
        response.close()

    def test_translation_catalogs_match_and_preserve_placeholders(self):
        source_path = Path(main.app.static_folder) / "i18n" / "de.json"
        english_path = Path(main.app.static_folder) / "i18n" / "en.json"
        source = json.loads(source_path.read_text(encoding="utf-8"))
        english = json.loads(english_path.read_text(encoding="utf-8"))
        source_keys = set(source) - {"_meta"}
        english_keys = set(english) - {"_meta"}

        self.assertEqual(source_keys, english_keys)
        self.assertGreater(len(source_keys), 200)
        self.assertTrue(source["_meta"]["source"])
        self.assertFalse(english["_meta"]["reviewed"])
        for key in source_keys:
            with self.subTest(key=key):
                self.assertIsInstance(source[key], str)
                self.assertIsInstance(english[key], str)
                self.assertEqual(
                    sorted(re.findall(r"\{[A-Za-z][A-Za-z0-9_]*\}", source[key])),
                    sorted(re.findall(r"\{[A-Za-z][A-Za-z0-9_]*\}", english[key])),
                )
                self.assertIsNone(re.search(r"<[^>\n]{1,200}>", english[key]))

    def test_translation_editor_is_local_only_and_available_on_vplan_host(self):
        response = self.client.get(
            "/vplan/translate", headers={"Host": "vplan.echteralsfake.me"}
        )
        javascript_response = self.client.get(
            "/static/vplan-translate.js",
            headers={"Host": "vplan.echteralsfake.me"},
        )

        html = response.get_data(as_text=True)
        javascript = javascript_response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertIn("Vertretungsplan übersetzen", html)
        self.assertIn("data-translation-list", html)
        self.assertIn("data-download", html)
        self.assertIn("Alles bleibt in deinem Browser", html)
        self.assertIn('data-i18n="translator.title"', html)
        self.assertIn('data-i18n="translator.download"', html)
        self.assertIn("https://github.com/EchterAlsFake/Server", html)
        self.assertIn("new Blob", javascript)
        self.assertIn("URL.createObjectURL", javascript)
        self.assertIn("textContent", javascript)
        self.assertIn('if (code === "de")', javascript)
        self.assertIn('t("translator.status.source_error"', javascript)
        self.assertNotIn('method: "POST"', javascript)
        response.close()
        javascript_response.close()

    def test_language_choice_and_static_catalogs_are_wired_into_the_plan(self):
        response = self.client.get(
            "/", headers={"Host": "vplan.echteralsfake.me"}
        )
        javascript_response = self.client.get(
            "/static/vplan.js", headers={"Host": "vplan.echteralsfake.me"}
        )

        html = response.get_data(as_text=True)
        javascript = javascript_response.get_data(as_text=True)
        self.assertIn("data-language-picker", html)
        self.assertIn('data-language-option="de"', html)
        self.assertIn('data-language-option="en"', html)
        self.assertIn("🇩🇪", html)
        self.assertIn("🇬🇧", html)
        self.assertIn('href="/vplan/translate"', html)
        self.assertIn('data-i18n="privacy.local.text"', html)
        self.assertIn('LANGUAGE_KEY = "vplan-language"', javascript)
        self.assertIn("safeStorage.set(LANGUAGE_KEY", javascript)
        self.assertIn('button.setAttribute("aria-pressed"', javascript)
        self.assertIn("flag.textContent = language.flag", javascript)
        self.assertIn("const DAY_ROLLOVER_HOUR = 15", javascript)
        self.assertIn("now.getHours() >= DAY_ROLLOVER_HOUR", javascript)
        self.assertIn("timestamp > today", javascript)
        self.assertIn("selectInitialDayTab();", javascript)
        self.assertIn("element.textContent =", javascript)
        self.assertNotIn("element.innerHTML", javascript)

        language_config = json.loads(
            (Path(main.app.static_folder) / "i18n" / "languages.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            [(language["code"], language["flag"]) for language in language_config["languages"]],
            [("de", "🇩🇪"), ("en", "🇬🇧")],
        )
        response.close()
        javascript_response.close()

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
            "/manifest.webmanifest",
            headers={"Host": "vplan.echteralsfake.me"},
        )
        worker_response = self.client.get(
            "/sw.js", headers={"Host": "vplan.echteralsfake.me"}
        )

        manifest = json.loads(manifest_response.get_data(as_text=True))
        self.assertEqual(manifest_response.status_code, 200)
        self.assertEqual(manifest["display"], "standalone")
        self.assertEqual(manifest["start_url"], "/vplan?source=pwa")
        self.assertEqual(manifest["scope"], "/vplan")
        self.assertEqual(manifest["id"], "/vplan")
        self.assertFalse(manifest["prefer_related_applications"])
        self.assertIn("no-store", manifest_response.headers["Cache-Control"])
        self.assertTrue(any("maskable" in icon["purpose"] for icon in manifest["icons"]))
        self.assertEqual(worker_response.status_code, 200)
        self.assertEqual(worker_response.headers["Service-Worker-Allowed"], "/vplan")
        worker = worker_response.get_data(as_text=True)
        self.assertIn("Planseiten bleiben immer netzwerkaktuell", worker)
        self.assertIn("CACHEABLE_PATHS", worker)
        self.assertIn("event.waitUntil", worker)
        self.assertIn("await cache.put", worker)
        manifest_response.close()
        worker_response.close()

    def test_install_events_are_captured_before_async_translations(self):
        response = self.client.get(
            "/static/vplan-pwa.js", headers={"Host": "vplan.echteralsfake.me"}
        )
        javascript = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn('window.addEventListener("beforeinstallprompt"', javascript)
        self.assertIn('navigator.serviceWorker.register("/sw.js", { scope: "/vplan" })', javascript)
        self.assertIn('document.readyState === "complete"', javascript)
        response.close()

    def test_class_selector_contains_only_a_to_c(self):
        response = self.client.get(
            "/", headers={"Host": "vplan.echteralsfake.me"}
        )
        html = response.get_data(as_text=True)

        for letter in "abc":
            self.assertIn(f'<option value="{letter}"', html)
        for letter in "defgh":
            self.assertNotIn(f'<option value="{letter}"', html)
        response.close()

    def test_vplan_host_uses_isolated_legal_pages_and_static_assets(self):
        privacy = self.client.get(
            "/vplan/privacy", headers={"Host": "vplan.echteralsfake.me"}
        )
        imprint = self.client.get(
            "/vplan/imprint", headers={"Host": "vplan.echteralsfake.me"}
        )
        old_privacy = self.client.get(
            "/datenschutz", headers={"Host": "vplan.echteralsfake.me"}
        )
        unrelated_static = self.client.get(
            "/static/index.css", headers={"Host": "vplan.echteralsfake.me"}
        )

        privacy_html = privacy.get_data(as_text=True)
        imprint_html = imprint.get_data(as_text=True)
        self.assertEqual(privacy.status_code, 200)
        self.assertEqual(imprint.status_code, 200)
        self.assertIn("nach 180 Tagen durch eine stündliche Bereinigung", privacy_html)
        self.assertNotIn("Porn Fetch", privacy_html)
        self.assertNotIn("Porn Fetch", imprint_html)
        self.assertEqual(old_privacy.status_code, 404)
        self.assertEqual(unrelated_static.status_code, 404)
        privacy.close()
        imprint.close()
        old_privacy.close()
        unrelated_static.close()

    def test_vplan_responses_use_the_restricted_security_policy(self):
        response = self.client.get(
            "/", headers={"Host": "vplan.echteralsfake.me"}
        )
        policy = response.headers["Content-Security-Policy"]

        self.assertIn("script-src 'self'", policy)
        self.assertNotIn("cdn.tailwindcss.com", policy)
        self.assertNotIn("nowpayments.io", policy)
        self.assertNotIn("'unsafe-inline'", policy.split("script-src", 1)[1].split(";", 1)[0])
        self.assertNotIn("'unsafe-inline'", policy.split("style-src", 1)[1].split(";", 1)[0])
        self.assertEqual(response.headers["X-XSS-Protection"], "0")
        response.close()

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
                patch.object(
                    main,
                    "VPLAN_SYNC_CONFIG",
                    SimpleNamespace(
                        enabled=True,
                        state_path=Path(temporary_directory) / "state.json",
                        teacher_code_seeds=(),
                    ),
                ),
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
                patch.object(
                    main,
                    "VPLAN_SYNC_CONFIG",
                    SimpleNamespace(
                        enabled=True,
                        state_path=Path(temporary_directory) / "state.json",
                        teacher_code_seeds=(),
                    ),
                ),
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
