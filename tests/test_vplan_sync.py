import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from vplan_sync import (
    VPlanSyncConfig,
    VPlanSyncError,
    VPlanSynchronizer,
    extract_teacher_names,
    load_vplan_learning,
    parse_vplan_html,
    plan_content_hash,
    redact_teacher_codes,
    sanitize_cached_plan,
)


TEST_SCHOOL_ID = 424242


def sample_html(
    stand: str = "2026-08-18 11:52:10",
    description: str = "Mathe",
    course_code: str = "12_mat1",
) -> str:
    return f'''<!doctype html><script>
        var vplanTage = [{{
            "WICHTIGE_HINWEISE": [["Titel", "Text"]],
            "WEITERE_HINWEISE": [],
            "DATUM": "Dienstag, 18. August 2026",
            "EINTRAEGE_KLASSEN": [{{
                "STUNDE": "08:35 - 09:20",
                "NEU": "<b>Ausfall:</b> {description}",
                "BEMERKUNGEN": "",
                "KLASSE": "{course_code}"
            }}]
        }}];
        var datum_stand = "{stand}";
    </script>'''


class ParseVPlanHtmlTests(unittest.TestCase):
    def test_extracts_nested_json_and_metadata(self):
        result = parse_vplan_html(sample_html(), TEST_SCHOOL_ID)

        self.assertEqual(result["meta"]["stand"], "2026-08-18 11:52:10")
        self.assertEqual(result["meta"]["schoolId"], TEST_SCHOOL_ID)
        self.assertEqual(result["meta"]["content_sha256"], plan_content_hash(result))
        self.assertEqual(result["tage"][0]["EINTRAEGE_KLASSEN"][0]["KLASSE"], "12_mat1")

    def test_rejects_a_page_without_the_expected_assignment(self):
        with self.assertRaises(VPlanSyncError):
            parse_vplan_html("<html>Login required</html>", TEST_SCHOOL_ID)

    def test_redacts_single_and_multiple_teacher_codes(self):
        self.assertEqual(
            redact_teacher_codes("Deu bei LiGyDe.Utt in C105"),
            "Deu bei Lehrkraft in C105",
        )
        self.assertEqual(
            redact_teacher_codes("JSV bei LiGyDe.Kru, LiGyDe.Wün in der Aula"),
            "JSV bei Lehrkraft in der Aula",
        )
        self.assertEqual(
            redact_teacher_codes("Mat bei LiGyDe.Shz in C103"),
            "Mat bei Lehrkraft in C103",
        )

    def test_redacts_teacher_code_in_standardized_tasks_remark(self):
        self.assertEqual(
            redact_teacher_codes(
                "Kurs hat Aufgaben von Hil, bitte bei fachlichen Fragen bereitstehen."
            ),
            "Kurs hat Aufgaben von Lehrkraft, bitte bei fachlichen Fragen bereitstehen.",
        )
        self.assertEqual(
            redact_teacher_codes("Klasse hat Aufgaben von Gro."),
            "Klasse hat Aufgaben von Lehrkraft.",
        )

    def test_redacts_titled_names_without_requiring_a_database_match(self):
        self.assertEqual(
            redact_teacher_codes(
                "Bemerkung: Frau Beispiel kommt mit dem Zug verspätet."
            ),
            "Bemerkung: Lehrkraft kommt mit dem Zug verspätet.",
        )
        self.assertEqual(
            redact_teacher_codes("Vertretung durch Herr Dr. Muster-Mann."),
            "Vertretung durch Lehrkraft.",
        )

    def test_extracts_unique_names_from_a_copied_staff_table(self):
        names = extract_teacher_names(
            "Name\tFunktion\n"
            "Frau Beispiel\tEng, Deu\n"
            "Herr Dr. Muster-Mann  Mat, Phy\n"
            "Frau Beispiel (in Elternzeit)\tDeu\n"
            "NTA\tTeam Nachteilsausgleich\n"
        )

        self.assertEqual(names, ("Frau Beispiel", "Herr Dr. Muster-Mann"))

    def test_scraped_plan_is_redacted_before_hashing(self):
        html = sample_html(description="Mat bei LiGyDe.Shz in C103").replace(
            '"BEMERKUNGEN": ""',
            '"BEMERKUNGEN": "Frau Beispiel kommt verspätet; Aufgaben von Hil."',
        )

        result = parse_vplan_html(html, TEST_SCHOOL_ID)
        entry = result["tage"][0]["EINTRAEGE_KLASSEN"][0]

        self.assertEqual(entry["NEU"], "<b>Ausfall:</b> Mat bei Lehrkraft in C103")
        self.assertEqual(
            entry["BEMERKUNGEN"],
            "Lehrkraft kommt verspätet; Aufgaben von Lehrkraft.",
        )
        self.assertNotIn("LiGyDe.", json.dumps(result, ensure_ascii=False))
        self.assertNotIn("Frau Beispiel", json.dumps(result, ensure_ascii=False))
        self.assertEqual(result["meta"]["content_sha256"], plan_content_hash(result))

    def test_learns_codes_from_explicit_tasks_and_notice_contexts(self):
        html = sample_html(description="Mat bei LiGyDe.Abc in C103").replace(
            '[["Titel", "Text"]]',
            '[["Klassentag", "Def und Ghi in B204"]]',
        ).replace(
            '"BEMERKUNGEN": ""',
            '"BEMERKUNGEN": "Aufgaben von Jkl."',
        )
        discovered: set[str] = set()

        result = parse_vplan_html(
            html,
            TEST_SCHOOL_ID,
            discovered_teacher_codes=discovered,
        )
        serialized = json.dumps(result, ensure_ascii=False)

        self.assertEqual(discovered, {"Abc", "Def", "Ghi", "Jkl"})
        self.assertNotIn("Abc", serialized)
        self.assertNotIn("Def", serialized)
        self.assertNotIn("Ghi", serialized)
        self.assertNotIn("Jkl", serialized)
        self.assertIn("Lehrkräfte in B204", serialized)

    def test_known_standalone_teacher_codes_are_redacted(self):
        self.assertEqual(
            redact_teacher_codes("Abc und Def in B204", ("Abc", "Def")),
            "Lehrkräfte in B204",
        )

    def test_existing_cache_is_atomically_sanitized_and_rehashed(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            plan_path = Path(temporary_directory) / "vplan.json"
            plan = {
                "meta": {"stand": "2026-08-20 06:00:00"},
                "tage": [{"BEMERKUNGEN": "Frau Beispiel kommt verspätet."}],
            }
            plan_path.write_text(json.dumps(plan), encoding="utf-8")

            changed = sanitize_cached_plan(plan_path)
            sanitized = json.loads(plan_path.read_text(encoding="utf-8"))

        self.assertTrue(changed)
        self.assertEqual(
            sanitized["tage"][0]["BEMERKUNGEN"],
            "Lehrkraft kommt verspätet.",
        )
        self.assertEqual(
            sanitized["meta"]["content_sha256"],
            plan_content_hash(sanitized),
        )


class VPlanSyncConfigTests(unittest.TestCase):
    def test_loads_school_id_from_dotenv_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / ".env").write_text(
                "VPLAN_SCHOOL_ID=123\nVPLAN_TEACHER_CODE_SEEDS=Abc,Def\n",
                encoding="utf-8",
            )

            with patch.dict(os.environ, {}, clear=True):
                config = VPlanSyncConfig.from_environment(root)

            self.assertEqual(config.school_id, 123)
            self.assertIn("schoolId=123", config.board_url)
            self.assertEqual(config.teacher_code_seeds, ("Abc", "Def"))

    def test_missing_school_id_fails_fast(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ValueError, "VPLAN_SCHOOL_ID"):
                    VPlanSyncConfig.from_environment(temporary_directory)


class SynchronizerTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        root = Path(self.temporary_directory.name)
        self.config = VPlanSyncConfig(
            enabled=True,
            school_id=TEST_SCHOOL_ID,
            plan_path=root / "vplan.json",
            state_path=root / "vplan.json.sync-state.json",
            lock_path=root / "vplan.json.sync.lock",
            board_url="https://example.invalid/board",
            teacher_code_seeds=("Def",),
            check_interval_seconds=120,
            request_timeout_seconds=5,
            max_response_bytes=1024 * 1024,
        )

    def tearDown(self):
        self.temporary_directory.cleanup()

    def write_plan(self, stand: str, description: str = "Mathe") -> dict:
        plan = parse_vplan_html(sample_html(stand, description), TEST_SCHOOL_ID)
        self.config.plan_path.write_text(json.dumps(plan), encoding="utf-8")
        return plan

    def test_changed_content_with_stale_timestamp_replaces_the_plan(self):
        self.write_plan("2026-08-18 11:52:10", "Mathe")
        synchronizer = VPlanSynchronizer(self.config)
        synchronizer._download_plan = Mock(
            return_value=(
                parse_vplan_html(
                    sample_html("2026-08-18 11:52:10", "Chemie"), TEST_SCHOOL_ID
                ),
                set(),
            )
        )

        result = synchronizer.sync_if_due()

        self.assertEqual(result["status"], "updated")
        saved = json.loads(self.config.plan_path.read_text(encoding="utf-8"))
        self.assertEqual(saved["meta"]["stand"], "2026-08-18 11:52:10")
        self.assertIn("Chemie", saved["tage"][0]["EINTRAEGE_KLASSEN"][0]["NEU"])
        self.assertEqual(saved["meta"]["content_sha256"], result["content_sha256"])

    def test_due_check_downloads_full_page_but_does_not_rewrite_identical_plan(self):
        original = self.write_plan("2026-08-18 11:52:10")
        downloaded = parse_vplan_html(sample_html(), TEST_SCHOOL_ID)
        downloaded["meta"]["synced_at"] = "2099-01-01T00:00:00+00:00"
        synchronizer = VPlanSynchronizer(self.config)
        synchronizer._download_plan = Mock(return_value=(downloaded, set()))

        result = synchronizer.sync_if_due()

        self.assertEqual(result["status"], "unchanged")
        synchronizer._download_plan.assert_called_once_with(["Def"])
        saved = json.loads(self.config.plan_path.read_text(encoding="utf-8"))
        self.assertEqual(saved, original)

        state = json.loads(self.config.state_path.read_text(encoding="utf-8"))
        self.assertEqual(state["last_content_sha256"], plan_content_hash(original))
        self.assertIn("last_fetch_at", state)

    def test_check_inside_two_minute_interval_does_not_download(self):
        self.write_plan("2026-08-18 11:52:10")
        self.config.state_path.write_text(
            json.dumps({"last_checked_epoch": time.time()}), encoding="utf-8"
        )
        synchronizer = VPlanSynchronizer(self.config)
        synchronizer._download_plan = Mock()

        result = synchronizer.sync_if_due()

        self.assertEqual(result["status"], "not_due")
        synchronizer._download_plan.assert_not_called()

    def test_teacher_and_course_learning_accumulates_during_school_year(self):
        first_plan = parse_vplan_html(
            sample_html(course_code="12_mat1"), TEST_SCHOOL_ID
        )
        second_plan = parse_vplan_html(
            sample_html(description="Chemie", course_code="12_che1"),
            TEST_SCHOOL_ID,
        )
        synchronizer = VPlanSynchronizer(self.config)
        synchronizer._download_plan = Mock(
            side_effect=[
                (first_plan, {"Abc"}),
                (second_plan, {"Ghi"}),
            ]
        )

        synchronizer.sync_if_due(force=True)
        synchronizer.sync_if_due(force=True)

        learning = load_vplan_learning(
            self.config.state_path,
            self.config.teacher_code_seeds,
        )
        self.assertEqual(learning["teacher_codes"], ["Abc", "Def", "Ghi"])
        self.assertEqual(learning["course_codes"], ["12_che1", "12_mat1"])

    def test_learning_resets_for_a_new_school_year(self):
        self.config.state_path.write_text(
            json.dumps(
                {
                    "vplan_learning": {
                        "school_year": "2025-2026",
                        "teacher_codes": ["Old"],
                        "course_codes": ["12_old1"],
                    }
                }
            ),
            encoding="utf-8",
        )

        learning = load_vplan_learning(
            self.config.state_path,
            self.config.teacher_code_seeds,
            now_epoch=1787184000.0,
        )

        self.assertEqual(learning["school_year"], "2026-2027")
        self.assertEqual(learning["teacher_codes"], ["Def"])
        self.assertEqual(learning["course_codes"], [])

    def test_existing_plan_survives_a_failed_refresh(self):
        original = self.write_plan("2026-08-18 10:00:00")
        synchronizer = VPlanSynchronizer(self.config)
        synchronizer._download_plan = Mock(side_effect=VPlanSyncError("invalid board"))

        result = synchronizer.sync_if_due()

        self.assertEqual(result["status"], "error")
        saved = json.loads(self.config.plan_path.read_text(encoding="utf-8"))
        self.assertEqual(saved, original)


if __name__ == "__main__":
    unittest.main()
