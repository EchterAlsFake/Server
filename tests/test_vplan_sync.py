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
    parse_vplan_html,
    redact_teacher_codes,
)


TEST_SCHOOL_ID = 424242


def sample_html(stand: str = "2026-08-18 11:52:10") -> str:
    return f'''<!doctype html><script>
        var vplanTage = [{{
            "WICHTIGE_HINWEISE": [["Titel", "Text"]],
            "WEITERE_HINWEISE": [],
            "DATUM": "Dienstag, 18. August 2026",
            "EINTRAEGE_KLASSEN": [{{
                "STUNDE": "08:35 - 09:20",
                "NEU": "<b>Ausfall:</b> Mathe",
                "BEMERKUNGEN": "",
                "KLASSE": "12_mat1"
            }}]
        }}];
        var datum_stand = "{stand}";
    </script>'''


class ParseVPlanHtmlTests(unittest.TestCase):
    def test_extracts_nested_json_and_metadata(self):
        result = parse_vplan_html(sample_html(), TEST_SCHOOL_ID)

        self.assertEqual(result["meta"]["stand"], "2026-08-18 11:52:10")
        self.assertEqual(result["meta"]["schoolId"], TEST_SCHOOL_ID)
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


class VPlanSyncConfigTests(unittest.TestCase):
    def test_loads_school_id_from_dotenv_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / ".env").write_text("VPLAN_SCHOOL_ID=123\n", encoding="utf-8")

            with patch.dict(os.environ, {}, clear=True):
                config = VPlanSyncConfig.from_environment(root)

            self.assertEqual(config.school_id, 123)
            self.assertIn("schoolId=123", config.board_url)

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
            modification_url="https://example.invalid/modification",
            check_interval_seconds=120,
            full_refresh_interval_seconds=3_600,
            request_timeout_seconds=5,
            max_response_bytes=1024 * 1024,
        )

    def tearDown(self):
        self.temporary_directory.cleanup()

    def write_plan(self, stand: str) -> dict:
        plan = parse_vplan_html(sample_html(stand), TEST_SCHOOL_ID)
        self.config.plan_path.write_text(json.dumps(plan), encoding="utf-8")
        return plan

    def test_changed_modification_date_replaces_the_plan(self):
        self.write_plan("2026-08-18 10:00:00")
        synchronizer = VPlanSynchronizer(self.config)
        synchronizer._get_remote_modification = Mock(return_value="2026-08-18 11:52:10")
        synchronizer._download_plan = Mock(
            return_value=parse_vplan_html(
                sample_html("2026-08-18 11:52:10"), TEST_SCHOOL_ID
            )
        )

        result = synchronizer.sync_if_due()

        self.assertEqual(result["status"], "updated")
        saved = json.loads(self.config.plan_path.read_text(encoding="utf-8"))
        self.assertEqual(saved["meta"]["stand"], "2026-08-18 11:52:10")

    def test_null_modification_date_uses_hourly_fallback(self):
        self.write_plan("2026-08-18 11:52:10")
        self.config.state_path.write_text(
            json.dumps({"last_full_refresh_epoch": time.time()}), encoding="utf-8"
        )
        synchronizer = VPlanSynchronizer(self.config)
        synchronizer._get_remote_modification = Mock(return_value=None)
        synchronizer._download_plan = Mock()

        result = synchronizer.sync_if_due()

        self.assertEqual(result["status"], "checked")
        self.assertIn("no usable timestamp", result["warning"])
        synchronizer._download_plan.assert_not_called()

    def test_existing_plan_survives_a_failed_refresh(self):
        original = self.write_plan("2026-08-18 10:00:00")
        synchronizer = VPlanSynchronizer(self.config)
        synchronizer._get_remote_modification = Mock(return_value="2026-08-18 11:52:10")
        synchronizer._download_plan = Mock(side_effect=VPlanSyncError("invalid board"))

        result = synchronizer.sync_if_due()

        self.assertEqual(result["status"], "error")
        saved = json.loads(self.config.plan_path.read_text(encoding="utf-8"))
        self.assertEqual(saved, original)


if __name__ == "__main__":
    unittest.main()
