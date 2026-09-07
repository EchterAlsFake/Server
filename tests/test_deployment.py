"""Cutover recovery tests use temporary files and never invoke systemd."""
import importlib.machinery
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


loader = importlib.machinery.SourceFileLoader(
    "eaf_deploy", str(Path(__file__).resolve().parents[1] / "deploy/eaf-deploy")
)
spec = importlib.util.spec_from_loader(loader.name, loader)
deployment = importlib.util.module_from_spec(spec)
loader.exec_module(deployment)


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.live = self.root / "server"
        self.live.mkdir()
        (self.live / ".venv").mkdir()
        (self.live / "data").mkdir()
        (self.live / "data/server.db").write_text("previous database")
        (self.live / ".env").write_text("test configuration")
        (self.live / "main.py").write_text("previous code")
        self.stage = self.root / "candidate"
        self.stage.mkdir()
        (self.stage / "main.py").write_text("new code")
        for target, options in (
            ("ROOT", {"new": self.root}),
            ("protect", {}), ("run", {}),
        ):
            patcher = patch.object(deployment, target, **options)
            patcher.start()
            self.addCleanup(patcher.stop)
        for target in ("os.chown", "os.chmod"):
            patcher = patch.object(
                deployment.os, target.split(".")[1]
            )
            patcher.start()
            self.addCleanup(patcher.stop)

        patcher = patch.object(deployment.pwd, "getpwnam",
                               return_value=SimpleNamespace(pw_uid=1000, pw_gid=1000))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_failed_activation_restores_matching_code_and_database(self):
        def fail(app):
            (self.live / "data/server.db").write_text("migrated database")
            raise RuntimeError("health check failed")
        with patch.object(deployment, "activate", side_effect=fail):
            with self.assertRaisesRegex(RuntimeError, "health check failed"):
                deployment.install("server", self.stage, False)
        self.assertEqual((self.live / "main.py").read_text(), "previous code")
        self.assertEqual((self.live / "data/server.db").read_text(), "previous database")
        self.assertEqual((self.live / ".env").read_text(), "test configuration")
        failed = list((self.root / ".eaf-backups").glob("failed-*"))
        self.assertEqual(len(failed), 1)
        self.assertEqual((failed[0] / "data/server.db").read_text(), "migrated database")

    def test_success_preserves_private_data_and_stopped_backup(self):
        with patch.object(deployment, "activate"):
            deployment.install("server", self.stage, False)
        self.assertEqual((self.live / "main.py").read_text(), "new code")
        self.assertEqual((self.live / "data/server.db").read_text(), "previous database")
        backup, = (self.root / ".eaf-backups").iterdir()
        self.assertEqual((backup / "main.py").read_text(), "previous code")

    def test_prepare_refuses_to_overwrite_existing_installation(self):
        with self.assertRaisesRegex(RuntimeError, "Already prepared"):
            deployment.install("server", self.stage, True)
        self.assertEqual((self.live / "main.py").read_text(), "previous code")
