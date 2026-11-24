"""Nabu package deployment tests: no real services, accounts, or devices."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[3] / "scripts/nabu_deploy.py"
spec = importlib.util.spec_from_file_location("nabu_deploy", MODULE)
nabu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nabu)
COMMIT = "a" * 40


class DeployTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.target = root / "nabu_web"
        self.target.mkdir()
        self.backups = root / "backups"
        self.release = {name: b"x = 1\n" for name in nabu.FILES}
        self.release["manifest.json"] = b'{"domain":"nabu_web"}\n'
        for name, content in self.release.items():
            (self.target / name).write_bytes(content)
        self.events = []

    def change(self, name="llm.py"):
        self.release[name] = b"x = 2\n"

    def fingerprint(self):
        return nabu.plan(self.target, COMMIT, self.release,
                         nabu.snapshot(self.target))["drift_fingerprint"]

    def apply(self, expected=None, smoke=None, health=None):
        return nabu.deploy(self.target, self.backups, COMMIT, self.release,
                           expected or self.fingerprint(),
                           check_active=lambda: self.events.append("active"),
                           import_smoke=smoke or (lambda: self.events.append("import")),
                           restart_service=lambda: self.events.append("restart"),
                           verify_health=health or (lambda: self.events.append("health")))

    def test_no_change_no_restart_or_backup(self):
        result = self.apply()
        self.assertEqual(result["status"], "already_current")
        self.assertEqual(self.events, [])
        self.assertFalse(self.backups.exists())

    def test_only_changed_files_and_private_backup(self):
        self.change()
        untouched = self.target / "radio.py"
        before = untouched.stat().st_mtime_ns
        result = self.apply()
        self.assertEqual(result["status"], "applied")
        self.assertEqual(self.events, ["active", "import", "restart", "health"])
        self.assertEqual(nabu.snapshot(self.target), self.release)
        self.assertEqual(untouched.stat().st_mtime_ns, before)
        backup = Path(result["backup"])
        self.assertEqual((backup / "llm.py").read_bytes(), b"x = 1\n")
        self.assertEqual(backup.stat().st_mode & 0o077, 0)
        self.assertEqual(json.loads((backup / "plan.json").read_text())["changed"], ["llm.py"])

    def test_stale_drift_refused_before_write(self):
        self.change()
        expected = self.fingerprint()
        (self.target / "llm.py").write_bytes(b"x = 3\n")
        with self.assertRaisesRegex(RuntimeError, "drift changed"):
            self.apply(expected)
        self.assertEqual((self.target / "llm.py").read_bytes(), b"x = 3\n")
        self.assertEqual(self.events, [])

    def test_import_failure_restores_without_restart(self):
        self.change()
        old = nabu.snapshot(self.target)
        def fail():
            raise RuntimeError("bad import")
        with self.assertRaisesRegex(RuntimeError, "original package restored"):
            self.apply(smoke=fail)
        self.assertEqual(nabu.snapshot(self.target), old)
        self.assertEqual(self.events, ["active"])

    def test_health_failure_restores_and_restarts_old(self):
        self.change()
        old = nabu.snapshot(self.target)
        def health():
            self.events.append("health")
            if self.events.count("health") == 1:
                raise RuntimeError("not ready")
        with self.assertRaisesRegex(RuntimeError, "original package restored"):
            self.apply(health=health)
        self.assertEqual(nabu.snapshot(self.target), old)
        self.assertEqual(self.events, ["active", "import", "restart", "health", "restart", "health"])

    def test_missing_file_is_created_then_removed_on_failed_import(self):
        (self.target / "llm.py").unlink()
        def fail():
            raise RuntimeError("bad import")
        with self.assertRaisesRegex(RuntimeError, "original package restored"):
            self.apply(smoke=fail)
        self.assertFalse((self.target / "llm.py").exists())

    def test_symlink_target_rejected(self):
        (self.target / "llm.py").unlink()
        (self.target / "llm.py").symlink_to(self.target / "radio.py")
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            self.fingerprint()

    def test_invalid_source_rejected_without_writes(self):
        self.release["llm.py"] = b"def ("
        with self.assertRaises(SyntaxError):
            self.apply()
        self.assertEqual(self.events, [])


if __name__ == "__main__":
    unittest.main()
