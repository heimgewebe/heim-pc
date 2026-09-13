from __future__ import annotations

import importlib.util
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "install_grok_subscription_wrapper",
    ROOT / "scripts/install_grok_subscription_wrapper.py",
)
assert SPEC and SPEC.loader
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class GrokSubscriptionWrapperInstallerTests(unittest.TestCase):
    def _home(self, root: Path) -> Path:
        home = root / "home"
        home.mkdir()
        return home

    def _fake_official(self, home: Path) -> Path:
        target = home / ".npm-global/bin/grok"
        target.parent.mkdir(parents=True)
        target.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "printf '%s|%s\\n' \"${XAI_API_KEY-unset}\" \"$*\"\n",
            encoding="utf-8",
        )
        target.chmod(0o755)
        return target

    def test_plan_is_read_only_and_reports_missing_official_entrypoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = self._home(Path(directory))
            result = installer.install(home=home, apply=False)
            self.assertFalse(result["apply"])
            self.assertFalse(result["officialEntrypointReady"])
            self.assertEqual(result["action"], "install")
            self.assertFalse((home / ".local/bin/grok").exists())

    def test_apply_executes_official_entrypoint_without_api_key_or_node_assumption(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = self._home(Path(directory))
            self._fake_official(home)
            result = installer.install(home=home, apply=True)
            wrapper = home / ".local/bin/grok"
            self.assertEqual(result["action"], "install")
            self.assertEqual(stat.S_IMODE(wrapper.stat().st_mode), 0o755)
            payload = wrapper.read_text(encoding="utf-8")
            self.assertNotIn("/usr/bin/node", payload)
            self.assertIn(".npm-global/bin/grok", payload)

            environment = dict(os.environ)
            environment["HOME"] = str(home)
            environment["XAI_API_KEY"] = "must-not-propagate"
            run = subprocess.run(
                [str(wrapper), "models", "--example"],
                text=True,
                capture_output=True,
                env=environment,
                check=True,
            )
            self.assertEqual(run.stdout.strip(), "unset|models --example")

            again = installer.install(home=home, apply=True)
            self.assertEqual(again["action"], "unchanged")

    def test_existing_different_launcher_requires_explicit_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = self._home(Path(directory))
            self._fake_official(home)
            wrapper = home / ".local/bin/grok"
            wrapper.parent.mkdir(parents=True)
            wrapper.write_text("old launcher\n", encoding="utf-8")
            with self.assertRaises(installer.InstallConflict):
                installer.install(home=home, apply=True)
            result = installer.install(home=home, apply=True, replace_existing=True)
            self.assertTrue(result["requiresReplacement"])
            self.assertEqual(wrapper.read_bytes(), installer.WRAPPER)

    def test_symlink_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = self._home(root)
            self._fake_official(home)
            outside = root / "outside"
            outside.write_text("outside\n", encoding="utf-8")
            wrapper = home / ".local/bin/grok"
            wrapper.parent.mkdir(parents=True)
            wrapper.symlink_to(outside)
            with self.assertRaises(installer.InstallConflict):
                installer.install(home=home, apply=False)


if __name__ == "__main__":
    unittest.main()
