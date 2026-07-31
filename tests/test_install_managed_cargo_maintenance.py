from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("install_managed_cargo_maintenance", ROOT / "scripts/install_managed_cargo_maintenance.py")
assert SPEC and SPEC.loader
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallManagedCargoMaintenanceTests(unittest.TestCase):
    def test_install_renders_commit_bound_release_and_units(self) -> None:
        head = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            home = base / "home"
            release_root = base / "releases"
            blobs = {relative: source.read_bytes() for relative, source in installer.SOURCES.items()}
            blobs["systemd/user/heim-pc-managed-cargo-maintenance.service.in"] = installer.SERVICE_TEMPLATE.read_bytes()
            blobs["systemd/user/heim-pc-managed-cargo-maintenance.timer"] = installer.TIMER_SOURCE.read_bytes()

            def fake_run(argv: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
                if argv[:3] == ["systemctl", "--user", "show"]:
                    return subprocess.CompletedProcess(argv, 0, "loaded\n", "")
                return subprocess.CompletedProcess(argv, 0, "", "")

            with (
                patch.object(installer, "repository_identity", return_value=(head, False)),
                patch.object(installer, "repository_blob", side_effect=lambda _root, *, head, relative_path: blobs[relative_path]),
                patch.object(installer, "run", side_effect=fake_run),
                patch.object(installer, "verify_unit_files", return_value={"status": "verified", "returncode": 0}),
            ):
                receipt = installer.install(home=home, release_root=release_root, apply=True, enable=True, start=False, expected_head=head)

            release = release_root / head
            self.assertEqual(receipt["systemd"], "timer-enabled")
            for relative in installer.SOURCES:
                self.assertTrue((release / relative).is_file())
            service = (home / ".config/systemd/user/heim-pc-managed-cargo-maintenance.service").read_text()
            self.assertIn(str(release), service)
            self.assertIn("ProtectHome=read-only", service)
            self.assertIn(f"ReadWritePaths={home}/.cache/heim-pc/managed-builds", service)
            self.assertNotIn("@RELEASE_ROOT@", service)
            timer = (home / ".config/systemd/user/heim-pc-managed-cargo-maintenance.timer").read_text()
            self.assertIn("OnCalendar=hourly", timer)
            import_check = subprocess.run(
                [sys.executable, str(release / "scripts/managed_cargo_maintenance.py"), "--help"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(import_check.returncode, 0, import_check.stderr)

    def test_dirty_repository_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            with patch.object(installer, "repository_identity", return_value=("b" * 40, True)):
                with self.assertRaisesRegex(installer.InstallError, "clean"):
                    installer.install(home=base / "home", release_root=base / "releases", apply=False, enable=False, start=False)


if __name__ == "__main__":
    unittest.main()
