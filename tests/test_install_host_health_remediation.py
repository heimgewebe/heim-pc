from __future__ import annotations

import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "install_host_health_remediation",
    ROOT / "scripts/install_host_health_remediation.py",
)
assert SPEC and SPEC.loader
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallHostHealthRemediationTests(unittest.TestCase):
    def test_plan_has_no_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            files = installer.install_files(
                source_root=ROOT,
                target_root=target,
                apply=False,
            )
            self.assertTrue(all(item["action"] == "planned" for item in files))
            self.assertEqual(list(target.iterdir()), [])

    def test_apply_is_idempotent_and_preserves_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            first = installer.install_files(
                source_root=ROOT,
                target_root=target,
                apply=True,
            )
            second = installer.install_files(
                source_root=ROOT,
                target_root=target,
                apply=True,
            )
            self.assertTrue(all(item["action"] == "installed" for item in first))
            self.assertTrue(all(item["action"] == "unchanged" for item in second))
            executable = target / "usr/local/sbin/heim-pc-host-health"
            drop_in = (
                target
                / "etc/systemd/user/fluidsynth.service.d/50-heim-pc-gdm-guard.conf"
            )
            self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(drop_in.stat().st_mode), 0o644)
            self.assertIn("ConditionUser=!gdm", drop_in.read_text(encoding="utf-8"))
            self.assertNotIn("alex", drop_in.read_text(encoding="utf-8"))
            journald = (
                target
                / "etc/systemd/journald.conf.d/50-heim-pc-retention.conf"
            )
            self.assertEqual(stat.S_IMODE(journald.stat().st_mode), 0o644)
            self.assertIn(
                "SystemMaxUse=2G", journald.read_text(encoding="utf-8")
            )
            self.assertIn(
                "SystemKeepFree=20G", journald.read_text(encoding="utf-8")
            )
            self.assertIn(
                "MaxRetentionSec=14day", journald.read_text(encoding="utf-8")
            )

    def test_existing_cpu_unit_is_backed_up_before_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            unit = target / "etc/systemd/system/cpu-governor.service"
            unit.parent.mkdir(parents=True)
            original = b"[Service]\nExecStart=/old/command\n"
            unit.write_bytes(original)
            results = installer.install_files(
                source_root=ROOT,
                target_root=target,
                apply=True,
            )
            cpu_result = next(
                item
                for item in results
                if item["target"].endswith("/cpu-governor.service")
            )
            self.assertIsNotNone(cpu_result["backup"])
            self.assertEqual(Path(cpu_result["backup"]).read_bytes(), original)
            self.assertIn(
                "ensure-performance-profile", unit.read_text(encoding="utf-8")
            )

    def test_symlink_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            outside = target / "outside"
            outside.mkdir()
            etc = target / "etc"
            etc.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(installer.InstallError, "symlink"):
                installer.install_files(
                    source_root=ROOT,
                    target_root=target,
                    apply=True,
                )

    def test_units_preserve_alex_and_bound_monitor_resources(self) -> None:
        fluid = (
            ROOT
            / "systemd/user/fluidsynth.service.d/50-heim-pc-gdm-guard.conf"
        ).read_text(encoding="utf-8")
        monitor = (
            ROOT / "systemd/system/heim-pc-mce-edac-monitor.service"
        ).read_text(encoding="utf-8")
        cpu = (ROOT / "systemd/system/cpu-governor.service").read_text(
            encoding="utf-8"
        )
        journald = (
            ROOT / "systemd/journald.conf.d/50-heim-pc-retention.conf"
        ).read_text(encoding="utf-8")
        self.assertIn("ConditionUser=!gdm", fluid)
        self.assertNotIn("ConditionUser=!alex", fluid)
        self.assertIn("TimeoutStartSec=30s", monitor)
        self.assertIn("CPUQuota=10%", monitor)
        self.assertIn("MemoryMax=64M", monitor)
        self.assertIn("ensure-performance-profile", cpu)
        self.assertIn("Storage=persistent", journald)
        self.assertIn("SystemMaxUse=2G", journald)
        self.assertIn("SystemKeepFree=20G", journald)
        self.assertIn("MaxRetentionSec=14day", journald)


if __name__ == "__main__":
    unittest.main()
