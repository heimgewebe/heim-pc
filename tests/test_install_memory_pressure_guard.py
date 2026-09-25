from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "install_memory_pressure_guard",
    ROOT / "scripts/install_memory_pressure_guard.py",
)
assert SPEC and SPEC.loader
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallMemoryPressureGuardTests(unittest.TestCase):
    def blobs(self) -> dict[str, bytes]:
        values = {
            relative: source.read_bytes()
            for relative, source in installer.SOURCES.items()
        }
        values[
            "systemd/system/heim-pc-grabowski-memory-guard.service.in"
        ] = installer.SYSTEM_SERVICE_TEMPLATE.read_bytes()
        return values

    def test_staged_install_contains_only_independent_guard(self) -> None:
        head = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            system_root = base / "system"
            blobs = self.blobs()
            with (
                patch.object(
                    installer,
                    "repository_identity",
                    return_value=(head, False),
                ),
                patch.object(
                    installer,
                    "repository_blob",
                    side_effect=lambda _root, *, head, relative_path: blobs[
                        relative_path
                    ],
                ),
                patch.object(
                    installer,
                    "verify_unit_file",
                    return_value={"status": "verified", "returncode": 0},
                ),
                patch.object(installer.os, "geteuid", return_value=1000),
            ):
                receipt = installer.install(
                    system_root=system_root,
                    release_root=installer.DEFAULT_RELEASE_ROOT,
                    apply=True,
                    enable=False,
                    start=False,
                    expected_head=head,
                )

            release = (
                system_root
                / "usr/local/lib/heim-pc/memory-pressure-guard/releases"
                / head
            )
            self.assertTrue(
                (release / "scripts/grabowski_memory_guard.py").is_file()
            )
            self.assertTrue(
                (release / "config/memory-pressure-guard.v1.json").is_file()
            )
            service = (
                system_root
                / "etc/systemd/system/heim-pc-grabowski-memory-guard.service"
            ).read_text()
            self.assertIn(
                f"/usr/local/lib/heim-pc/memory-pressure-guard/releases/{head}",
                service,
            )
            self.assertIn(
                "StateDirectory=heim-pc/grabowski-memory-guard",
                service,
            )
            self.assertIn("OOMScoreAdjust=-900", service)
            self.assertNotIn("PartOf=grabowski-operator.service", service)
            self.assertNotIn("earlyoom", service.lower())
            self.assertEqual(receipt["systemd_state"], "staged-root-installed")

    def test_live_apply_requires_root(self) -> None:
        with (
            patch.object(
                installer,
                "repository_identity",
                return_value=("b" * 40, False),
            ),
            patch.object(installer.os, "geteuid", return_value=1000),
        ):
            with self.assertRaisesRegex(installer.InstallError, "requires root"):
                installer.install(
                    system_root=Path("/"),
                    release_root=installer.DEFAULT_RELEASE_ROOT,
                    apply=True,
                    enable=False,
                    start=False,
                )

    def test_staged_root_cannot_control_live_service(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                installer.InstallError,
                "live system root",
            ):
                installer.install(
                    system_root=Path(temporary),
                    release_root=installer.DEFAULT_RELEASE_ROOT,
                    apply=True,
                    enable=True,
                    start=False,
                )

    def test_dirty_repository_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with (
                patch.object(
                    installer,
                    "repository_identity",
                    return_value=("c" * 40, True),
                ),
                patch.object(installer.os, "geteuid", return_value=1000),
            ):
                with self.assertRaisesRegex(installer.InstallError, "clean"):
                    installer.install(
                        system_root=Path(temporary),
                        release_root=installer.DEFAULT_RELEASE_ROOT,
                        apply=False,
                        enable=False,
                        start=False,
                    )

    def test_observe_only_preflight_accepts_healthy_state(self) -> None:
        completed = subprocess.CompletedProcess(
            ["python"],
            0,
            json.dumps(
                {
                    "action": "none",
                    "reason": "healthy",
                    "result": "observed",
                }
            ),
            "",
        )
        with patch.object(installer, "run", return_value=completed):
            result = installer.observe_only_preflight(Path("/release"))
        self.assertEqual(result["action"], "none")

    def test_observe_only_preflight_refuses_pending_restart(self) -> None:
        completed = subprocess.CompletedProcess(
            ["python"],
            0,
            json.dumps(
                {
                    "action": "restart",
                    "reason": "host_memory_emergency",
                    "result": "observe-only",
                }
            ),
            "",
        )
        with patch.object(installer, "run", return_value=completed):
            with self.assertRaisesRegex(
                installer.InstallError,
                "not safe for automatic activation",
            ):
                installer.observe_only_preflight(Path("/release"))

    def test_system_template_is_outside_target_cgroup(self) -> None:
        service = installer.SYSTEM_SERVICE_TEMPLATE.read_text()
        self.assertNotIn("PartOf=grabowski-operator.service", service)
        self.assertNotIn("Slice=grabowski", service)
        self.assertIn("OOMScoreAdjust=-900", service)
        self.assertIn("MemoryMax=128M", service)


if __name__ == "__main__":
    unittest.main()
