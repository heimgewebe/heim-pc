from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import stat
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
                    "verify_unit_data",
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
            self.assertIn("MemorySwapMax=0", service)
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

    def test_live_apply_requires_expected_head(self) -> None:
        with patch.object(installer.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(
                installer.InstallError,
                "requires expected_head",
            ):
                installer.install(
                    system_root=Path("/"),
                    release_root=installer.DEFAULT_RELEASE_ROOT,
                    apply=True,
                    enable=False,
                    start=False,
                    expected_head=None,
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

    def test_activation_preflight_accepts_healthy_persistent_state(self) -> None:
        completed = subprocess.CompletedProcess(
            ["python"],
            0,
            json.dumps(
                {
                    "action": "none",
                    "reason": "healthy",
                    "result": "preflight",
                    "persistent_state": {
                        "circuit_open": False,
                        "consecutive_over_limit": 0,
                        "restart_history_count": 0,
                        "last_pid": 123,
                        "pending_action": None,
                    },
                }
            ),
            "",
        )
        with patch.object(installer, "run", return_value=completed) as mocked:
            result = installer.observe_only_preflight(Path("/release"))
        argv = mocked.call_args.args[0]
        self.assertIn("--preflight-only", argv)
        self.assertIn(str(installer.STATE_DIR), argv)
        self.assertEqual(result["action"], "none")
        self.assertEqual(result["result"], "preflight")

    def test_activation_preflight_refuses_pending_restart(self) -> None:
        completed = subprocess.CompletedProcess(
            ["python"],
            0,
            json.dumps(
                {
                    "action": "restart",
                    "reason": "sustained_grabowski_rss",
                    "result": "preflight",
                    "persistent_state": {
                        "circuit_open": False,
                        "consecutive_over_limit": 1,
                        "restart_history_count": 0,
                        "last_pid": 123,
                        "pending_action": None,
                    },
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

    def test_activation_preflight_refuses_open_persistent_circuit(self) -> None:
        completed = subprocess.CompletedProcess(
            ["python"],
            0,
            json.dumps(
                {
                    "action": "stop-circuit",
                    "reason": "circuit_already_open",
                    "result": "preflight",
                    "persistent_state": {
                        "circuit_open": True,
                        "consecutive_over_limit": 0,
                        "restart_history_count": 1,
                        "last_pid": 123,
                        "pending_action": {
                            "action": "restart",
                            "initiated_at_unix": 100,
                            "pid": 123,
                            "reason": "host_memory_emergency",
                        },
                    },
                }
            ),
            "",
        )
        with patch.object(installer, "run", return_value=completed):
            with self.assertRaisesRegex(
                installer.InstallError,
                "persistent circuit is open",
            ):
                installer.observe_only_preflight(Path("/release"))

    def test_activation_preflight_precedes_unit_install_enable_and_restart(self) -> None:
        head = "d" * 40
        release = installer.DEFAULT_RELEASE_ROOT / head
        blobs = self.blobs()
        events: list[tuple[str, str]] = []

        def fake_atomic(path: Path, data: bytes, mode: int) -> dict[str, object]:
            events.append(("install", str(path)))
            return {
                "path": str(path),
                "action": "installed",
                "mode": format(mode, "04o"),
                "sha256": installer.sha256(data),
            }

        def fake_preflight(candidate_release: Path) -> dict[str, object]:
            events.append(("preflight", str(candidate_release)))
            return {
                "action": "none",
                "reason": "healthy",
                "result": "preflight",
                "persistent_state": {
                    "circuit_open": False,
                    "pending_action": None,
                },
            }

        def fake_run(
            argv: list[str], *, cwd: Path | None = None
        ) -> subprocess.CompletedProcess[str]:
            events.append(("run", " ".join(argv)))
            if argv[1:3] == ["show", f"{installer.UNIT_NAME}.service"]:
                if "--value" in argv:
                    return subprocess.CompletedProcess(argv, 0, "loaded\n", "")
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    "ActiveState=active\n"
                    "MainPID=456\n"
                    f"ControlGroup=/system.slice/{installer.UNIT_NAME}.service\n",
                    "",
                )
            return subprocess.CompletedProcess(argv, 0, "", "")

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
                "verify_unit_data",
                return_value={"status": "verified", "returncode": 0},
            ),
            patch.object(installer.os, "geteuid", return_value=0),
            patch.object(installer, "existing_unit_enabled", return_value=False),
            patch.object(installer, "existing_unit_active", return_value=False),
            patch.object(installer, "observe_only_preflight", side_effect=fake_preflight),
            patch.object(installer, "atomic_install", side_effect=fake_atomic),
            patch.object(installer, "run", side_effect=fake_run),
            patch.object(
                installer,
                "read_process_argv",
                return_value=installer.expected_guard_argv(release),
            ),
        ):
            receipt = installer.install(
                system_root=Path("/"),
                release_root=installer.DEFAULT_RELEASE_ROOT,
                apply=True,
                enable=True,
                start=True,
                expected_head=head,
            )

        preflight_index = events.index(("preflight", str(release)))
        unit_install_index = next(
            index
            for index, event in enumerate(events)
            if event == ("install", str(installer.SYSTEM_UNIT_PATH))
        )
        enable_index = next(
            index
            for index, event in enumerate(events)
            if event == (
                "run",
                f"{installer.SYSTEMCTL} enable {installer.UNIT_NAME}.service",
            )
        )
        restart_index = next(
            index
            for index, event in enumerate(events)
            if event == (
                "run",
                f"{installer.SYSTEMCTL} restart {installer.UNIT_NAME}.service",
            )
        )

        self.assertLess(preflight_index, unit_install_index)
        self.assertLess(preflight_index, enable_index)
        self.assertLess(enable_index, restart_index)
        self.assertFalse(
            any(
                event
                == ("run", f"{installer.SYSTEMCTL} start {installer.UNIT_NAME}.service")
                for event in events
            )
        )
        self.assertEqual(
            receipt["systemd_state"],
            "enabled+restarted-active-exact-release",
        )
        self.assertEqual(
            receipt["running_argv"],
            installer.expected_guard_argv(release),
        )

    def test_preexisting_enabled_unit_is_preflighted_before_replacement(self) -> None:
        head = "e" * 40
        release = installer.DEFAULT_RELEASE_ROOT / head
        blobs = self.blobs()
        events: list[tuple[str, str]] = []

        def fake_atomic(path: Path, data: bytes, mode: int) -> dict[str, object]:
            events.append(("install", str(path)))
            return {
                "path": str(path),
                "action": "installed",
                "mode": format(mode, "04o"),
                "sha256": installer.sha256(data),
            }

        def fake_run(
            argv: list[str], *, cwd: Path | None = None
        ) -> subprocess.CompletedProcess[str]:
            if argv[1:3] == ["show", f"{installer.UNIT_NAME}.service"]:
                return subprocess.CompletedProcess(argv, 0, "loaded\n", "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        with (
            patch.object(installer, "repository_identity", return_value=(head, False)),
            patch.object(
                installer,
                "repository_blob",
                side_effect=lambda _root, *, head, relative_path: blobs[
                    relative_path
                ],
            ),
            patch.object(
                installer,
                "verify_unit_data",
                return_value={"status": "verified", "returncode": 0},
            ),
            patch.object(installer.os, "geteuid", return_value=0),
            patch.object(installer, "existing_unit_enabled", return_value=True),
            patch.object(installer, "existing_unit_active", return_value=False),
            patch.object(
                installer,
                "observe_only_preflight",
                side_effect=lambda candidate: (
                    events.append(("preflight", str(candidate)))
                    or {
                        "action": "none",
                        "result": "preflight",
                        "persistent_state": {
                            "circuit_open": False,
                            "pending_action": None,
                        },
                    }
                ),
            ),
            patch.object(installer, "atomic_install", side_effect=fake_atomic),
            patch.object(installer, "run", side_effect=fake_run),
        ):
            receipt = installer.install(
                system_root=Path("/"),
                release_root=installer.DEFAULT_RELEASE_ROOT,
                apply=True,
                enable=False,
                start=False,
                expected_head=head,
            )

        self.assertLess(
            events.index(("preflight", str(release))),
            events.index(("install", str(installer.SYSTEM_UNIT_PATH))),
        )
        self.assertEqual(receipt["systemd_state"], "installed-existing-enabled")

    def test_active_not_enabled_unit_is_preflighted_before_replacement(self) -> None:
        head = "1" * 40
        release = installer.DEFAULT_RELEASE_ROOT / head
        blobs = self.blobs()
        events: list[tuple[str, str]] = []

        def fake_atomic(path: Path, data: bytes, mode: int) -> dict[str, object]:
            events.append(("install", str(path)))
            return {
                "path": str(path),
                "action": "installed",
                "mode": format(mode, "04o"),
                "sha256": installer.sha256(data),
            }

        def fake_run(
            argv: list[str], *, cwd: Path | None = None
        ) -> subprocess.CompletedProcess[str]:
            if argv[1:3] == ["show", f"{installer.UNIT_NAME}.service"]:
                return subprocess.CompletedProcess(argv, 0, "loaded\n", "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        with (
            patch.object(installer, "repository_identity", return_value=(head, False)),
            patch.object(
                installer,
                "repository_blob",
                side_effect=lambda _root, *, head, relative_path: blobs[
                    relative_path
                ],
            ),
            patch.object(
                installer,
                "verify_unit_data",
                return_value={"status": "verified", "returncode": 0},
            ),
            patch.object(installer.os, "geteuid", return_value=0),
            patch.object(installer, "existing_unit_enabled", return_value=False),
            patch.object(installer, "existing_unit_active", return_value=True),
            patch.object(
                installer,
                "observe_only_preflight",
                side_effect=lambda candidate: (
                    events.append(("preflight", str(candidate)))
                    or {
                        "action": "none",
                        "result": "preflight",
                        "persistent_state": {
                            "circuit_open": False,
                            "pending_action": None,
                        },
                    }
                ),
            ),
            patch.object(installer, "atomic_install", side_effect=fake_atomic),
            patch.object(installer, "run", side_effect=fake_run),
        ):
            receipt = installer.install(
                system_root=Path("/"),
                release_root=installer.DEFAULT_RELEASE_ROOT,
                apply=True,
                enable=False,
                start=False,
                expected_head=head,
            )

        self.assertLess(
            events.index(("preflight", str(release))),
            events.index(("install", str(installer.SYSTEM_UNIT_PATH))),
        )
        self.assertEqual(receipt["systemd_state"], "installed-existing-active")
        self.assertTrue(receipt["preexisting_active"])

    def test_atomic_install_uses_0755_parent_and_fsyncs_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "a" / "b" / "payload"
            with patch.object(installer, "_fsync_directory") as fsync_directory:
                result = installer.atomic_install(target, b"payload", 0o600)
            self.assertEqual(result["action"], "installed")
            self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o755)
            fsync_directory.assert_called_once_with(target.parent)

    def test_running_release_must_match_exact_commit(self) -> None:
        head = "f" * 40
        blobs = self.blobs()

        def fake_atomic(path: Path, data: bytes, mode: int) -> dict[str, object]:
            return {
                "path": str(path),
                "action": "installed",
                "mode": format(mode, "04o"),
                "sha256": installer.sha256(data),
            }

        def fake_run(
            argv: list[str], *, cwd: Path | None = None
        ) -> subprocess.CompletedProcess[str]:
            if argv[1:3] == ["show", f"{installer.UNIT_NAME}.service"]:
                if "--value" in argv:
                    return subprocess.CompletedProcess(argv, 0, "loaded\n", "")
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    "ActiveState=active\n"
                    "MainPID=456\n"
                    f"ControlGroup=/system.slice/{installer.UNIT_NAME}.service\n",
                    "",
                )
            return subprocess.CompletedProcess(argv, 0, "", "")

        with (
            patch.object(installer, "repository_identity", return_value=(head, False)),
            patch.object(
                installer,
                "repository_blob",
                side_effect=lambda _root, *, head, relative_path: blobs[
                    relative_path
                ],
            ),
            patch.object(
                installer,
                "verify_unit_data",
                return_value={"status": "verified", "returncode": 0},
            ),
            patch.object(installer.os, "geteuid", return_value=0),
            patch.object(installer, "existing_unit_enabled", return_value=False),
            patch.object(installer, "existing_unit_active", return_value=False),
            patch.object(
                installer,
                "observe_only_preflight",
                return_value={
                        "action": "none",
                        "result": "preflight",
                        "persistent_state": {
                            "circuit_open": False,
                            "pending_action": None,
                        },
                    },
            ),
            patch.object(installer, "atomic_install", side_effect=fake_atomic),
            patch.object(installer, "run", side_effect=fake_run),
            patch.object(
                installer,
                "read_process_argv",
                return_value=[
                    installer.PYTHON,
                    "/usr/local/lib/heim-pc/memory-pressure-guard/releases/old/scripts/grabowski_memory_guard.py",
                ],
            ),
        ):
            with self.assertRaisesRegex(
                installer.InstallError,
                "does not match the installed release",
            ):
                installer.install(
                    system_root=Path("/"),
                    release_root=installer.DEFAULT_RELEASE_ROOT,
                    apply=True,
                    enable=False,
                    start=True,
                    expected_head=head,
                )

    def test_system_template_is_outside_target_cgroup(self) -> None:
        service = installer.SYSTEM_SERVICE_TEMPLATE.read_text()
        self.assertNotIn("PartOf=grabowski-operator.service", service)
        self.assertNotIn("Slice=grabowski", service)
        self.assertIn("OOMScoreAdjust=-900", service)
        self.assertIn("MemoryMax=128M", service)
        self.assertIn("MemorySwapMax=0", service)


if __name__ == "__main__":
    unittest.main()