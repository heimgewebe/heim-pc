from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
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
            self.assertIn("KillMode=mixed", service)
            self.assertIn("SendSIGKILL=yes", service)
            self.assertIn("TimeoutStopSec=150s", service)
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
            "enabled+exact-release-process-observed",
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

    def test_atomic_install_uses_0755_parent_and_fsyncs_every_new_directory_edge(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            target = base / "a" / "b" / "payload"
            fsynced_paths: list[str] = []
            real_fsync = os.fsync

            def traced_fsync(fd: int) -> None:
                fsynced_paths.append(os.readlink(f"/proc/self/fd/{fd}"))
                real_fsync(fd)

            with patch.object(installer.os, "fsync", side_effect=traced_fsync):
                result = installer.atomic_install(target, b"payload", 0o600)

            self.assertEqual(result["action"], "installed")
            self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o755)
            self.assertIn(str(base), fsynced_paths)
            self.assertIn(str(base / "a"), fsynced_paths)
            self.assertIn(str(base / "a" / "b"), fsynced_paths)

    def test_atomic_install_rejects_symlinked_parent_ancestor_without_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            stage = base / "stage"
            outside = base / "outside"
            stage.mkdir()
            (outside / "systemd/system").mkdir(parents=True)
            (stage / "etc").symlink_to(outside, target_is_directory=True)
            escaped_target = outside / "systemd/system/payload"

            with self.assertRaisesRegex(
                installer.InstallError,
                "install parent ancestor is unsafe",
            ):
                installer.atomic_install(
                    stage / "etc/systemd/system/payload",
                    b"payload",
                    0o600,
                )

            self.assertFalse(escaped_target.exists())

    def test_cli_preserves_symlinked_system_root_for_fail_closed_rejection(self) -> None:
        head = "a" * 40
        blobs = self.blobs()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            outside = base / "outside"
            outside.mkdir()
            system_root = base / "stage"
            system_root.symlink_to(outside, target_is_directory=True)
            argv = [
                "install_memory_pressure_guard.py",
                "--system-root",
                str(system_root),
                "--apply",
                "--expected-head",
                head,
            ]
            with (
                patch.object(sys, "argv", argv),
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
            ):
                self.assertEqual(installer.main(), 1)

            self.assertTrue(system_root.is_symlink())
            self.assertFalse((outside / "usr").exists())
            self.assertFalse((outside / "etc").exists())

    def test_unit_state_probe_fails_closed_on_systemctl_error(self) -> None:
        with patch.object(
            installer,
            "run",
            side_effect=installer.InstallError("Failed to connect to bus"),
        ):
            with self.assertRaisesRegex(
                installer.InstallError,
                "Failed to connect to bus",
            ):
                installer.existing_unit_active()

    def test_unit_state_probe_accepts_known_negative_states(self) -> None:
        active = subprocess.CompletedProcess(
            ["systemctl"],
            0,
            "LoadState=loaded\nActiveState=inactive\n",
            "",
        )
        enabled = subprocess.CompletedProcess(
            ["systemctl"],
            0,
            "LoadState=loaded\nUnitFileState=disabled\n",
            "",
        )
        with patch.object(
            installer,
            "run",
            side_effect=[active, enabled],
        ):
            self.assertFalse(installer.existing_unit_active())
            self.assertFalse(installer.existing_unit_enabled())

    def test_unit_state_probe_treats_missing_unit_as_safe_absence(self) -> None:
        enabled = subprocess.CompletedProcess(
            ["systemctl"],
            0,
            "LoadState=not-found\nUnitFileState=\n",
            "",
        )
        active = subprocess.CompletedProcess(
            ["systemctl"],
            0,
            "LoadState=not-found\nActiveState=inactive\n",
            "",
        )
        with patch.object(
            installer,
            "run",
            side_effect=[enabled, active],
        ):
            self.assertFalse(installer.existing_unit_enabled())
            self.assertFalse(installer.existing_unit_active())

    def test_unit_state_probe_rejects_transitional_active_state(self) -> None:
        completed = subprocess.CompletedProcess(
            ["systemctl"],
            0,
            "LoadState=loaded\nActiveState=activating\n",
            "",
        )
        with patch.object(installer, "run", return_value=completed):
            with self.assertRaisesRegex(
                installer.InstallError,
                "transitional/unknown ActiveState",
            ):
                installer.existing_unit_active()


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


    def test_verify_rejects_basename_diagnostic_even_with_host_sigabrt(self) -> None:
        path = Path("/tmp/verify") / f"{installer.UNIT_NAME}.service"
        stderr = (f"{path.name}:14: Unknown key name 'Broken'\n"
                  "Failed to allocate device monitor\nAssertion '*_head == _item' failed\n")
        with patch.object(installer.subprocess, "run", return_value=
                subprocess.CompletedProcess([], -installer.signal.SIGABRT, "", stderr)):
            with self.assertRaisesRegex(installer.InstallError, "target diagnostics"):
                installer.verify_unit_file(path)

    def test_atomic_install_rejects_dangling_ancestor_without_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            stage = base / "stage"
            stage.mkdir()
            outside = base / "absent-outside"
            (stage / "etc").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(installer.InstallError):
                installer.atomic_install(stage / "etc/systemd/system/unit", b"unit", 0o644)
            self.assertFalse(outside.exists())
            self.assertEqual(list(stage.iterdir()), [stage / "etc"])

    def test_install_parent_fd_survives_visible_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            stage = base / "stage"
            stage.mkdir()
            outside = base / "outside"
            outside.mkdir()
            original = base / "original-stage"
            real_open = installer._open_install_directory_fd
            def swapped(path, *, create):
                fd = real_open(path, create=create)
                stage.rename(original)
                stage.symlink_to(outside, target_is_directory=True)
                return fd
            with patch.object(installer, "_open_install_directory_fd", side_effect=swapped):
                installer.atomic_install(stage / "unit", b"unit", 0o644)
            self.assertEqual((original / "unit").read_bytes(), b"unit")
            self.assertEqual(list(outside.iterdir()), [])



if __name__ == "__main__":
    unittest.main()
