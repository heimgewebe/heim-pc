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
    "install_worktree_target_maintenance",
    ROOT / "scripts" / "install_worktree_target_maintenance.py",
)
assert SPEC and SPEC.loader
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallWorktreeTargetMaintenanceTests(unittest.TestCase):
    def test_install_renders_commit_bound_release_and_units(self) -> None:
        head = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            home = base / "home"
            release_root = base / "releases"

            def fake_run(argv: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
                if (
                    argv[:3] == ["systemctl", "--user", "show"]
                    and "--property=LoadState" in argv
                ):
                    return subprocess.CompletedProcess(argv, 0, "loaded\n", "")
                return subprocess.CompletedProcess(argv, 0, "", "")

            policy = json.loads(installer.POLICY_SOURCE.read_text(encoding="utf-8"))
            policy["quarantine_root"] = str(home / "repos/.worktree-target-quarantine")
            blobs = {
                "scripts/worktree_target_maintenance.py": installer.SCRIPT_SOURCE.read_bytes(),
                "config/worktree-target-policy.v1.json": (json.dumps(policy) + "\n").encode("utf-8"),
                "systemd/user/heim-pc-worktree-target-maintenance.service.in": installer.SERVICE_TEMPLATE.read_bytes(),
                "systemd/user/heim-pc-worktree-target-maintenance.timer": installer.TIMER_SOURCE.read_bytes(),
            }
            with (
                patch.object(installer, "repository_identity", return_value=(head, False)),
                patch.object(installer, "repository_blob", side_effect=lambda _root, *, head, relative_path: blobs[relative_path]),
                patch.object(installer, "run", side_effect=fake_run),
                patch.object(
                    installer, "verify_unit_files",
                    return_value={"status": "verified", "returncode": 0},
                ),
            ):
                receipt = installer.install(
                    home=home,
                    release_root=release_root,
                    apply=True,
                    enable=True,
                    start=False,
                    expected_head=head,
                )

            release = release_root / head
            self.assertEqual(receipt["repository_head"], head)
            self.assertEqual(receipt["systemd"], "timer-enabled")
            self.assertTrue((release / "scripts/worktree_target_maintenance.py").is_file())
            self.assertTrue((release / "config/worktree-target-policy.v1.json").is_file())
            service = (home / ".config/systemd/user/heim-pc-worktree-target-maintenance.service").read_text()
            self.assertIn(str(release), service)
            self.assertNotIn("@RELEASE_ROOT@", service)
            self.assertIn("ProtectHome=read-only", service)
            self.assertIn("NoNewPrivileges=true", service)
            self.assertNotIn("PrivateDevices=true", service)
            self.assertNotIn("ProtectKernelModules=true", service)
            for directive in (
                "PrivateTmp=true",
                "ProtectSystem=strict",
                "ProtectKernelTunables=true",
                "ProtectControlGroups=true",
                "RestrictRealtime=true",
                "RestrictSUIDSGID=true",
                "LockPersonality=true",
            ):
                self.assertIn(directive, service)
            self.assertNotIn("@HOME@", service)
            self.assertNotIn("@READ_WRITE_PATHS@", service)
            self.assertIn(
                f"ConditionFileIsExecutable={home}/.local/share/grabowski-mcp/.venv/bin/python",
                service,
            )
            self.assertIn(
                f"ReadWritePaths=-{home}/.local/state/heim-pc/worktree-target-maintenance",
                service,
            )
            self.assertIn(
                f"ReadWritePaths=-{home}/repos/.worktree-target-quarantine",
                service,
            )
            for repository in policy["repositories"]:
                for root in repository["worktree_roots"]:
                    self.assertIn(f"ReadWritePaths=-{root}", service)
            timer = (home / ".config/systemd/user/heim-pc-worktree-target-maintenance.timer").read_text()
            self.assertIn("OnCalendar=*-*-* 04:00:00", timer)
            self.assertIn("RandomizedDelaySec=30min", timer)
            self.assertTrue((home / ".local/state/heim-pc/worktree-target-maintenance").is_dir())

    def test_verify_unit_files_accepts_exact_known_host_crash(self) -> None:
        service = Path("/tmp/example.service")
        timer = Path("/tmp/example.timer")
        stderr = (
            "Failed to allocate device monitor: unsupported\n"
            "Assertion '*_head == _item' failed at src/core/device.c:51\n"
        )
        completed = subprocess.CompletedProcess(
            ["systemd-analyze"], -installer.signal.SIGABRT, "", stderr
        )
        with patch.object(installer.subprocess, "run", return_value=completed):
            result = installer.verify_unit_files(service, timer)
        self.assertEqual(result["status"], "host-verifier-unavailable")

    def test_verify_unit_files_rejects_target_diagnostics_even_on_known_host_crash(self) -> None:
        service = Path("/tmp/example.service")
        timer = Path("/tmp/example.timer")
        stderr = (
            "Failed to allocate device monitor: unsupported\n"
            f"{service}:4: Unknown key name 'BrokenKey' in section 'Unit'\n"
            "Assertion '*_head == _item' failed at src/core/device.c:51\n"
        )
        completed = subprocess.CompletedProcess(
            ["systemd-analyze"], -installer.signal.SIGABRT, "", stderr
        )
        with patch.object(installer.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(installer.InstallError, "target diagnostics"):
                installer.verify_unit_files(service, timer)

    def test_systemd_path_rejects_unsafe_unit_syntax(self) -> None:
        for path in (Path("/home/alex/bad path"), Path("/home/%u/runtime"), Path('/home/alex/"bad"')):
            with self.subTest(path=path):
                with self.assertRaisesRegex(installer.InstallError, "safe absolute systemd path"):
                    installer.systemd_path(path, label="test")

    def test_dirty_repository_is_rejected_before_install(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            with patch.object(installer, "repository_identity", return_value=("b" * 40, True)):
                with self.assertRaisesRegex(installer.InstallError, "clean"):
                    installer.install(
                        home=base / "home",
                        release_root=base / "releases",
                        apply=True,
                        enable=False,
                        start=False,
                    )


if __name__ == "__main__":
    unittest.main()
