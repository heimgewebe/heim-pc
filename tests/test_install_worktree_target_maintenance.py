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
            self.assertNotIn("@HOME@", service)
            self.assertNotIn("@READ_WRITE_PATHS@", service)
            self.assertIn(
                f"ConditionPathIsExecutable={home}/.local/share/grabowski-mcp/.venv/bin/python",
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
            self.assertTrue((home / ".local/state/heim-pc/worktree-target-maintenance").is_dir())

    def test_systemd_path_rejects_whitespace(self) -> None:
        with self.assertRaisesRegex(installer.InstallError, "safe absolute systemd path"):
            installer.systemd_path(Path("/home/alex/bad path"), label="test")

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
