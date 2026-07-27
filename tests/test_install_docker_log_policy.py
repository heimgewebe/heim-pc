from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "install_docker_log_policy",
    ROOT / "scripts" / "install_docker_log_policy.py",
)
assert SPEC and SPEC.loader
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallDockerLogPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy_data = (ROOT / "config/runaway-guard.v1.json").read_bytes()
        self.desired = installer.docker_policy(self.policy_data)

    def test_merge_preserves_unrelated_daemon_configuration(self) -> None:
        existing = {
            "runtimes": {
                "nvidia": {
                    "args": [],
                    "path": "nvidia-container-runtime",
                }
            },
            "features": {"buildkit": True},
        }
        merged = installer.merge_daemon_config(existing, self.desired)
        self.assertEqual(merged["runtimes"], existing["runtimes"])
        self.assertEqual(merged["features"], existing["features"])
        self.assertEqual(merged["log-driver"], "local")
        self.assertEqual(merged["log-opts"], {"max-size": "50m", "max-file": "3"})
        self.assertNotIn("log-driver", existing)

    def test_conflicting_existing_logging_policy_fails_closed(self) -> None:
        with self.assertRaisesRegex(installer.InstallError, "conflicts"):
            installer.merge_daemon_config(
                {"log-driver": "json-file"},
                self.desired,
            )
        with self.assertRaisesRegex(installer.InstallError, "max-size"):
            installer.merge_daemon_config(
                {"log-driver": "local", "log-opts": {"max-size": "1g"}},
                self.desired,
            )

    def test_apply_is_atomic_backup_bound_and_idempotent(self) -> None:
        existing = {
            "runtimes": {
                "nvidia": {
                    "args": [],
                    "path": "nvidia-container-runtime",
                }
            }
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "etc/docker/daemon.json"
            target.parent.mkdir(parents=True)
            before = (json.dumps(existing, indent=2) + "\n").encode("utf-8")
            target.write_bytes(before)
            backup_root = root / "backups"
            receipt = installer.apply_policy(
                target=target,
                backup_root=backup_root,
                policy_data=self.policy_data,
                apply=True,
            )
            self.assertEqual(receipt["action"], "installed")
            self.assertTrue(receipt["restart_required"])
            self.assertIsNotNone(receipt["backup"])
            backup_path = Path(receipt["backup"]["path"])
            self.assertEqual(backup_path.read_bytes(), before)
            installed = json.loads(target.read_text())
            self.assertEqual(installed["runtimes"], existing["runtimes"])
            self.assertEqual(installed["log-driver"], "local")
            self.assertEqual(installed["log-opts"], {"max-file": "3", "max-size": "50m"})

            replay = installer.apply_policy(
                target=target,
                backup_root=backup_root,
                policy_data=self.policy_data,
                apply=True,
            )
            self.assertEqual(replay["action"], "unchanged")
            self.assertFalse(replay["restart_required"])
            self.assertIsNone(replay["backup"])

    def test_plan_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "daemon.json"
            target.write_text("{}\n")
            before = target.read_bytes()
            receipt = installer.apply_policy(
                target=target,
                backup_root=root / "backups",
                policy_data=self.policy_data,
                apply=False,
            )
            self.assertEqual(receipt["action"], "planned")
            self.assertEqual(target.read_bytes(), before)
            self.assertFalse((root / "backups").exists())

    def test_atomic_install_rejects_changed_preimage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "daemon.json"
            target.write_bytes(b"current")
            with self.assertRaisesRegex(installer.InstallError, "preimage changed"):
                installer.atomic_install(
                    target,
                    b"replacement",
                    mode=0o644,
                    expected_current=b"expected-old",
                )
            self.assertEqual(target.read_bytes(), b"current")

    def test_symlink_target_is_rejected_before_read_or_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real.json"
            real.write_text("{}\n")
            target = root / "daemon.json"
            target.symlink_to(real)
            with self.assertRaisesRegex(installer.InstallError, "symlink"):
                installer.apply_policy(
                    target=target,
                    backup_root=root / "backups",
                    policy_data=self.policy_data,
                    apply=True,
                )
            self.assertEqual(real.read_text(), "{}\n")


if __name__ == "__main__":
    unittest.main()
