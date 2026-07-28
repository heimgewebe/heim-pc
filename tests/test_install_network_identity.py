from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "install_network_identity",
    ROOT / "scripts" / "install_network_identity.py",
)
assert SPEC and SPEC.loader
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallNetworkIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy_data = (ROOT / "config/network-identity.v1.json").read_bytes()
        self.policy = installer.network_policy(self.policy_data)

    def test_policy_is_bounded_to_loopback_hostname_identity(self) -> None:
        self.assertEqual(self.policy["hostname"], "heim-pc")
        self.assertEqual(self.policy["hosts_address"], "127.0.1.1")
        invalid = json.dumps(
            {
                "schema_version": 1,
                "kind": "heim_pc_network_identity_policy",
                "hostname": "heim-pc",
                "hosts_address": "192.168.178.55",
                "expected_default_interface": "enp6s0",
                "minimum_link_speed_mbps": 1000,
            }
        ).encode()
        with self.assertRaisesRegex(installer.InstallError, "loopback"):
            installer.network_policy(invalid)

    def test_merge_appends_managed_block_and_preserves_unrelated_entries(self) -> None:
        before = b"127.0.0.1\tlocalhost\n::1\tlocalhost\n192.168.178.55 leitstand.example\n"
        after = installer.merge_hosts(before, hostname="heim-pc", address="127.0.1.1")
        text = after.decode()
        self.assertIn("192.168.178.55 leitstand.example", text)
        self.assertIn(installer.BEGIN_MARKER, text)
        self.assertIn("127.0.1.1\theim-pc", text)
        self.assertTrue(text.endswith(installer.END_MARKER + "\n"))

    def test_merge_is_idempotent_for_managed_block(self) -> None:
        before = b"127.0.0.1 localhost\n\n# BEGIN heim-pc network identity v1\n127.0.1.1\theim-pc\n# END heim-pc network identity v1\n"
        after = installer.merge_hosts(before, hostname="heim-pc", address="127.0.1.1")
        self.assertEqual(after, before)

    def test_conflicting_or_unmanaged_hostname_mapping_fails_closed(self) -> None:
        with self.assertRaisesRegex(installer.InstallError, "conflicting unmanaged"):
            installer.merge_hosts(
                b"127.0.0.1 localhost\n192.168.178.55 heim-pc\n",
                hostname="heim-pc",
                address="127.0.1.1",
            )
        with self.assertRaisesRegex(installer.InstallError, "unmanaged mapping"):
            installer.merge_hosts(
                b"127.0.0.1 localhost\n127.0.1.1 heim-pc\n",
                hostname="heim-pc",
                address="127.0.1.1",
            )

    def test_malformed_managed_markers_fail_closed(self) -> None:
        with self.assertRaisesRegex(installer.InstallError, "markers are malformed"):
            installer.merge_hosts(
                b"127.0.0.1 localhost\n# BEGIN heim-pc network identity v1\n",
                hostname="heim-pc",
                address="127.0.1.1",
            )

    def test_apply_is_backup_bound_atomic_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "hosts"
            before = b"127.0.0.1 localhost\n::1 localhost\n"
            target.write_bytes(before)
            backup_root = root / "backups"
            receipt = installer.apply_policy(
                target=target,
                backup_root=backup_root,
                policy_data=self.policy_data,
                apply=True,
            )
            self.assertEqual(receipt["action"], "installed")
            self.assertEqual(target.stat().st_mode & 0o777, 0o644)
            backup = Path(receipt["backup"]["path"])
            self.assertEqual(backup.read_bytes(), before)
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            self.assertIn(b"127.0.1.1\theim-pc", target.read_bytes())

            replay = installer.apply_policy(
                target=target,
                backup_root=backup_root,
                policy_data=self.policy_data,
                apply=True,
            )
            self.assertEqual(replay["action"], "unchanged")
            self.assertIsNone(replay["backup"])

    def test_backup_directory_is_fsynced_before_target_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "hosts"
            target.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            backup_root = root / "backups"
            events: list[tuple[str, Path]] = []
            original_atomic_install = installer.atomic_install

            def record_fsync(path: Path) -> None:
                events.append(("fsync", path))

            def record_atomic_install(path: Path, data: bytes, **kwargs: object) -> None:
                events.append(("install", path))
                original_atomic_install(path, data, **kwargs)

            with (
                mock.patch.object(installer, "_fsync_directory", side_effect=record_fsync),
                mock.patch.object(installer, "atomic_install", side_effect=record_atomic_install),
            ):
                installer.apply_policy(
                    target=target,
                    backup_root=backup_root,
                    policy_data=self.policy_data,
                    apply=True,
                )

            self.assertEqual(events[0], ("fsync", backup_root))
            self.assertEqual(events[1], ("install", target))

    def test_plan_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "hosts"
            target.write_text("127.0.0.1 localhost\n", encoding="utf-8")
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

    def test_symlink_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real-hosts"
            real.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            target = root / "hosts"
            target.symlink_to(real)
            with self.assertRaisesRegex(installer.InstallError, "symlink"):
                installer.apply_policy(
                    target=target,
                    backup_root=root / "backups",
                    policy_data=self.policy_data,
                    apply=True,
                )
            self.assertEqual(real.read_text(encoding="utf-8"), "127.0.0.1 localhost\n")


if __name__ == "__main__":
    unittest.main()
