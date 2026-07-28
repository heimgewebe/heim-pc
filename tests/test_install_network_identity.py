from __future__ import annotations

import importlib.util
import json
import os
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
                backup_anchor=root,
                policy_data=self.policy_data,
                apply=True,
            )
            self.assertEqual(receipt["action"], "installed")
            self.assertEqual(target.stat().st_mode & 0o777, 0o644)
            backup = Path(receipt["backup"]["path"])
            self.assertEqual(backup.read_bytes(), before)
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            self.assertIn(b"127.0.1.1\theim-pc", target.read_bytes())

            target.write_bytes(before)
            retry = installer.apply_policy(
                target=target,
                backup_root=backup_root,
                backup_anchor=root,
                policy_data=self.policy_data,
                apply=True,
            )
            self.assertEqual(retry["action"], "installed")
            self.assertEqual(retry["backup"]["path"], str(backup))

            replay = installer.apply_policy(
                target=target,
                backup_root=backup_root,
                backup_anchor=root,
                policy_data=self.policy_data,
                apply=True,
            )
            self.assertEqual(replay["action"], "unchanged")
            self.assertIsNone(replay["backup"])

    def test_backup_directory_chain_is_durable_before_target_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "hosts"
            before = b"127.0.0.1 localhost\n"
            target.write_bytes(before)
            level_one = root / "state"
            level_two = level_one / "network-identity"
            backup_root = level_two / "backups"
            events: list[tuple[str, Path]] = []
            original_atomic_install = installer.atomic_install
            original_ensure_backup = installer._ensure_preimage_backup

            def record_fsync(path: Path) -> None:
                events.append(("fsync", path))

            def record_ensure_backup(path: Path, data: bytes) -> None:
                events.append(("backup", path))
                original_ensure_backup(path, data)

            def record_atomic_install(path: Path, data: bytes, **kwargs: object) -> None:
                events.append(("install", path))
                original_atomic_install(path, data, **kwargs)

            with (
                mock.patch.object(installer, "_fsync_directory", side_effect=record_fsync),
                mock.patch.object(
                    installer,
                    "_ensure_preimage_backup",
                    side_effect=record_ensure_backup,
                ),
                mock.patch.object(installer, "atomic_install", side_effect=record_atomic_install),
            ):
                installer.apply_policy(
                    target=target,
                    backup_root=backup_root,
                    backup_anchor=root,
                    policy_data=self.policy_data,
                    apply=True,
                )

            expected_backup = backup_root / f"hosts-{installer.sha256(before)}.txt"
            install_index = events.index(("install", target))
            self.assertEqual(
                events[:install_index],
                [
                    ("fsync", root),
                    ("fsync", level_one),
                    ("fsync", level_two),
                    ("backup", expected_backup),
                    ("fsync", backup_root),
                ],
            )

    def test_retry_fsyncs_existing_backup_ancestry_at_every_interruption_depth(self) -> None:
        for existing_depth in (1, 2, 3):
            with self.subTest(existing_depth=existing_depth), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target = root / "hosts"
                target.write_text("127.0.0.1 localhost\n", encoding="utf-8")
                ancestry = [
                    root / "state",
                    root / "state" / "network-identity",
                    root / "state" / "network-identity" / "backups",
                ]
                for directory in ancestry[:existing_depth]:
                    directory.mkdir(mode=0o700)
                backup_root = ancestry[-1]
                events: list[tuple[str, Path]] = []
                original_ensure_backup = installer._ensure_preimage_backup
                original_atomic_install = installer.atomic_install

                def record_fsync(path: Path) -> None:
                    events.append(("fsync", path))

                def record_ensure_backup(path: Path, data: bytes) -> None:
                    events.append(("backup", path))
                    original_ensure_backup(path, data)

                def record_atomic_install(path: Path, data: bytes, **kwargs: object) -> None:
                    events.append(("install", path))
                    original_atomic_install(path, data, **kwargs)

                with (
                    mock.patch.object(installer, "_fsync_directory", side_effect=record_fsync),
                    mock.patch.object(
                        installer,
                        "_ensure_preimage_backup",
                        side_effect=record_ensure_backup,
                    ),
                    mock.patch.object(
                        installer,
                        "atomic_install",
                        side_effect=record_atomic_install,
                    ),
                ):
                    installer.apply_policy(
                        target=target,
                        backup_root=backup_root,
                        backup_anchor=root,
                        policy_data=self.policy_data,
                        apply=True,
                    )

                backup_index = next(
                    index for index, event in enumerate(events) if event[0] == "backup"
                )
                install_index = events.index(("install", target))
                self.assertEqual(
                    events[:backup_index],
                    [
                        ("fsync", root),
                        ("fsync", ancestry[0]),
                        ("fsync", ancestry[1]),
                    ],
                )
                self.assertEqual(events[backup_index + 1], ("fsync", backup_root))
                self.assertLess(backup_index, install_index)

    def test_backup_ancestry_rejects_untrusted_owner_mode_and_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "hosts"
            target.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o700)
            unsafe.chmod(0o777)

            with self.assertRaisesRegex(installer.InstallError, "group- or other-writable"):
                installer.apply_policy(
                    target=target,
                    backup_root=unsafe / "backups",
                    backup_anchor=root,
                    policy_data=self.policy_data,
                    apply=True,
                )

            with (
                mock.patch.object(installer.os, "geteuid", return_value=os.geteuid() + 1),
                self.assertRaisesRegex(installer.InstallError, "unexpected owner"),
            ):
                installer.apply_policy(
                    target=target,
                    backup_root=root / "owned" / "backups",
                    backup_anchor=root,
                    policy_data=self.policy_data,
                    apply=True,
                )

            with tempfile.TemporaryDirectory() as outside:
                with self.assertRaisesRegex(installer.InstallError, "below durable anchor"):
                    installer.apply_policy(
                        target=target,
                        backup_root=Path(outside) / "backups",
                        backup_anchor=root,
                        policy_data=self.policy_data,
                        apply=True,
                    )

            symlink = root / "symlink"
            symlink.symlink_to(root / "unsafe")
            with self.assertRaisesRegex(installer.InstallError, "path is unsafe"):
                installer.apply_policy(
                    target=target,
                    backup_root=symlink / "backups",
                    backup_anchor=root,
                    policy_data=self.policy_data,
                    apply=True,
                )

            with self.assertRaisesRegex(installer.InstallError, "filesystem root"):
                installer.apply_policy(
                    target=target,
                    backup_root=root / "root-anchored" / "backups",
                    backup_anchor=Path("/"),
                    policy_data=self.policy_data,
                    apply=True,
                )

            self.assertEqual(target.read_text(encoding="utf-8"), "127.0.0.1 localhost\n")

    def test_plan_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "hosts"
            target.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            before = target.read_bytes()
            receipt = installer.apply_policy(
                target=target,
                backup_root=root / "backups",
                backup_anchor=root,
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
                    backup_anchor=root,
                    policy_data=self.policy_data,
                    apply=True,
                )
            self.assertEqual(real.read_text(encoding="utf-8"), "127.0.0.1 localhost\n")


if __name__ == "__main__":
    unittest.main()
