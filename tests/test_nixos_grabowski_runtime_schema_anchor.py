"""Root-controlled NixOS contract schema anchor: deterministic positive and negative cases."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import runpy
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SCRIPT = ROOT / "nixos/system/modules/grabowski-runtime-schema-install.py"
anchor = SimpleNamespace(**runpy.run_path(str(SOURCE_SCRIPT), run_name="anchor_test"))
CANONICAL = b"CANONICAL_VALIDATOR_MODULE = 'grabowski_runtime_contract'\n"


class RuntimeSchemaAnchorTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.boundary = Path(temp.name)
        self.boundary.chmod(0o700)
        self.uid = os.getuid()
        self.store = self.boundary / "nix" / "store"
        self.source = (
            self.store / (("a" * 32) + "-grabowski-operator-89eafe9c")
            / "lib" / "python3.12" / "site-packages"
            / "grabowski_runtime_contract.py"
        )
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(CANONICAL)
        self.source.chmod(0o444)
        self.destination = (
            self.boundary / "etc" / "grabowski" / "runtime-contract-schema.py"
        )
        self.destination.parent.mkdir(parents=True)
        self.destination.parent.chmod(0o755)

    def install(self, source: Path | None = None) -> str:
        return anchor.install(
            self.source if source is None else source,
            self.destination,
            authority_uid=self.uid,
            store_root=self.store,
            trusted_boundary=self.boundary,
        )

    def test_root_owned_regular_single_link_is_atomically_installed(self) -> None:
        digest = self.install()
        self.assertEqual(digest, hashlib.sha256(CANONICAL).hexdigest())
        self.assertEqual(self.destination.read_bytes(), CANONICAL)
        info = self.destination.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(info.st_uid, self.uid)
        self.assertEqual(info.st_nlink, 1)
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o644)
        self.assertEqual(self.install(), digest)

    def test_source_symlink_is_denied_before_creating_anchor(self) -> None:
        self.source.unlink()
        self.source.symlink_to("/etc/hosts")
        with self.assertRaises(OSError):
            self.install()
        self.assertFalse(self.destination.exists())

    def test_nix_deduplicated_store_source_hardlinks_are_admitted(self) -> None:
        # Nix store optimisation may hardlink identical immutable files to
        # /nix/store/.links/. Only the installed /etc anchor must be single-link.
        links = self.store / ".links"
        links.mkdir(mode=0o755)
        os.link(self.source, links / "deduplicated-schema")
        self.assertEqual(self.source.stat().st_nlink, 2)
        digest = self.install()
        self.assertEqual(digest, hashlib.sha256(CANONICAL).hexdigest())
        self.assertEqual(self.destination.read_bytes(), CANONICAL)
        self.assertEqual(self.destination.stat().st_nlink, 1)
        self.assertEqual(self.install(), digest)

    def test_source_writable_by_others_is_denied(self) -> None:
        self.source.chmod(0o666)
        with self.assertRaises(PermissionError):
            self.install()
        self.assertFalse(self.destination.exists())

    def test_root_owned_ancestor_cannot_be_group_or_world_writable(self) -> None:
        self.store.chmod(0o777)
        with self.assertRaises(PermissionError):
            self.install()
        self.assertFalse(self.destination.exists())

    def test_nixos_root_nixbld_sticky_store_is_admitted(self) -> None:
        # Synthetic test runs as the ordinary test UID; model the host's
        # root:nixbld 01775 exception without changing real root metadata.
        self.store.chmod(0o1775)
        allowed_gid = self.store.stat().st_gid
        with mock.patch.object(
            anchor.grp, "getgrnam",
            return_value=SimpleNamespace(gr_gid=allowed_gid),
        ) as lookup:
            self.assertEqual(
                self.install(), hashlib.sha256(CANONICAL).hexdigest()
            )
        lookup.assert_called_once_with("nixbld")
        self.assertEqual(self.destination.read_bytes(), CANONICAL)

    def test_sticky_store_with_untrusted_group_is_denied(self) -> None:
        self.store.chmod(0o1775)
        with mock.patch.object(
            anchor.grp, "getgrnam",
            return_value=SimpleNamespace(gr_gid=self.store.stat().st_gid + 1),
        ):
            with self.assertRaises(PermissionError):
                self.install()
        self.assertFalse(self.destination.exists())

    def test_store_without_sticky_bit_cannot_use_group_exception(self) -> None:
        self.store.chmod(0o775)
        with mock.patch.object(
            anchor.grp, "getgrnam",
            return_value=SimpleNamespace(gr_gid=self.store.stat().st_gid),
        ):
            with self.assertRaises(PermissionError):
                self.install()
        self.assertFalse(self.destination.exists())

    def test_sticky_store_world_writable_remains_denied(self) -> None:
        self.store.chmod(0o1777)
        with mock.patch.object(
            anchor.grp, "getgrnam",
            return_value=SimpleNamespace(gr_gid=self.store.stat().st_gid),
        ):
            with self.assertRaises(PermissionError):
                self.install()
        self.assertFalse(self.destination.exists())

    def test_group_writable_package_dir_is_denied_inside_sticky_store(self) -> None:
        self.store.chmod(0o1775)
        self.source.parent.chmod(0o775)
        with mock.patch.object(
            anchor.grp, "getgrnam",
            return_value=SimpleNamespace(gr_gid=self.store.stat().st_gid),
        ):
            with self.assertRaises(PermissionError):
                self.install()
        self.assertFalse(self.destination.exists())

    def test_source_must_be_in_expected_nix_package_slot(self) -> None:
        wrong = self.store / "untrusted-package" / "lib/python3.12/site-packages"
        wrong.mkdir(parents=True)
        alternative = wrong / self.source.name
        alternative.write_bytes(CANONICAL)
        alternative.chmod(0o444)
        with self.assertRaises(PermissionError):
            self.install(alternative)

    def test_destination_symlink_is_rejected_without_following(self) -> None:
        self.destination.symlink_to(self.source)
        with self.assertRaises(PermissionError):
            self.install()
        self.assertEqual(self.source.read_bytes(), CANONICAL)

    def test_destination_hardlink_is_rejected_without_replacement(self) -> None:
        self.install()
        linked = self.destination.parent / "unexpected-link"
        os.link(self.destination, linked)
        with self.assertRaises(PermissionError):
            self.install()
        self.assertEqual(linked.read_bytes(), CANONICAL)

    def test_unsafe_existing_file_is_never_replaced(self) -> None:
        self.install()
        self.destination.chmod(0o666)
        with self.assertRaises(PermissionError):
            self.install()
        self.assertEqual(self.destination.read_bytes(), CANONICAL)

    def test_destination_directory_must_remain_searchable_mode_0755(self) -> None:
        self.destination.parent.chmod(0o750)
        with self.assertRaises(PermissionError):
            self.install()
        self.assertFalse(self.destination.exists())

    def test_oversize_pinned_input_is_denied(self) -> None:
        self.source.chmod(0o644)
        self.source.write_bytes(b"x" * (anchor.MAX_BYTES + 1))
        self.source.chmod(0o444)
        with self.assertRaises(PermissionError):
            self.install()
        self.assertFalse(self.destination.exists())

    def test_existing_anchor_replaced_during_staging_is_not_overwritten(self) -> None:
        self.install()
        replacement = b"new-root-owned-schema-from-concurrent-authority"
        mkstemp = anchor.tempfile.mkstemp

        def switch_existing_anchor(*args, **kwargs):
            self.destination.unlink()
            self.destination.write_bytes(replacement)
            self.destination.chmod(0o644)
            return mkstemp(*args, **kwargs)

        with mock.patch.object(anchor.tempfile, "mkstemp", side_effect=switch_existing_anchor):
            with self.assertRaisesRegex(PermissionError, "changed"):
                self.install()
        self.assertEqual(self.destination.read_bytes(), replacement)

    def test_new_anchor_appearing_during_staging_is_not_overwritten(self) -> None:
        replacement = b"new-root-owned-anchor-created-in-parallel"
        mkstemp = anchor.tempfile.mkstemp

        def create_competing_anchor(*args, **kwargs):
            self.destination.write_bytes(replacement)
            self.destination.chmod(0o644)
            return mkstemp(*args, **kwargs)

        with mock.patch.object(anchor.tempfile, "mkstemp", side_effect=create_competing_anchor):
            with self.assertRaisesRegex(PermissionError, "appeared"):
                self.install()
        self.assertEqual(self.destination.read_bytes(), replacement)

    def test_nixos_operator_requires_validated_root_anchor(self) -> None:
        module = (ROOT / "nixos/system/modules/grabowski-production.nix").read_text()
        self.assertIn(
            "systemd.services.grabowski-runtime-schema-install = lib.mkIf admit",
            module,
        )
        self.assertIn(
            "grabowski-runtime-schema-install.service",
            module,
        )
        self.assertIn(
            "${cfg.operatorPackage}/lib/python3.12/site-packages/grabowski_runtime_contract.py",
            module,
        )
        self.assertIn("ConfigurationDirectoryMode = \"0755\";", module)
        self.assertIn("ProtectSystem = \"strict\";", module)
        self.assertIn('NoNewPrivileges = true;', module)
        self.assertNotIn(
            'environment.etc."grabowski/runtime-contract-schema.py"',
            module,
        )
        self.assertIn('CacheDirectory = "grabowski-xdg";', module)
        # The fixed root-owned Restic probe must not resurrect a setuid
        # escalation path inside the unprivileged Grabowski operator.
        self.assertNotIn("NoNewPrivileges = false;", module)


if __name__ == "__main__":
    unittest.main()