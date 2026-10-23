"""Root-only broker policy provisioning: strict atomic admission and negatives."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "nixos/system/modules/grabowski-private-policy-install.py"
policy = SimpleNamespace(**runpy.run_path(str(SCRIPT), run_name="policy_test"))

BENIGN = b'{"schema_version":2,"actions":{}}\n'


class PrivateBrokerPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.boundary = Path(self.temp.name)
        self.boundary.chmod(0o700)
        self.uid = os.getuid()
        self.secret_parent = self.boundary / "persist"
        self.secret_parent.mkdir(mode=0o700)
        secret_dir = self.secret_parent / "secrets"
        secret_dir.mkdir(mode=0o700)
        self.source_root = secret_dir / "grabowski"
        self.source_root.mkdir(mode=0o700)
        self.source = self.source_root / "privileged-actions.json"
        self.source.write_bytes(BENIGN)
        self.source.chmod(0o600)
        self.etc = self.boundary / "etc"
        self.etc.mkdir(mode=0o700)
        self.dest_dir = self.etc / "grabowski"
        self.dest_dir.mkdir(mode=0o755)
        # The test process may have a restrictive umask, while systemd applies
        # ConfigurationDirectoryMode explicitly at service startup.
        self.dest_dir.chmod(0o755)
        self.destination = self.dest_dir / "privileged-actions.json"

    def install(self):
        return policy.install(
            self.source,
            self.destination,
            authority_uid=self.uid,
            source_root=self.source_root,
            trusted_boundary=self.boundary,
        )

    def test_private_root_file_is_installed_atomically_and_exact(self):
        digest = self.install()
        self.assertEqual(digest, hashlib.sha256(BENIGN).hexdigest())
        self.assertEqual(self.destination.read_bytes(), BENIGN)
        meta = self.destination.lstat()
        self.assertTrue(stat.S_ISREG(meta.st_mode))
        self.assertEqual(meta.st_uid, self.uid)
        self.assertEqual(stat.S_IMODE(meta.st_mode), 0o600)
        self.assertEqual(self.install(), digest)

    def test_invalid_policy_does_not_replace_previous_safe_target(self):
        self.install()
        previous = self.destination.read_bytes()
        self.source.write_text('{"schema_version":2,"actions":{"unsafe":null}}')
        self.source.chmod(0o600)
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(self.destination.read_bytes(), previous)
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o600)

    def test_hardlinked_destination_is_denied_without_replacement(self):
        self.install()
        previous = self.destination.read_bytes()
        linked = self.dest_dir / "unexpected-hardlink"
        os.link(self.destination, linked)
        self.source.write_bytes(b'{"schema_version":2,"actions":{"allowed":{"enabled":false}}}\n')
        self.source.chmod(0o600)
        with self.assertRaises(PermissionError):
            self.install()
        self.assertEqual(self.destination.read_bytes(), previous)
        self.assertEqual(linked.read_bytes(), previous)

    def test_missing_source_is_denied_without_creating_target(self):
        self.source.unlink()
        with self.assertRaises(FileNotFoundError):
            self.install()
        self.assertFalse(self.destination.exists())

    def test_symlink_source_is_denied(self):
        self.source.unlink()
        self.source.symlink_to("/etc/hosts")
        with self.assertRaises(OSError):
            self.install()
        self.assertFalse(self.destination.exists())

    def test_source_must_be_private_regular_single_link(self):
        self.source.chmod(0o644)
        with self.assertRaises(PermissionError):
            self.install()
        self.source.chmod(0o600)
        second = self.source_root / "hardlink"
        os.link(self.source, second)
        with self.assertRaises(PermissionError):
            self.install()

    def test_group_or_world_writable_ancestor_is_denied(self):
        self.secret_parent.chmod(0o777)
        with self.assertRaises(PermissionError):
            self.install()
        self.secret_parent.chmod(0o700)
        self.source_root.chmod(0o770)
        with self.assertRaises(PermissionError):
            self.install()

    def test_source_directory_private_and_dest_directory_searchable(self):
        self.source_root.chmod(0o750)
        with self.assertRaises(PermissionError):
            self.install()
        self.source_root.chmod(0o700)
        self.dest_dir.chmod(0o750)
        with self.assertRaises(PermissionError):
            self.install()

    def test_mismatching_source_or_trusted_boundary_is_denied(self):
        candidate = self.source_root / "alternate.json"
        candidate.write_bytes(BENIGN)
        candidate.chmod(0o600)
        with self.assertRaises(PermissionError):
            policy.install(
                candidate, self.destination, authority_uid=self.uid,
                source_root=self.source_root, trusted_boundary=self.boundary,
            )
        with self.assertRaises(PermissionError):
            policy.install(
                self.source, self.destination, authority_uid=self.uid,
                source_root=self.source_root,
                trusted_boundary=self.boundary / "unrelated",
            )

    def test_destination_must_be_regular_nonsymlink_0600(self):
        self.destination.symlink_to("/etc/hosts")
        with self.assertRaises(PermissionError):
            self.install()
        self.destination.unlink()
        self.destination.write_bytes(BENIGN)
        self.destination.chmod(0o644)
        with self.assertRaises(PermissionError):
            self.install()
        self.assertEqual(self.destination.read_bytes(), BENIGN)

    def test_unsupported_or_malformed_policies_are_denied(self):
        for document in (
            {"schema_version": 1, "actions": {}},
            {"schema_version": 2},
            {"schema_version": 2, "actions": []},
            {"schema_version": 2, "actions": {}, "extra": True},
            {"schema_version": 2, "actions": {"any": None}},
            {"schema_version": 2, "actions": {"": {}}},
        ):
            with self.subTest(document=document):
                self.source.write_text(json.dumps(document))
                self.source.chmod(0o600)
                with self.assertRaises(ValueError):
                    self.install()
                self.assertFalse(self.destination.exists())

    def test_oversized_policy_is_denied(self):
        self.source.write_bytes(BENIGN + b" " * (policy.MAX_BYTES + 1))
        self.source.chmod(0o600)
        with self.assertRaises(PermissionError):
            self.install()


if __name__ == "__main__":
    unittest.main()