"""Offline negative tests of NixOS Rootbroker unit and executable trust."""
import os
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
AUTH = ROOT / "nixos/system/modules/grabowski-nixos-unit-authority.py"
# run_path does not create __pycache__ inside the immutable Nix flake source.
authority = SimpleNamespace(**runpy.run_path(str(AUTH), run_name="nixos_authority_test"))


class TestNixOSRootbrokerAuthority(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.store = root / "nix" / "store"
        self.store.mkdir(parents=True, mode=0o700)
        self.store.parent.chmod(0o700)
        self.store.chmod(0o700)
        # A real NixOS VM resolves the unit inside a root-owned Store output.
        self.unit_dir = self.store / ("a" * 32 + "-unit-grabowski-operator.service")
        self.unit_dir.mkdir(mode=0o700)
        self.unit_file = self.unit_dir / "grabowski-operator.service"
        self.unit_file.write_text("[Service]\nExecStart=/nix/store/pinned\n")
        self.unit_file.chmod(0o444)
        self.etc = root / "etc"
        self.systemd = self.etc / "systemd"
        self.sysunits = self.systemd / "system"
        self.sysunits.mkdir(parents=True, mode=0o700)
        self.etc.chmod(0o700)
        self.systemd.chmod(0o700)
        self.sysunits.chmod(0o700)
        self.fragment = self.sysunits / "grabowski-operator.service"
        self.fragment.symlink_to(self.unit_file)
        self.uid = os.getuid()
        self.operator_pkg = self.store / ("b" * 32 + "-grabowski-operator-a1d443a1")
        (self.operator_pkg / "bin").mkdir(parents=True, mode=0o700)
        self.entry = self.operator_pkg / "bin" / "grabowski-operator"
        self.entry.write_text("#!/bin/sh\nexit 0\n")
        self.entry.chmod(0o555)

    def trusted_fragment(self, path=None):
        return authority.fragment_trusted(
            self.fragment if path is None else path,
            etc_fragment=self.fragment,
            store_root=self.store,
            trusted_uid=self.uid,
        )

    def argv(self, value=None):
        return authority.expected_operator_argv(
            environ={authority.OPERATOR_ENTRYPOINT_ENV: str(self.entry) if value is None else value},
            store_root=self.store,
            trusted_uid=self.uid,
        )

    def test_nixos_generated_symlink_and_direct_nix_store_fragment_admitted(self):
        self.assertTrue(self.trusted_fragment())
        self.assertTrue(self.trusted_fragment(self.unit_file))

    def test_wrong_unit_path_or_unit_store_identity_rejected(self):
        wrong = self.sysunits / "other.service"
        wrong.symlink_to(self.unit_file)
        self.assertFalse(self.trusted_fragment(wrong))
        self.assertFalse(self.trusted_fragment(Path("/tmp/grabowski-operator.service")))
        nonstore = self.sysunits / "not-in-store"
        nonstore.write_text("[Service]\n")
        self.fragment.unlink()
        self.fragment.symlink_to(nonstore)
        self.assertFalse(self.trusted_fragment())

    def test_root_owned_immutable_regular_file_required(self):
        self.unit_file.chmod(0o666)
        self.assertFalse(self.trusted_fragment())
        self.unit_file.chmod(0o444)
        self.unit_dir.chmod(0o777)
        self.assertFalse(self.trusted_fragment())
        self.unit_dir.chmod(0o700)
        noncanonical_dir = self.store / ("c" * 32 + "-unit-unrelated.service")
        noncanonical_dir.mkdir(mode=0o700)
        nested = noncanonical_dir / "grabowski-operator.service"
        nested.write_text("[Service]\n")
        nested.chmod(0o444)
        self.assertFalse(self.trusted_fragment(nested))
        # Root-owned and sticky /nix/store 01775 is the observed NixOS mode;
        # group-writable without sticky, or world-writable, is forbidden.
        self.store.chmod(0o1775)
        self.assertTrue(self.trusted_fragment())
        self.store.chmod(0o775)
        self.assertFalse(self.trusted_fragment())
        self.store.chmod(0o1777)
        self.assertFalse(self.trusted_fragment())

    def test_etc_path_must_be_root_controlled_symlink(self):
        self.fragment.unlink()
        self.fragment.write_text("[Service]\nExecStart=unrelated\n")
        self.assertFalse(self.trusted_fragment())
        self.fragment.unlink()
        self.fragment.symlink_to(self.unit_file)
        self.etc.chmod(0o777)
        self.assertFalse(self.trusted_fragment())

    def test_nixos_etc_directory_symlink_chain_admitted_only_if_immutable(self):
        self.fragment.unlink()
        self.sysunits.rmdir()
        static_units = self.etc / "static" / "systemd" / "system"
        static_units.mkdir(parents=True, mode=0o700)
        (self.etc / "static").chmod(0o700)
        (self.etc / "static" / "systemd").chmod(0o700)
        static_fragment = static_units / "grabowski-operator.service"
        static_fragment.symlink_to(self.unit_file)
        self.sysunits.symlink_to(static_units)
        self.assertTrue(self.trusted_fragment())
        static_units.chmod(0o777)
        self.assertFalse(self.trusted_fragment())

    def test_wrong_trusted_uid_fails_even_for_matching_paths(self):
        self.assertFalse(
            authority.fragment_trusted(
                self.fragment, etc_fragment=self.fragment,
                store_root=self.store, trusted_uid=self.uid + 1,
            )
        )

    def test_broker_expected_process_command_exact_and_store_bound(self):
        self.assertEqual(
            self.argv(),
            (
                str(self.entry), "-m", "grabowski_operator", "--transport",
                "streamable-http", "--host", "127.0.0.1", "--port", "18181",
            ),
        )
        self.assertRaises(PermissionError, authority.expected_operator_argv, environ={},
                          store_root=self.store, trusted_uid=self.uid)
        self.assertRaises(PermissionError, self.argv, "/tmp/grabowski-operator")
        self.assertRaises(PermissionError, self.argv, str(self.entry) + "\x00bad")
        self.store.chmod(0o1775)
        self.assertEqual(self.argv()[0], str(self.entry))
        self.store.chmod(0o775)
        self.assertRaises(PermissionError, self.argv)
        self.store.chmod(0o1777)
        self.assertRaises(PermissionError, self.argv)

    def test_old_release_operator_rejected_even_if_immutable(self):
        # The previous Gen48 operator remains in the Nix store for recovery,
        # but must not authenticate as the new release's systemd MainPID.
        obsolete = self.store / ("c" * 32 + "-grabowski-operator-5e136cf3")
        (obsolete / "bin").mkdir(parents=True, mode=0o700)
        old_entry = obsolete / "bin" / "grabowski-operator"
        old_entry.write_text("#!/bin/sh\nexit 0\n")
        old_entry.chmod(0o555)
        self.assertRaises(PermissionError, self.argv, str(old_entry))

    def test_effective_root_owned_operator_can_advance_after_self_deploy(self):
        # PID1 has a newer immutable ExecStart while the NixOS base unit is old.
        active = "/nix/store/" + "d" * 32 + "-grabowski-operator-68c8bcde/bin/grabowski-operator"
        expected = (
            "{ path=" + active + " ; argv[]=" + active
            + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a]"
            + " ; pid=0 ; code=(null) ; status=0/0 }\n"
        ).encode()
        with patch.object(authority.subprocess, "run", return_value=SimpleNamespace(
            returncode=0, stdout=expected, stderr=b""
        )):
            with patch.dict(authority.expected_operator_argv.__globals__, {
                "_safe_nix_store_directory": lambda *_args, **_kw: True,
                "_safe_dir": lambda *_args, **_kw: True,
                "_safe_file": lambda *_args, **_kw: True,
            }):
                actual = authority.expected_operator_argv()
        self.assertEqual(actual[0], active)
        self.assertEqual(actual[1:], (
            "-m", "grabowski_operator", "--transport", "streamable-http",
            "--host", "127.0.0.1", "--port", "18181",
        ))
        # A mismatching arbitrary peer argv is never inferred from PID1.
        for reply in (
            expected.replace(("argv[]=" + active).encode(), b"argv[]=/tmp/attacker"),
            expected + expected,
            expected.replace(("path=" + active).encode(), b"path=/tmp/attacker"),
        ):
            with patch.object(authority.subprocess, "run", return_value=SimpleNamespace(
                returncode=0, stdout=reply, stderr=b""
            )):
                self.assertRaises(PermissionError, authority._effective_operator_entrypoint)

    def test_pid1_execstart_errors_refuse_before_peer_admission(self):
        for reply, code, stderr in (
            (b"", 0, b""), (b"bad unit", 0, b""),
            (b"x" * 4097, 0, b""), (b"", 1, b""),
            (b"", 0, b"connection denied"),
        ):
            with patch.object(authority.subprocess, "run", return_value=SimpleNamespace(
                returncode=code, stdout=reply, stderr=stderr
            )):
                self.assertRaises(PermissionError, authority._effective_operator_entrypoint)

    def test_modified_or_unrelated_binary_rejected(self):
        self.entry.chmod(0o777)
        self.assertRaises(PermissionError, self.argv)
        self.entry.chmod(0o555)
        self.operator_pkg.chmod(0o777)
        self.assertRaises(PermissionError, self.argv)
        self.operator_pkg.chmod(0o700)
        self.entry.rename(self.entry.with_name("different-operator"))
        self.assertRaises(PermissionError, self.argv)


if __name__ == "__main__":
    unittest.main()