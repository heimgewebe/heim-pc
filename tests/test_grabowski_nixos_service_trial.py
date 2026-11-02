"""Regression of a NixOS source-bound, reversible service-only trial; no host effects."""
from pathlib import Path
import hashlib
import json
import os
import importlib.util
import stat
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "scripts/grabowski_nixos_service_trial.py"
spec = importlib.util.spec_from_file_location("grabowski_nixos_service_trial", S)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def originals():
    op = (
        "[Service]\n"
        f"ExecStart={m.OLD_OP}/bin/grabowski-operator\n"
        f"ExecStartPost={m.OLD_OP}/bin/python3 -I -B /nix/store/ingress.py "
        f"{m.OLD_OP}/share/grabowski/nixos-integrity-manifest.json\n"
        f"Environment=PATH=/run/wrappers/bin:{m.OLD_BR}/bin:/nix/store/coreutils/bin\n"
    )
    broker = (f"[Service]\nExecStart={m.OLD_BR}/bin/grabowski-privileged-broker\n"
              f"Environment=GRABOWSKI_NIXOS_OPERATOR_ENTRYPOINT={m.OLD_OP}/bin/grabowski-operator\n")
    schema = (f"[Service]\nExecStart=/nix/store/python/bin/python -I -B "
              f"/nix/store/installer.py {m.OLD_OP}/lib/python3.12/site-packages/"
              "grabowski_runtime_contract.py\n")
    return op, broker, schema


class TrialContractTests(unittest.TestCase):
    def test_three_units_together_and_desktop_untouched(self):
        result = m.render(originals())
        self.assertEqual(set(result), set(m.UNITS))
        self.assertIn(m.NEW_OP + "/bin/grabowski-operator", result[m.UNITS[0]])
        self.assertIn(m.NEW_BR + "/bin/grabowski-privileged-broker", result[m.UNITS[1]])
        self.assertIn(m.NEW_OP + "/lib/python3.12/site-packages/grabowski_runtime_contract.py", result[m.UNITS[2]])
        self.assertIn("ExecStartPost=" + m.NEW_OP + "/bin/python3 -I -B", result[m.UNITS[0]])
        self.assertNotIn(m.OLD_BR + "/bin", result[m.UNITS[0]])
        self.assertTrue(all("xrdp" not in s.lower() and "display-manager" not in s.lower()
                            for s in result.values()))

    def test_path_uses_existing_nix_environment_without_fabrication(self):
        result = m.render(originals())
        self.assertIn("PATH=/run/wrappers/bin:" + m.NEW_BR + "/bin:/nix/store/coreutils/bin",
                      result[m.UNITS[0]])

    def test_preimage_mismatch_does_not_fallback_to_guess(self):
        old = list(originals())
        old[0] = old[0].replace(m.OLD_OP, "/tmp/untrusted")
        with self.assertRaises(m.TrialError):
            m.render(tuple(old))
        old = list(originals())
        old[0] += "Environment=PATH=/tmp/other\n"
        with self.assertRaises(m.TrialError):
            m.render(tuple(old))
        old = list(originals())
        old[2] = old[2].replace(m.OLD_OP, "/tmp/other")
        with self.assertRaises(m.TrialError):
            m.render(tuple(old))

    def test_every_package_is_pinned_not_mutable_worktree(self):
        for prefix in (m.OLD_OP, m.OLD_BR, m.NEW_OP, m.NEW_BR, m.INGRESS):
            self.assertTrue(prefix.startswith("/nix/store/"))
        self.assertEqual(len(m.HEAD), 40)
        self.assertEqual(len(m.MANIFEST_SHA), 64)

    def test_private_create_cannot_replace_existing(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "trial"
            m.exclusive_write(p, b"first")
            self.assertEqual(p.read_bytes(), b"first")
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                m.exclusive_write(p, b"new")
            self.assertEqual(p.read_bytes(), b"first")

    def test_immutable_manifest_must_bind_exact_release(self):
        with mock.patch.object(m, "checked_regular") as checked:
            checked.side_effect = lambda p: (
                b'{"repo_head":"incorrect","release_id":"other","entrypoint_contract":{"expected_tools":[]}}'
                if "nixos-integrity-manifest.json" in str(p)
                else b'{"source_revision":"incorrect","release_id":"other"}'
            )
            with mock.patch.object(m, "digest", return_value=m.MANIFEST_SHA):
                with self.assertRaises(m.TrialError):
                    m.verified_release()

    def test_plan_refuses_concurrent_trial(self):
        with mock.patch.object(m, "verified_release"), mock.patch.object(m, "original_units", return_value=originals()), \
             mock.patch.object(m, "root_dir"), mock.patch.object(m, "operator_matches", return_value=True):
            with tempfile.TemporaryDirectory() as tmp:
                old = m.STATE
                try:
                    m.STATE = Path(tmp) / "ongoing"
                    m.STATE.write_text("{}")
                    with self.assertRaisesRegex(m.TrialError, "another native trial"):
                        m.plan()
                finally:
                    m.STATE = old

    def test_confirmation_refuses_unknown_or_wrong_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            before_state, before_ack = m.STATE, m.ACK
            try:
                m.STATE, m.ACK = Path(tmp) / "state", Path(tmp) / "ack"
                m.STATE.write_text('{"head":"incorrect"}')
                with mock.patch.object(m, "checked_regular", side_effect=lambda p: p.read_bytes()), \
                     mock.patch.object(m, "operator_matches", return_value=True):
                    with self.assertRaises(m.TrialError):
                        m.confirm()
                self.assertFalse(m.ACK.exists())
            finally:
                m.STATE, m.ACK = before_state, before_ack

    def test_rollback_does_not_delete_mutated_dropins(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "override.conf"
            path.write_bytes(b"mutated")
            with mock.patch.object(m, "dropin_paths", return_value={m.UNITS[0]:path}), \
                 mock.patch.object(m, "checked_regular", return_value=b"mutated"):
                with self.assertRaisesRegex(m.TrialError, "modified"):
                    m.remove_own_dropins({m.UNITS[0]:"expected"})
            self.assertTrue(path.exists())


    def test_manual_rollback_requires_existing_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "missing"
            with mock.patch.object(m, "STATE", p), \
                 mock.patch.object(m, "dropin_paths", return_value={m.UNITS[0]:p}):
                with self.assertRaisesRegex(m.TrialError, "no trial state"):
                    m.rollback()

    def test_failed_manual_recovery_preserves_root_owned_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "state"
            ack = Path(tmp) / "ack"
            p.write_text("current")
            with mock.patch.object(m, "STATE", p), mock.patch.object(m, "ACK", ack), \
                 mock.patch.object(m, "original_units", return_value=originals()), \
                 mock.patch.object(m, "revert", side_effect=m.TrialError("recovery failed")):
                with self.assertRaisesRegex(m.TrialError, "recovery failed"):
                    m.rollback()
            self.assertTrue(p.exists())

    def test_successful_manual_rollback_cleans_trial_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, ack = Path(tmp) / "state", Path(tmp) / "ack"
            p.write_text("current")
            ack.write_text("current")
            with mock.patch.object(m, "STATE", p), mock.patch.object(m, "ACK", ack), \
                 mock.patch.object(m, "original_units", return_value=originals()), \
                 mock.patch.object(m, "revert"):
                m.rollback()
            self.assertFalse(p.exists())
            self.assertFalse(ack.exists())


    def test_exclusive_release_lock_blocks_second_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "release.lock"
            with mock.patch.object(m, "LOCK", lock):
                fd = m.exclusive_release_lock(owner_uid=os.getuid())
                try:
                    self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)
                    with self.assertRaises(BlockingIOError):
                        m.exclusive_release_lock(owner_uid=os.getuid())
                finally:
                    os.close(fd)
                again = m.exclusive_release_lock(owner_uid=os.getuid())
                os.close(again)

    def test_release_lock_never_follows_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            link = Path(tmp) / "release.lock"
            target.write_text("not a lock")
            link.symlink_to(target)
            with mock.patch.object(m, "LOCK", link):
                with self.assertRaises(OSError):
                    m.exclusive_release_lock(owner_uid=os.getuid())
            self.assertEqual(target.read_text(), "not a lock")


if __name__ == "__main__":
    unittest.main()