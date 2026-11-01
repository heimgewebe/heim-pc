"""Regression tests for the explicitly triggered NixOS broker bootstrap.

Uses only disposable private fixtures; never accesses /persist or /etc.
"""
import json
import os
from pathlib import Path
import runpy
import stat
import tempfile
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "nixos/system/modules/grabowski-rootbroker-bootstrap.py"
BOOT = SimpleNamespace(**runpy.run_path(str(SCRIPT), run_name="bootstrap_tests"))


class RootbrokerBootstrapTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.uid = os.getuid()
        self.source = self.root / "persist/secrets/grabowski/privileged-actions.json"
        self.installed = self.root / "etc/grabowski/privileged-actions.json"
        self.lock = self.root / "run/grabowski/rootbroker-cutover.lock"
        self.backups = self.root / "var/lib/grabowski/rootbroker-cutover-backups"
        for path in (self.source, self.installed, self.lock, self.backups / "placeholder"):
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.installed.parent.chmod(0o755)
        self.backups.chmod(0o700)
        self.old = (b'{"schema_version":2,"actions":{"nixos_restic_root_unit":'
                    b'{"enabled":true},"publish_recovery_marker":{"enabled":true}}}\n')
        for p in (self.source, self.installed):
            p.write_bytes(self.old)
            p.chmod(0o600)
        self.lock.write_bytes(b"")
        self.lock.chmod(0o600)
        self.action = {
            "enabled": True, "mode": "argv-json",
            "policy_intent": "trusted-owner-root-autonomy",
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
            "kill_switch_path": "/var/lib/grabowski/operator-blockade/operator-kill-switch",
            "target_pattern": r"\\{.{1,49152}\\}",
            "cwd_pattern": "/[A-Za-z0-9._/@:+-]{0,999}",
            "allow_shell": True, "max_argv": 128, "timeout_seconds": 3600,
        }

    def installer(self):
        BOOT.atomic_replace(self.installed, self.source.read_bytes(), uid=self.uid,
                            trusted_boundary=self.root)

    def invoke(self, *, apply=False, **overrides):
        params = dict(source=self.source, installed=self.installed, lock=self.lock,
                      backups=self.backups, expected_old_sha=BOOT.sha(self.source.read_bytes()),
                      action=self.action, installer=self.installer, apply=apply,
                      uid=self.uid, trusted_boundary=self.root)
        params.update(overrides)
        return BOOT.bootstrap(**params)

    def test_default_plan_is_nonmutating(self):
        outcome = self.invoke()
        self.assertEqual(outcome["state"], "ready")
        self.assertFalse(outcome["changed"])
        self.assertEqual(self.source.read_bytes(), self.old)
        self.assertEqual(self.installed.read_bytes(), self.old)
        self.assertEqual(list(self.backups.iterdir()), [])

    def test_explicit_apply_preserves_actions_and_creates_backup(self):
        outcome = self.invoke(apply=True)
        self.assertEqual(outcome["state"], "applied")
        self.assertEqual(self.source.read_bytes(), self.installed.read_bytes())
        doc = json.loads(self.source.read_bytes())
        self.assertEqual(doc["actions"]["operator_power_argv"], self.action)
        self.assertTrue(doc["actions"]["publish_recovery_marker"]["enabled"])
        backup = Path(outcome["backup_path"])
        self.assertEqual(backup.read_bytes(), self.old)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assertEqual(self.invoke()["state"], "already_applied")

    def test_wrong_expected_preimage_fails_unchanged(self):
        with self.assertRaisesRegex(BOOT.BootstrapError, "mismatch"):
            self.invoke(apply=True, expected_old_sha="0" * 64)
        self.assertEqual(self.source.read_bytes(), self.old)

    def test_out_of_sync_installed_policy_fails(self):
        self.installed.write_bytes(b'{"schema_version":2,"actions":{}}')
        with self.assertRaisesRegex(BOOT.BootstrapError, "mismatch"):
            self.invoke(apply=True)
        self.assertEqual(self.source.read_bytes(), self.old)

    def test_symlink_and_hardlink_sources_rejected(self):
        self.source.unlink()
        self.source.symlink_to(self.installed)
        with self.assertRaises(OSError):
            self.invoke()
        self.source.unlink()
        self.source.write_bytes(self.old)
        self.source.chmod(0o600)
        os.link(self.source, self.source.parent / "unexpected-hardlink")
        with self.assertRaisesRegex(BOOT.BootstrapError, "unsafe root policy"):
            self.invoke(apply=True)

    def test_writable_directory_rejected(self):
        self.source.parent.chmod(0o777)
        with self.assertRaisesRegex(BOOT.BootstrapError, "unsafe parent"):
            self.invoke(apply=True)

    def test_installer_failure_rolls_back_private_source(self):
        def fail():
            raise RuntimeError("simulated installer failure")
        with self.assertRaisesRegex(RuntimeError, "simulated"):
            self.invoke(apply=True, installer=fail)
        self.assertEqual(self.source.read_bytes(), self.old)
        self.assertEqual(self.installed.read_bytes(), self.old)

    def test_post_install_error_rolls_back_both_files(self):
        calls = []
        def install_then_fail():
            calls.append(1)
            self.installer()
            if len(calls) == 1:
                raise RuntimeError("post-install failure")
        with self.assertRaisesRegex(RuntimeError, "post-install"):
            self.invoke(apply=True, installer=install_then_fail)
        self.assertEqual(self.source.read_bytes(), self.old)
        self.assertEqual(self.installed.read_bytes(), self.old)
        self.assertEqual(len(calls), 2)

    def test_existing_different_authority_is_not_overwritten(self):
        doc = json.loads(self.old)
        doc["actions"]["operator_power_argv"] = {"enabled": False}
        data = json.dumps(doc).encode()
        self.source.write_bytes(data)
        self.installed.write_bytes(data)
        with self.assertRaisesRegex(BOOT.BootstrapError, "differs"):
            self.invoke(apply=True)

    def test_pinned_source_hash_and_peer_constraints(self):
        payload = {"actions": {"operator_power_argv": self.action}}
        fake = SimpleNamespace(returncode=0, stdout=json.dumps(payload).encode())
        runner = lambda *_a, **_kw: fake
        with self.assertRaisesRegex(BOOT.BootstrapError, "SHA mismatch"):
            BOOT.read_pinned_action(Path("/repo"), BOOT.PINNED_COMMIT, "0" * 64, runner=runner)
        verified = BOOT.read_pinned_action(Path("/repo"), BOOT.PINNED_COMMIT,
                                          BOOT.sha(BOOT.canonical_json(self.action)),
                                          runner=runner)
        self.assertEqual(verified, self.action)
        weaker = dict(self.action)
        weaker.pop("allowed_peer_unit")
        fake.stdout = json.dumps({"actions": {"operator_power_argv": weaker}}).encode()
        with self.assertRaisesRegex(BOOT.BootstrapError, "peer contract"):
            BOOT.read_pinned_action(Path("/repo"), BOOT.PINNED_COMMIT,
                                    BOOT.sha(BOOT.canonical_json(weaker)), runner=runner)

    def test_nixos_helper_has_no_auto_run_unit_or_private_policy_payload(self):
        production = (ROOT / "nixos/system/modules/grabowski-production.nix").read_text()
        self.assertIn('rootbrokerBootstrapPackage = pkgs.runCommand', production)
        self.assertIn('grabowski-rootbroker-bootstrap.py', production)
        self.assertIn('environment.systemPackages = lib.optionals admit', production)
        self.assertNotIn('systemd.services.grabowski-rootbroker-bootstrap', production)
        self.assertIn('SOURCE = Path("/persist/secrets/grabowski/privileged-actions.json")',
                      (ROOT / "nixos/system/modules/grabowski-private-policy-install.py").read_text())


if __name__ == "__main__":
    unittest.main()
