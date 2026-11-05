"""Regression tests for the complete unprivileged NixOS recovery refresh client."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "nixos/system/modules/grabowski-recovery-mcp-refresh.py"
MODULE = ROOT / "nixos/system/modules/grabowski-production.nix"
spec = importlib.util.spec_from_file_location("nixos_recovery_refresh", SCRIPT)
refresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refresh)
NOW = 1_793_900_000


def current_status():
    return {
        "ready_for_privileged_actions": True,
        "checks": {
            "audit_chain": True,
            "deployment_provenance": True,
            "local_backup_fresh": True,
            "backup_timer_enabled": True,
            "backup_timer_active": True,
            "server_recovery_fresh": True,
            "server_recovery_source_current": True,
            "kill_switch_clear": True,
            "privileged_broker_ready": True,
        },
        "local_backup": {"valid": True, "snapshot_id": "deadbeef"},
        "server_recovery": {
            "valid": True, "snapshot_id": "deadbeef",
            "generated_at_unix": NOW - 60,
        },
        "server_recovery_source_publication": {"current": True},
    }


class DecisionTests(unittest.TestCase):
    def test_valid_recent_proof_is_reused(self):
        self.assertEqual(refresh.decide(current_status(), now=NOW), "skip")

    def test_refresh_before_24_hour_expiry(self):
        s = current_status()
        s["server_recovery"]["generated_at_unix"] = NOW - 11 * 60 * 60
        self.assertEqual(refresh.decide(s, now=NOW), "refresh")

    def test_unpublished_proof_retriggers_broker_publication(self):
        s = current_status()
        s["server_recovery_source_publication"]["current"] = False
        self.assertEqual(refresh.decide(s, now=NOW), "refresh")

    def test_root_proof_missing_but_native_backup_valid(self):
        s = current_status()
        s["ready_for_privileged_actions"] = False
        s["server_recovery"] = {"valid": False}
        self.assertEqual(refresh.decide(s, now=NOW), "refresh")

    def test_latest_failed_or_running_backup_cannot_destroy_old_proof(self):
        for value in (False, None):
            s = current_status()
            s["server_recovery"]["generated_at_unix"] = NOW - 12 * 60 * 60
            s["local_backup"]["valid"] = value
            with self.subTest(value=value), self.assertRaisesRegex(
                RuntimeError, "no journal-bound successful native backup"
            ):
                refresh.decide(s, now=NOW)

    def test_unready_timer_rootbroker_or_killswitch_rejected(self):
        for key in refresh.PREREQUISITE_CHECKS:
            s = current_status()
            s["server_recovery"]["generated_at_unix"] = NOW - 12 * 60 * 60
            s["checks"][key] = False
            with self.subTest(key=key), self.assertRaisesRegex(
                RuntimeError, "rootbroker is not ready"
            ):
                refresh.decide(s, now=NOW)

    def test_malformed_evidence_rejected(self):
        for status, now in ((None, NOW), ({}, NOW), (current_status(), True),
                            (current_status(), 0)):
            with self.subTest(value=status, now=now), self.assertRaises(RuntimeError):
                refresh.decide(status, now=now)

    def test_clock_future_proof_is_not_misclassified_as_fresh(self):
        s = current_status()
        s["server_recovery"]["generated_at_unix"] = NOW + 60
        self.assertEqual(refresh.decide(s, now=NOW), "refresh")


class PublishedProofTests(unittest.TestCase):
    @staticmethod
    def valid():
        return {
            "restore_probe_valid": True,
            "repository_check_valid": True,
            "snapshot_id": "abcd1234",
            "root_proof": {"validated": True},
            "canonical_recovery": {"valid": True, "snapshot_id": "abcd1234"},
            "source_recovery": {"valid": True},
            "publication": {"success": True},
        }

    def test_accepts_nixos_proof_without_remote_only_marker_valid(self):
        self.assertEqual(refresh.require_published_proof(self.valid()), "abcd1234")

    def test_missing_root_or_publication_is_rejected(self):
        variants = (
            ("root", "root_proof", None),
            ("canonical", "canonical_recovery", {"valid": False}),
            ("source", "source_recovery", {"valid": False}),
            ("publish", "publication", {"success": False}),
            ("backup", "repository_check_valid", False),
            ("restore", "restore_probe_valid", False),
            ("snapshot", "snapshot_id", "wrong-id"),
        )
        for label, key, value in variants:
            proof = self.valid()
            proof[key] = value
            with self.subTest(kind=label), self.assertRaisesRegex(
                RuntimeError, "canonical publication not proven"
            ):
                refresh.require_published_proof(proof)


class DeclarationTests(unittest.TestCase):
    def test_fixed_nonroot_operator_path_is_used(self):
        module = MODULE.read_text()
        self.assertIn('systemd.services."grabowski-recovery-refresh" = lib.mkIf admit', module)
        self.assertIn('systemd.timers."grabowski-recovery-refresh" = lib.mkIf admit', module)
        self.assertIn('User = "alex";', module)
        self.assertIn(
            'ExecStart = "${cfg.operatorPackage}/bin/python3 -I -B '
            '${./grabowski-recovery-mcp-refresh.py}";', module
        )
        self.assertIn('NoNewPrivileges = true;', module)
        self.assertIn('RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" ];', module)
        self.assertIn('CapabilityBoundingSet = [ ];', module)

    def test_two_recovery_opportunities_after_native_backup(self):
        module = MODULE.read_text()
        self.assertIn('OnCalendar = "*-*-* 09,21:15:00";', module)
        self.assertIn('RandomizedDelaySec = "10m";', module)
        self.assertIn('Persistent = true;', module)
        self.assertIn('Unit = "grabowski-recovery-refresh.service";', module)
        self.assertEqual(refresh.REFRESH_AFTER_SECONDS, 11 * 60 * 60)

    def test_only_complete_mcp_publication_method_is_invoked(self):
        source = SCRIPT.read_text()
        self.assertIn('"grabowski_recovery_server_probe"', source)
        self.assertIn('"grabowski_recovery_status"', source)
        self.assertIn('127.0.0.1:18181/mcp', source)
        self.assertNotIn('subprocess', source)
        self.assertNotIn('sudo ', source)
        self.assertNotIn('restic restore', source)
        self.assertIn('all(v is True for v in after["checks"].values())', source)


if __name__ == "__main__":
    unittest.main()