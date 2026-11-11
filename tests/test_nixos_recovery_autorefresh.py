"""Regression tests for the complete unprivileged NixOS recovery refresh client."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

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

    def test_new_completed_backup_defeats_recent_proof(self):
        status = current_status()
        proof_time = status["server_recovery"]["generated_at_unix"]
        self.assertEqual(
            refresh.decide(status, now=NOW, latest_backup_finished_unix=proof_time + 1),
            "refresh",
        )
        self.assertEqual(
            refresh.decide(status, now=NOW, latest_backup_finished_unix=proof_time),
            "skip",
        )

    def test_new_backup_invalidates_local_marker_even_if_old_canonical_is_intact(self):
        s = current_status()
        s["local_backup"] = {
            "valid": False,
            "error": "NixOS recovery snapshot lacks matching completed backup invocation",
        }
        generated = s["server_recovery"]["generated_at_unix"]
        self.assertEqual(
            refresh.decide(s, now=NOW, latest_backup_finished_unix=generated + 4),
            "refresh",
        )
        # If there was no later successful backup, preserve the old intact
        # recovery proof instead of overwriting it during a failed upload.
        self.assertEqual(
            refresh.decide(s, now=NOW, latest_backup_finished_unix=None),
            "skip",
        )

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

    def test_invalid_previous_marker_allows_new_native_backup_probe(self):
        s = current_status()
        s["ready_for_privileged_actions"] = False
        s["checks"]["local_backup_fresh"] = False
        s["checks"]["server_recovery_fresh"] = False
        s["checks"]["server_recovery_source_current"] = False
        s["local_backup"] = {
            "valid": False,
            "snapshot_id": "f30f8e22",
            "error": "NixOS recovery snapshot lacks matching completed backup invocation",
        }
        s["server_recovery"] = {"valid": False, "snapshot_id": "f30f8e22"}
        s["server_recovery_source_publication"] = {"current": False}
        # The old marker cannot attest the new run; root probe validates the
        # new systemd invocation and snapshot before writing a fresh marker.
        self.assertEqual(refresh.decide(s, now=NOW), "refresh")

    def test_failed_or_running_backup_cannot_destroy_intact_old_proof(self):
        for value in (False, None):
            s = current_status()
            s["server_recovery"]["generated_at_unix"] = NOW - 12 * 60 * 60
            s["local_backup"]["valid"] = value
            with self.subTest(value=value):
                self.assertEqual(refresh.decide(s, now=NOW), "skip")

    def test_invalid_marker_still_requires_native_timer_and_rootbroker(self):
        for key in refresh.PREREQUISITE_CHECKS:
            s = current_status()
            s["ready_for_privileged_actions"] = False
            s["checks"][key] = False
            s["local_backup"]["valid"] = False
            s["server_recovery"]["valid"] = False
            with self.subTest(key=key), self.assertRaisesRegex(
                RuntimeError, "rootbroker is not ready"
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


class NativeBackupReadTests(unittest.TestCase):
    @staticmethod
    def result(**fields):
        values = {
            "LoadState": "loaded", "ActiveState": "inactive",
            "Result": "success", "ExecMainCode": "1", "ExecMainStatus": "0",
            "ExecMainExitTimestamp": f"@{NOW - 10}",
        }
        values.update(fields)
        return Mock(returncode=0, stdout="\n".join(
            f"{key}={value}" for key, value in values.items()
        ) + "\n")

    def test_completed_backup_timestamp_uses_fixed_readonly_query(self):
        with patch.object(refresh.subprocess, "run", return_value=self.result()) as run:
            self.assertEqual(refresh.latest_completed_backup_unix(now=NOW), NOW - 10)
        args, kwargs = run.call_args
        self.assertEqual(args[0][:5], [
            "/run/current-system/sw/bin/systemctl", "--system",
            "--timestamp=unix", "show", "restic-backups-heim-pc.service",
        ])
        self.assertFalse(kwargs["check"])
        self.assertNotIn("shell", kwargs)

    def test_failed_running_unavailable_and_future_are_not_evidence(self):
        for values in (
            {"ActiveState": "activating"}, {"Result": "exit-code"},
            {"ExecMainStatus": "1"}, {"ExecMainCode": "2"},
            {"ExecMainExitTimestamp": ""}, {"LoadState": "not-found"},
            {"ExecMainExitTimestamp": f"@{NOW+55}"},
        ):
            with self.subTest(fields=values), patch.object(
                refresh.subprocess, "run", return_value=self.result(**values)
            ):
                self.assertIsNone(refresh.latest_completed_backup_unix(now=NOW))
        with patch.object(refresh.subprocess, "run", side_effect=OSError):
            self.assertIsNone(refresh.latest_completed_backup_unix(now=NOW))


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
        self.assertIn('"--timestamp=unix"', source)
        self.assertNotIn('shell=True', source)
        self.assertNotIn('sudo ', source)
        self.assertNotIn('restic restore', source)
        self.assertIn('all(v is True for v in after["checks"].values())', source)
        self.assertIn('while isinstance(exc, BaseExceptionGroup)', source)


if __name__ == "__main__":
    unittest.main()