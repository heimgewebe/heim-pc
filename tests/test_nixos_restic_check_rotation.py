"""Actual rotating Restic data-check progression, full check and failure paths."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import time
import types
import unittest
from unittest.mock import MagicMock, patch

SOURCE = Path(__file__).resolve().parents[1] / "nixos/system/modules/heim-pc-restic-recovery-probe.py"
SPEC = importlib.util.spec_from_file_location("restic_rotation_effect_test", SOURCE)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class RotationEffectsTests(unittest.TestCase):
    def test_successful_checks_cycle_all_ten_partitions(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            state = Path(root)
            with patch.object(probe, "STATE", state), patch.object(
                probe, "CHECK_CURSOR", state / "check-cursor.json"
            ):
                seen = []
                for _ in range(20):
                    part = probe._next_check_part()
                    seen.append(part)
                    probe._commit_check_part(part)
                    self.assertEqual(json.loads(probe.CHECK_CURSOR.read_text())["repository_id"],
                                     probe.REPOSITORY_ID)
                self.assertEqual(seen, list(range(1, 11)) * 2)
                self.assertEqual(probe._next_check_part(), 1)

    def test_cursor_bound_to_repository_and_valid_index(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            file = Path(root) / "check-cursor.json"
            with patch.object(probe, "CHECK_CURSOR", file):
                for body in (
                    {"repository_id": "0" * 64, "last_part": 1},
                    {"repository_id": probe.REPOSITORY_ID, "last_part": 0},
                    {"repository_id": probe.REPOSITORY_ID, "last_part": 11},
                    {"repository_id": probe.REPOSITORY_ID, "last_part": "10"},
                    {},
                ):
                    file.write_text(json.dumps(body))
                    with self.subTest(body=body):
                        with self.assertRaises(RuntimeError):
                            probe._next_check_part()

    def invoke(self, part: int, fail: bool = False):
        """Run the full main logic using a faked root-owned state; no real restic."""
        state = MagicMock()
        state.lstat.return_value = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
        now = int(time.time())
        backup_run = ("a" * 32, now - 700, now - 300, 100, 200)
        with tempfile.TemporaryDirectory() as root:
            with patch.object(probe, "STATE", state), \
                 patch.object(probe, "PROOF", Path(root) / "proof.json"), \
                 patch.object(probe.os, "geteuid", return_value=0), \
                 patch.object(probe.sys, "argv", ["fixed-unit"]), \
                 patch.object(probe, "_mount_identity", return_value="/dev/sda1"), \
                 patch.object(probe, "_backup_timer_ready", return_value=backup_run), \
                 patch.object(probe, "_snapshot_for_backup_run",
                              return_value=("b" * 64, now - 400)), \
                 patch.object(probe, "_restore_digest", return_value="c" * 64), \
                 patch.object(probe, "_require_backup_run_unchanged"), \
                 patch.object(probe, "_next_check_part", return_value=part), \
                 patch.object(probe, "_commit_check_part") as commit, \
                 patch.object(probe, "_write_proof") as proof_out, \
                 patch.object(probe, "_restic",
                              side_effect=RuntimeError("data check failed") if fail else None) as check:
                if fail:
                    with self.assertRaisesRegex(RuntimeError, "data check failed"):
                        probe.main()
                else:
                    self.assertEqual(probe.main(), 0)
                calls = [c for c in check.call_args_list if c.args and c.args[0] == "check"]
                self.assertEqual(len(calls), 1)
                mode = f"--read-data-subset={part}/10"
                self.assertEqual(calls[0].args, ("check", mode, "--retry-lock", "6h"))
                if fail:
                    commit.assert_not_called()
                    proof_out.assert_not_called()
                else:
                    commit.assert_called_once_with(part)
                    proof_out.assert_called_once()
                    payload = proof_out.call_args.args[0]
                    # Exact shared v1 ABI: both the running Grabowski server
                    # and rootbroker reject unexpected proof fields.
                    self.assertEqual(set(payload), {
                        "schema_version", "kind", "started_at_unix",
                        "completed_at_unix", "snapshot_id", "snapshot_time_unix",
                        "repository_id", "backup_uuid", "backup_source",
                        "restore_sha256", "restore_probe_valid",
                        "repository_check_valid",
                    })

    def test_tenth_success_reads_last_tenth(self) -> None:
        self.invoke(10)

    def test_prior_nine_steps_read_different_subsets(self) -> None:
        for part in range(1, 10):
            with self.subTest(part=part):
                self.invoke(part)

    def test_failed_last_subset_does_not_advance_or_publish_success(self) -> None:
        self.invoke(10, fail=True)

    def test_failed_partial_check_does_not_advance(self) -> None:
        self.invoke(2, fail=True)

    def test_nixos_probe_runs_before_existing_refresh_not_on_duplicate_timer(self) -> None:
        nix = (Path(__file__).resolve().parents[1]
               / "nixos/system/modules/restic-seagate-backup.nix").read_text()
        self.assertNotIn('systemd.timers."heim-pc-restic-recovery-probe" = {', nix)
        self.assertIn('grabowski-recovery-refresh.service.d/10-restic-proof.conf', nix)
        self.assertIn('Requires=heim-pc-restic-recovery-probe.service', nix)
        self.assertIn('After=heim-pc-restic-recovery-probe.service', nix)
        self.assertIn('TimeoutStartSec = "8h";', nix)


if __name__ == "__main__":
    unittest.main()