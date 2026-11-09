"""Scoped retention behavioural tests. Never touch the live backup repository."""
from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import time
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "nixos/system/modules/heim-pc-restic-retention.py"
SPEC = importlib.util.spec_from_file_location("restic_retention_effect_test", SOURCE)
assert SPEC is not None and SPEC.loader is not None
ret = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ret)

REAL_LOAD_PROOF = ret._load_recovery_proof

RECENT = "a" * 64
OLDER = "b" * 64
POP = "c" * 64


def entry(sid: str, host: str, tag: str, when: int, paths=None) -> dict:
    return {
        "id": sid, "hostname": host, "tags": [tag],
        "paths": sorted(paths if paths is not None else ret.REQUIRED_PATHS),
        "time": datetime.fromtimestamp(when, timezone.utc).isoformat(),
    }


def snapshots(now: int) -> dict[str, dict]:
    return {
        RECENT: entry(RECENT, ret.HOST, ret.TAG, now - 3600),
        OLDER: entry(OLDER, ret.HOST, ret.TAG, now - 86400),
        POP: entry(POP, "heim-pc", "daily", now - 100),
    }


class RetentionEffectsTests(unittest.TestCase):
    def setUp(self) -> None:
        argv_patch = patch.object(ret.sys, "argv", ["heim-pc-restic-retention.py"])
        argv_patch.start()
        self.addCleanup(argv_patch.stop)
        self.now = int(time.time())
        self.rows = snapshots(self.now)
        self.proof = {
            "schema_version": 1,
            "kind": "heim_pc.nixos_restic_recovery_root_proof",
            "snapshot_id": RECENT,
            "snapshot_time_unix": self.now - 3600,
            "started_at_unix": self.now - 1200,
            "completed_at_unix": self.now - 900,
            "repository_id": ret.REPO_ID,
            "backup_uuid": ret.DEVICE_UUID,
            "restore_sha256": "f" * 64,
            "restore_probe_valid": True,
            "repository_check_valid": True,
        }
        proof_patch = patch.object(ret, "_load_recovery_proof", return_value=self.proof)
        proof_patch.start()
        self.addCleanup(proof_patch.stop)

    def test_recent_restic_snapshot_requires_successful_root_restore_proof(self):
        self.assertEqual(ret.latest_healthy_snapshot(self.rows, self.now), RECENT)

    def test_foreign_or_partial_backups_cannot_authorize_retention(self):
        bad = {
            POP: self.rows[POP],
            RECENT: entry(RECENT, ret.HOST, ret.TAG, self.now - 100,
                          paths={"/home/alex", "/etc"}),
        }
        with self.assertRaisesRegex(RuntimeError, "retention skipped"):
            ret.latest_healthy_snapshot(bad, self.now)

    def test_stale_or_future_backups_skip_deletion(self):
        for when in (self.now - ret.MAX_BACKUP_AGE - 1, self.now + 120):
            with self.subTest(time=when):
                row = {RECENT: entry(RECENT, ret.HOST, ret.TAG, when)}
                with self.assertRaisesRegex(RuntimeError, "retention skipped"):
                    ret.latest_healthy_snapshot(row, self.now)

    def test_latest_healthy_snapshot_is_protected_even_with_foreign_newer(self):
        rows = dict(self.rows)
        rows[POP] = entry(POP, "heim-pc", "daily", self.now - 1)
        self.assertEqual(ret.latest_healthy_snapshot(rows, self.now), RECENT)

    def test_failed_or_missing_root_proof_prevents_retention(self):
        for change in (
            {"restore_probe_valid": False},
            {"repository_check_valid": False},
            {"snapshot_id": OLDER},
            {"repository_id": "0" * 64},
            {"backup_uuid": "other"},
            {"completed_at_unix": self.now - ret.MAX_BACKUP_AGE - 1},
            {"snapshot_time_unix": self.now + 1},
        ):
            with self.subTest(change=change):
                with patch.object(ret, "_load_recovery_proof", return_value={**self.proof, **change}):
                    with self.assertRaises(RuntimeError):
                        ret.latest_healthy_snapshot(self.rows, self.now)

    def test_incomplete_snapshot_cannot_replace_verified_recovery_point(self):
        rows = dict(self.rows)
        rows["d" * 64] = entry("d" * 64, ret.HOST, ret.TAG, self.now - 30)
        # A newer incomplete snapshot has the same metadata but no root proof.
        self.assertEqual(ret.latest_healthy_snapshot(rows, self.now), RECENT)

    def test_missing_or_unsafe_root_proof_fails_closed(self):
        from unittest.mock import MagicMock
        import stat
        for mode, owner, links in (
            (stat.S_IFLNK | 0o777, 0, 1),
            (stat.S_IFREG | 0o644, 1000, 1),
            (stat.S_IFREG | 0o666, 0, 1),
            (stat.S_IFREG | 0o644, 0, 2),
        ):
            with self.subTest(mode=mode, owner=owner, links=links):
                file = MagicMock()
                file.lstat.return_value = type("Meta", (), {
                    "st_mode": mode, "st_uid": owner, "st_nlink": links
                })()
                with patch.object(ret, "ROOT_PROOF", file):
                    with self.assertRaises(RuntimeError):
                        REAL_LOAD_PROOF()

    def test_restic_lock_wait_has_matching_subprocess_deadline(self):
        from unittest.mock import patch
        with patch.object(ret, "command", return_value="") as command:
            ret.restic("snapshots", "--json", "--retry-lock=6h")
            self.assertGreater(command.call_args.kwargs["timeout"], 6 * 3600)

    def test_empty_dry_run_json_null_is_normal_and_skips_prune(self):
        # Real restic 0.18.1 returns "remove": null if nothing is deletable.
        with patch.object(ret, "restic", return_value=json.dumps([
            {"host": ret.HOST, "keep": [self.rows[RECENT]], "remove": None}
        ])) as run:
            self.assertEqual(ret.removal_plan(self.rows, RECENT), [])
            self.assertIn("--dry-run", run.call_args.args)
            self.assertIn("--tag", run.call_args.args)
            self.assertIn("--group-by", run.call_args.args)

    def test_dry_run_targets_exact_nixos_ids(self):
        groups = [{"host": ret.HOST, "remove": [self.rows[OLDER]]}]
        with patch.object(ret, "restic", return_value=json.dumps(groups)):
            self.assertEqual(ret.removal_plan(self.rows, RECENT), [OLDER])

    def test_dry_run_never_deletes_pop_or_recent_nixos_snapshot(self):
        for sid in (POP, RECENT):
            with self.subTest(snapshot=sid):
                groups = [{"remove": [self.rows[sid]]}]
                with patch.object(ret, "restic", return_value=json.dumps(groups)):
                    with self.assertRaisesRegex(RuntimeError, "protected"):
                        ret.removal_plan(self.rows, RECENT)

    def test_dry_run_unknown_or_duplicate_ids_fail_closed(self):
        for planned in ([{"id": "d" * 64}], [self.rows[OLDER], self.rows[OLDER]]):
            with self.subTest(plan=planned):
                with patch.object(ret, "restic", return_value=json.dumps([
                    {"remove": planned}
                ])):
                    with self.assertRaisesRegex(RuntimeError, "unknown or duplicate"):
                        ret.removal_plan(self.rows, RECENT)

    def test_invalid_dry_run_shape_fails_closed(self):
        with patch.object(ret, "restic", return_value=json.dumps([{"remove": {}}])):
            with self.assertRaisesRegex(RuntimeError, "invalid .*removal"):
                ret.removal_plan(self.rows, RECENT)

    def test_snapshot_inventory_waits_for_restic_lock(self):
        with patch.object(ret, "restic", return_value=json.dumps([self.rows[OLDER]])) as run:
            self.assertEqual(ret.snapshots(), {OLDER: self.rows[OLDER]})
            run.assert_called_once_with("snapshots", "--json", "--retry-lock=6h")

    def test_non_root_invocation_rejected_before_touching_repository(self):
        with patch.object(ret.os, "geteuid", return_value=1000), \
             patch.object(ret, "require_repository") as disk:
            with self.assertRaisesRegex(RuntimeError, "root-only"):
                ret.main()
            disk.assert_not_called()

    def test_no_old_snapshots_skips_forget_and_prune(self):
        with patch.object(ret.os, "geteuid", return_value=0), \
             patch.object(ret, "require_repository"), \
             patch.object(ret, "snapshots", return_value=self.rows), \
             patch.object(ret, "latest_healthy_snapshot", return_value=RECENT), \
             patch.object(ret, "removal_plan", return_value=[]), \
             patch.object(ret, "restic") as call:
            self.assertEqual(ret.main(), 0)
            call.assert_not_called()

    def test_only_exact_checked_ids_are_deleted_and_pruned(self):
        calls = []
        with patch.object(ret.os, "geteuid", return_value=0), \
             patch.object(ret, "require_repository") as disk, \
             patch.object(ret, "snapshots", return_value=self.rows), \
             patch.object(ret, "latest_healthy_snapshot", return_value=RECENT), \
             patch.object(ret, "removal_plan", return_value=[OLDER]), \
             patch.object(ret, "restic", side_effect=lambda *a, **kw: calls.append(a)):
            self.assertEqual(ret.main(), 0)
        self.assertEqual(disk.call_count, 3)
        self.assertEqual(calls, [
            ("forget", "--retry-lock=6h", OLDER),
            ("prune", "--retry-lock=6h"),
        ])

    def test_inventory_change_after_dry_run_aborts_before_deletion(self):
        with patch.object(ret.os, "geteuid", return_value=0), \
             patch.object(ret, "require_repository"), \
             patch.object(ret, "snapshots", side_effect=[
                 self.rows, {RECENT: self.rows[RECENT]}
             ]), \
             patch.object(ret, "latest_healthy_snapshot", return_value=RECENT), \
             patch.object(ret, "removal_plan", return_value=[OLDER]), \
             patch.object(ret, "restic") as call:
            with self.assertRaisesRegex(RuntimeError, "changed after dry-run"):
                ret.main()
            call.assert_not_called()

    def test_usb_disk_change_aborts_before_deletion(self):
        with patch.object(ret.os, "geteuid", return_value=0), \
             patch.object(ret, "require_repository", side_effect=[
                 None, RuntimeError("backup USB changed")
             ]) as disk, \
             patch.object(ret, "snapshots", return_value=self.rows), \
             patch.object(ret, "latest_healthy_snapshot", return_value=RECENT), \
             patch.object(ret, "removal_plan", return_value=[OLDER]), \
             patch.object(ret, "restic") as call:
            with self.assertRaisesRegex(RuntimeError, "USB changed"):
                ret.main()
            self.assertEqual(disk.call_count, 2)
            call.assert_not_called()

    def test_usb_disk_change_before_prune_never_repacks(self):
        calls = []
        with patch.object(ret.os, "geteuid", return_value=0), \
             patch.object(ret, "require_repository", side_effect=[
                 None, None, RuntimeError("backup USB changed")
             ]), \
             patch.object(ret, "snapshots", return_value=self.rows), \
             patch.object(ret, "latest_healthy_snapshot", return_value=RECENT), \
             patch.object(ret, "removal_plan", return_value=[OLDER]), \
             patch.object(ret, "restic", side_effect=lambda *a, **kw: calls.append(a)):
            with self.assertRaisesRegex(RuntimeError, "USB changed"):
                ret.main()
        self.assertEqual(calls, [("forget", "--retry-lock=6h", OLDER)])


if __name__ == "__main__":
    unittest.main()