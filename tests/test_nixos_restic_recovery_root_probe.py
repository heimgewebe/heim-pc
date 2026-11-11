from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import stat
import tempfile
import unittest
from unittest.mock import patch

SOURCE_FILE = Path(__file__).resolve().parents[1] / "nixos/system/modules/heim-pc-restic-recovery-probe.py"
SPEC = importlib.util.spec_from_file_location("heim_pc_restic_root_probe_test_module", SOURCE_FILE)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def snapshot_row(timestamp: datetime) -> dict[str, object]:
    return {
        "id": "a" * 64,
        "hostname": probe.HOST,
        "time": timestamp.isoformat().replace("+00:00", "Z"),
        "tags": [probe.TAG],
        "paths": ["/etc", "/persist", "/home/alex"],
    }


class RootOwnedResticProbeTests(unittest.TestCase):
    def test_snapshot_requires_host_tag_complete_paths_and_fresh_timestamp(self) -> None:
        now = int(datetime.now(timezone.utc).timestamp())
        valid = snapshot_row(datetime.fromtimestamp(now - 600, timezone.utc))
        with patch.object(probe, "_restic", return_value=json.dumps([valid])):
            self.assertEqual(probe._snapshot(now), (valid["id"], now - 600))
        for bad in (
            {**valid, "hostname": "foreign"},
            {**valid, "tags": ["smoke"]},
            {**valid, "paths": ["/etc"]},
            {**valid, "time": "malformed"},
            snapshot_row(datetime.fromtimestamp(now - 25 * 3600, timezone.utc)),
        ):
            with self.subTest(bad=bad):
                with patch.object(probe, "_restic", return_value=json.dumps([bad])):
                    with self.assertRaises(RuntimeError):
                        probe._snapshot(now)

    def test_root_stage_restore_compares_exact_bytes_and_cleans_up(self) -> None:
        payload = b"root-owned proof\n"
        observed_stages = []

        def restic(*args, **kwargs):
            del kwargs
            if args[0] == "ls":
                return json.dumps({"message_type": "node", "path": probe.SOURCE,
                                   "type": "file", "size": len(payload)}) + "\n"
            if args[0] == "restore":
                stage = Path(args[args.index("--target") + 1])
                observed_stages.append(stage)
                restored = stage / probe.SOURCE.lstrip("/")
                restored.parent.mkdir(parents=True)
                restored.write_bytes(payload)
                return ""
            if args[0] == "dump":
                return payload
            raise AssertionError(args)

        with tempfile.TemporaryDirectory() as state:
            with patch.object(probe, "STATE", Path(state)):
                with patch.object(probe, "_restic", side_effect=restic):
                    digest = probe._restore_digest("a" * 64)
                self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
            self.assertTrue(observed_stages)
            self.assertFalse(observed_stages[0].exists())
            self.assertEqual(list(Path(state).iterdir()), [])

    def test_corrupt_dump_prevents_success(self) -> None:
        good = b"file contents"
        def restic(*args, **kwargs):
            del kwargs
            if args[0] == "ls":
                return json.dumps({"message_type":"node", "path": probe.SOURCE,
                                   "type":"file", "size":len(good)})
            if args[0] == "restore":
                path = Path(args[args.index("--target") + 1]) / probe.SOURCE.lstrip("/")
                path.parent.mkdir(parents=True)
                path.write_bytes(good)
                return ""
            if args[0] == "dump":
                return b"bad!" + good
            raise AssertionError(args)
        with tempfile.TemporaryDirectory() as state:
            with patch.object(probe, "STATE", Path(state)), patch.object(probe, "_restic", side_effect=restic):
                with self.assertRaisesRegex(RuntimeError, "restored bytes differ"):
                    probe._restore_digest("a" * 64)

    def test_symlink_restore_rejected_even_with_matching_size(self) -> None:
        payload = b"locked"
        def restic(*args, **kwargs):
            del kwargs
            if args[0] == "ls":
                return json.dumps({"message_type":"node","path":probe.SOURCE,
                                   "type":"file","size":len(payload)})
            if args[0] == "restore":
                stage = Path(args[args.index("--target") + 1])
                path = stage / probe.SOURCE.lstrip("/")
                path.parent.mkdir(parents=True)
                target = stage / "target"
                target.write_bytes(payload)
                path.symlink_to(target)
                return ""
            raise AssertionError(args)
        with tempfile.TemporaryDirectory() as state:
            with patch.object(probe, "STATE", Path(state)), patch.object(probe, "_restic", side_effect=restic):
                with self.assertRaisesRegex(RuntimeError, "restore type or size"):
                    probe._restore_digest("a" * 64)

    def test_restored_parent_symlink_cannot_escape_private_stage(self) -> None:
        payload = b"outside-stage"
        with tempfile.TemporaryDirectory() as private:
            root = Path(private)
            stage = root / "stage"
            stage.mkdir()
            outside = root / "outside"
            (outside / "secrets" / "restic").mkdir(parents=True)
            (outside / "secrets" / "restic" / "heim-pc-excludes").write_bytes(payload)
            (stage / "persist").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "restore type or size"):
                probe._read_regular_restored_bytes(
                    str(stage), probe.SOURCE, len(payload)
                )

    def test_direct_descriptor_read_rejects_symlink_or_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as private:
            root = Path(private)
            stage = root / "stage"
            stage.mkdir()
            restored = stage / probe.SOURCE.lstrip("/")
            restored.parent.mkdir(parents=True)
            payload = b"fixed"
            target = root / "target"
            target.write_bytes(payload)
            restored.symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, "restore type or size"):
                probe._read_regular_restored_bytes(str(stage), probe.SOURCE, len(payload))
            restored.unlink()
            os.link(target, restored)
            with self.assertRaisesRegex(RuntimeError, "restore type or size"):
                probe._read_regular_restored_bytes(str(stage), probe.SOURCE, len(payload))

    def test_backup_timer_requires_completed_successful_service_invocation(self) -> None:
        now = int(probe.time.time())
        keys = (
            "LoadState", "Result", "ExecMainStatus", "ExecMainCode",
            "ExecMainStartTimestamp", "ExecMainExitTimestamp",
            "ExecMainStartTimestampMonotonic", "ExecMainExitTimestampMonotonic",
            "InvocationID",
        )
        show = [
            "systemctl", "--timestamp=unix", "show",
            *[part for key in keys for part in ("-p", key)],
            "restic-backups-heim-pc.service",
        ]
        good = {
            "LoadState": "loaded", "Result": "success",
            "ExecMainStatus": "0", "ExecMainCode": "1",
            "ExecMainStartTimestamp": f"@{now - 120}",
            "ExecMainExitTimestamp": f"@{now - 60}",
            "ExecMainStartTimestampMonotonic": "27174979444",
            "ExecMainExitTimestampMonotonic": "27211406222",
            "InvocationID": "a" * 32,
        }
        cases = (
            ("real_completed_backup", good, True),
            ("never_executed", {**good, "ExecMainCode": "0",
                                "ExecMainExitTimestampMonotonic": "0"}, False),
            ("missing_completion_time", {**good, "ExecMainExitTimestampMonotonic": "0"}, False),
            ("missing_exit_code", {key: value for key, value in good.items()
                                   if key != "ExecMainCode"}, False),
            ("failed_exit", {**good, "ExecMainStatus": "1"}, False),
            ("signalled", {**good, "ExecMainCode": "2"}, False),
            ("failed_result", {**good, "Result": "exit-code"}, False),
            ("unloaded", {**good, "LoadState": "not-found"}, False),
            ("non_numeric_time", {**good, "ExecMainExitTimestampMonotonic": ""}, False),
            ("future_exit", {**good, "ExecMainExitTimestamp": f"@{now + 600}"}, False),
            ("no_start", {**good, "ExecMainStartTimestamp": "n/a"}, False),
            ("no_invocation", {**good, "InvocationID": ""}, False),
            ("inverted_monotonic", {**good, "ExecMainStartTimestampMonotonic": "27211406222"}, False),
            ("duplicate_result", {**good, "Other": "success"}, False),
        )
        for case, fields, should_succeed in cases:
            with self.subTest(case=case):
                output = "\n".join(f"{key}={value}" for key, value in fields.items()) + "\n"
                with patch.object(probe, "_command", side_effect=["", "", output]) as command:
                    if should_succeed:
                        self.assertEqual(probe._backup_timer_ready(), (
                            "a" * 32, now - 120, now - 60, 27174979444, 27211406222))
                    else:
                        with self.assertRaisesRegex(RuntimeError, "has not succeeded"):
                            probe._backup_timer_ready()
                    self.assertEqual(command.call_count, 3)
                    self.assertEqual(command.call_args_list[2].args[0], show)

    def test_snapshot_must_belong_to_completed_backup_run(self) -> None:
        now = int(probe.time.time())
        row = snapshot_row(datetime.fromtimestamp(now - 600, timezone.utc))
        run = ("a" * 32, now - 1200, now - 300, 1_000_000, 10_000_000)
        with patch.object(probe, "_restic", return_value=json.dumps([row])):
            with patch.object(probe, "_require_backup_snapshot_in_journal") as journal:
                self.assertEqual(probe._snapshot_for_backup_run(now, run),
                                 (row["id"], now - 600))
                journal.assert_called_once_with(row["id"], run)
                with self.assertRaisesRegex(RuntimeError, "not from the successful"):
                    probe._snapshot_for_backup_run(
                        now, ("b" * 32, now - 200, now - 100, 1_000_000, 10_000_000))
                journal.assert_called_once()

    def test_snapshot_journal_marker_is_bound_to_real_service_invocation(self) -> None:
        now = int(probe.time.time())
        run = ("a" * 32, now - 1200, now - 300, 1_000_000, 10_000_000)
        full_id = "cef8366c" + "1" * 56
        event = {
            "_SYSTEMD_INVOCATION_ID": run[0],
            "_SYSTEMD_UNIT": "restic-backups-heim-pc.service",
            "MESSAGE": "snapshot cef8366c saved",
            "__REALTIME_TIMESTAMP": str((now - 600) * 1_000_000 + 19),
            "__MONOTONIC_TIMESTAMP": "5500000",
        }
        expected_command = [
            "journalctl", "--system", "--no-pager", "--output=json", "-n", "300",
            "_SYSTEMD_INVOCATION_ID=" + run[0],
        ]
        cases = (
            ("actual_journal_marker", [event], True),
            ("no_markers", [{**event, "MESSAGE": "processed files"}], False),
            ("wrong_snapshot", [{**event, "MESSAGE": "snapshot deadbeef saved"}], False),
            ("wrong_invocation", [{**event, "_SYSTEMD_INVOCATION_ID": "b" * 32}], False),
            ("other_unit", [{**event, "_SYSTEMD_UNIT": "foreign.service"}], False),
            ("before_start", [{**event, "__REALTIME_TIMESTAMP":
                               str((now - 1300) * 1_000_000)}], False),
            ("after_exit", [{**event, "__REALTIME_TIMESTAMP":
                             str((now - 200) * 1_000_000)}], False),
            ("before_mono", [{**event, "__MONOTONIC_TIMESTAMP": "999999"}], False),
            ("after_mono", [{**event, "__MONOTONIC_TIMESTAMP": "11000000"}], False),
            ("non_numeric_mono", [{**event, "__MONOTONIC_TIMESTAMP": "+5500000"}], False),
            ("missing_realtime", [{k: v for k, v in event.items()
                                   if k != "__REALTIME_TIMESTAMP"}], False),
            ("double_marker", [event, event], False),
            ("foreign_row", [event, {**event, "_SYSTEMD_UNIT": "foreign.service"}], False),
            ("no_rows", [], False),
        )
        for label, rows, should_succeed in cases:
            with self.subTest(label=label):
                output = "\n".join(json.dumps(row) for row in rows)
                with patch.object(probe, "_command", return_value=output) as call:
                    if should_succeed:
                        probe._require_backup_snapshot_in_journal(full_id, run)
                    else:
                        with self.assertRaises(RuntimeError):
                            probe._require_backup_snapshot_in_journal(full_id, run)
                    call.assert_called_once_with(expected_command, timeout=30)
        with patch.object(probe, "_command", return_value="{broken") as call:
            with self.assertRaisesRegex(RuntimeError, "journal evidence is malformed"):
                probe._require_backup_snapshot_in_journal(full_id, run)
            call.assert_called_once_with(expected_command, timeout=30)

    def test_garbage_collected_backup_receipt_uses_trusted_journal(self) -> None:
        now = int(probe.time.time())
        service = "restic-backups-heim-pc.service"
        boot = "a" * 32
        invocation = "b" * 32
        start_us, end_us = (now - 600) * 1000000, (now - 60) * 1000000
        start_mono, end_mono = 1000000, 541000000

        def manager(message, marker, stamp, mono, pid="1", boot_id=boot):
            return {"_PID": pid, "_SYSTEMD_UNIT": "init.scope", "UNIT": service,
                    "MESSAGE": message, "MESSAGE_ID": marker, "_BOOT_ID": boot_id,
                    "__REALTIME_TIMESTAMP": str(stamp),
                    "__MONOTONIC_TIMESTAMP": str(mono)}

        started = manager("Starting " + service + "...",
                          "7d4958e842da4a758f6c1cdc7b36dcc5", start_us, start_mono)
        finished = manager("Finished " + service + ".",
                           "39f53479d3a045ac8e11786248231fbf", end_us, end_mono)
        snapshot = {"_SYSTEMD_UNIT": service, "_BOOT_ID": boot,
                    "_SYSTEMD_INVOCATION_ID": invocation,
                    "MESSAGE": "snapshot 81afdf3e saved",
                    "__REALTIME_TIMESTAMP": str(start_us + 2000000),
                    "__MONOTONIC_TIMESTAMP": str(start_mono + 2000000)}
        gc_fields = {
            "LoadState": "loaded", "Result": "success", "ExecMainStatus": "0",
            "ExecMainCode": "0", "InvocationID": "",
            "ExecMainStartTimestamp": "", "ExecMainExitTimestamp": "",
            "ExecMainStartTimestampMonotonic": "0",
            "ExecMainExitTimestampMonotonic": "0",
        }
        show = "\n".join(k + "=" + v for k, v in gc_fields.items())
        cases = [
            ("valid", [started, finished], [snapshot], True),
            ("newer_start", [started, finished, started], [snapshot], False),
            ("newer_failure", [started, finished, manager(
                "Failed to start " + service + ".", "", end_us + 1000000,
                end_mono + 1000000)], [snapshot], False),
            ("spoof_pid1", [{**started, "_PID": "222"}, finished], [snapshot], False),
            ("wrong_manager_message_id", [started, {**finished, "MESSAGE_ID": "bad"}],
             [snapshot], False),
            ("missing_completion", [started], [snapshot], False),
            ("missing_snapshot", [started, finished], [], False),
            ("duplicate_snapshot", [started, finished], [snapshot, snapshot], False),
            ("foreign_boot", [started, finished],
             [{**snapshot, "_BOOT_ID": "c" * 32}], False),
            ("snapshot_after_finish", [started, finished],
             [{**snapshot, "__MONOTONIC_TIMESTAMP": str(end_mono + 1)}], False),
            ("invalid_invocation", [started, finished],
             [{**snapshot, "_SYSTEMD_INVOCATION_ID": ""}], False),
        ]
        for label, manager_rows, snapshot_rows, accepted in cases:
            with self.subTest(label=label):
                manager_log = "\n".join(json.dumps(row) for row in manager_rows)
                snapshot_log = "\n".join(json.dumps(row) for row in snapshot_rows)
                calls = ["", "", show, manager_log, snapshot_log]
                with patch.object(probe, "_command", side_effect=calls) as cmd:
                    if accepted:
                        self.assertEqual(
                            probe._backup_timer_ready(),
                            (invocation, now - 600, now - 60, start_mono, end_mono),
                        )
                        self.assertEqual(cmd.call_count, 5)
                    else:
                        with self.assertRaises(RuntimeError):
                            probe._backup_timer_ready()
        with patch.object(probe, "_command",
                          side_effect=["", "", show, "{bad json"]):
            with self.assertRaisesRegex(RuntimeError, "journal is malformed"):
                probe._backup_timer_ready()

    def test_recovery_rejects_changed_systemd_invocation_before_publishing(self) -> None:
        expected = ("a" * 32, 100, 200, 100000, 300000)
        with patch.object(probe, "_backup_timer_ready", return_value=expected):
            probe._require_backup_run_unchanged(expected)
        with patch.object(probe, "_backup_timer_ready",
                          return_value=("b" * 32, 100, 200, 100000, 300000)):
            with self.assertRaisesRegex(RuntimeError, "invocation changed"):
                probe._require_backup_run_unchanged(expected)

    def test_root_receipt_atomic_write_and_no_secret_content(self) -> None:
        record = {"schema_version":1,"kind":"heim_pc.nixos_restic_recovery_root_proof",
                  "restore_sha256":"b"*64}
        with tempfile.TemporaryDirectory() as state:
            with patch.object(probe, "STATE", Path(state)), patch.object(probe, "PROOF", Path(state)/"proof.json"):
                result = Path(state)/"proof.json"
                result.write_bytes(b"previous valid proof")
                previous_inode = result.stat().st_ino
                probe._write_proof(record)
                self.assertNotEqual(result.stat().st_ino, previous_inode)
                self.assertEqual(json.loads(result.read_text()), record)
                self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o644)
                self.assertEqual(list(Path(state).iterdir()), [result])

    def test_old_proof_available_during_check_but_revoked_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as state:
            existing = Path(state) / "proof.json"
            old_proof = b'{"previous":"root-verified-snapshot"}\\n'
            existing.write_bytes(old_proof)
            def fail_after_observing_old_proof(*args, **kwargs):
                self.assertEqual(existing.read_bytes(), old_proof)
                raise RuntimeError("simulated integrity check failure")

            root_state = SimpleNamespace(
                lstat=lambda: SimpleNamespace(
                    st_mode=stat.S_IFDIR | 0o700, st_uid=0
                )
            )
            with (
                patch.object(probe.sys, "argv", ["root-proof.py"]),
                patch.object(probe, "STATE", root_state),
                patch.object(probe, "PROOF", existing),
                patch.object(probe.os, "geteuid", return_value=0),
                patch.object(probe, "_mount_identity", return_value="/dev/sda1"),
                patch.object(
                    probe, "_backup_timer_ready",
                    return_value=("a" * 32, 100, 200, 100000, 300000),
                ),
                patch.object(
                    probe, "_snapshot_for_backup_run",
                    return_value=("b" * 64, 150),
                ),
                patch.object(probe, "_restore_digest", return_value="c" * 64),
                patch.object(probe, "_next_check_part", return_value=6),
                patch.object(
                    probe, "_restic",
                    side_effect=fail_after_observing_old_proof,
                ) as restic,
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "simulated integrity check failure"
                ):
                    probe.main()
                self.assertEqual(restic.call_args.args[:2], ("check", "--read-data-subset=6/10"))
            self.assertFalse(existing.exists())

    def test_non_root_execution_rejected_before_touching_proof(self) -> None:
        with patch.object(probe.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(RuntimeError, "root-only"):
                probe.main()


if __name__ == "__main__":
    unittest.main()
