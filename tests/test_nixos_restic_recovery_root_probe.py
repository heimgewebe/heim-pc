from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
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

    def test_root_receipt_atomic_write_and_no_secret_content(self) -> None:
        record = {"schema_version":1,"kind":"heim_pc.nixos_restic_recovery_root_proof",
                  "restore_sha256":"b"*64}
        with tempfile.TemporaryDirectory() as state:
            with patch.object(probe, "STATE", Path(state)), patch.object(probe, "PROOF", Path(state)/"proof.json"):
                probe._write_proof(record)
                result = Path(state)/"proof.json"
                self.assertEqual(json.loads(result.read_text()), record)
                self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o644)
                self.assertEqual(list(Path(state).iterdir()), [result])

    def test_non_root_execution_rejected_before_touching_proof(self) -> None:
        with patch.object(probe.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(RuntimeError, "root-only"):
                probe.main()


if __name__ == "__main__":
    unittest.main()
