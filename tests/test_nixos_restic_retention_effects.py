"""Behavioural safety tests. No test uses a real backup repository."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path
import time
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "nixos/system/modules/heim-pc-restic-retention.py"
SPEC = importlib.util.spec_from_file_location("restic_retention_effect_test", SOURCE)
assert SPEC is not None and SPEC.loader is not None
ret = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ret)

CURRENT_ID = "a" * 64
OLD_ID = "b" * 64
POP_ID = "c" * 64
SNAPS = {
    CURRENT_ID: {"id": CURRENT_ID, "hostname": ret.HOST, "tags": [ret.TAG]},
    OLD_ID: {"id": OLD_ID, "hostname": ret.HOST, "tags": [ret.TAG]},
    POP_ID: {"id": POP_ID, "hostname": "heim-pc", "tags": ["daily"]},
}


def proof(now: int) -> dict:
    return {
        "kind": "heim_pc.restic_independent_full_restore.v1",
        "repository_id": ret.REPO_ID, "backup_uuid": ret.DEVICE_UUID,
        "source_host": ret.HOST, "restore_host": "recovery-host-2",
        "restore_medium": "independent-repository-copy",
        "complete_restore": True,
        "off_host_password_escrow_verified": True,
        "completed_at_unix": now - 100,
        "snapshot_id": CURRENT_ID,
        "inventory": {
            "source_sha256": "d" * 64,
            "restored_sha256": "d" * 64,
            "covered_paths": sorted(ret.REQUIRED_PATHS),
            "file_count": 4000000, "total_bytes": 150000000000,
        },
    }


class RetentionEffectsTests(unittest.TestCase):
    def setUp(self) -> None:
        # systemd invokes the root script without arguments; unittest does not.
        argv_patch = patch.object(ret.sys, "argv", ["heim-pc-restic-retention.py"])
        argv_patch.start()
        self.addCleanup(argv_patch.stop)

    def test_missing_attestation_fails_before_any_forget(self) -> None:
        with patch.object(ret.os, "geteuid", return_value=0):
            with patch.object(ret, "require_repository"):
                with patch.object(ret, "snapshots", return_value=SNAPS):
                    with patch.object(ret, "independent_proof", side_effect=FileNotFoundError):
                        with patch.object(ret, "restic") as repo_call:
                            with self.assertRaises(FileNotFoundError):
                                ret.main()
                            repo_call.assert_not_called()

    def test_no_local_machine_attestation_and_no_mismatched_inventory(self) -> None:
        now = int(time.time())
        original = proof(now)
        invalid = [
            {"restore_host": "heim-pc"},
            {"restore_host": "heim-pc-nixos"},
            {"repository_id": "0" * 64},
            {"backup_uuid": "different"},
            {"snapshot_id": POP_ID},
            {"complete_restore": False},
            {"restore_medium": "same-disk"},
            {"off_host_password_escrow_verified": False},
            {"completed_at_unix": now - 31 * 86400},
            {"inventory": {**original["inventory"], "restored_sha256": "0" * 64}},
            {"inventory": {**original["inventory"], "covered_paths": ["/home/alex"]}},
        ]
        with patch.object(ret, "command", return_value="Verified OK"):
            for override in invalid:
                with self.subTest(value=override):
                    payload = json.dumps({**original, **override}).encode()
                    with patch.object(ret, "read_trusted", return_value=payload):
                        with self.assertRaises(RuntimeError):
                            ret.independent_proof(now, SNAPS)

    def test_matching_signed_full_restore_is_valid(self) -> None:
        now = int(time.time())
        payload = json.dumps(proof(now)).encode()
        with patch.object(ret, "command", return_value="Verified OK") as openssl:
            with patch.object(ret, "read_trusted", return_value=payload):
                self.assertEqual(ret.independent_proof(now, SNAPS), CURRENT_ID)
        self.assertEqual(openssl.call_count, 1)
        self.assertEqual(openssl.call_args.args[0][0:3], ["openssl", "dgst", "-sha256"])

    def test_signed_attestation_rejects_tampered_bytes_with_real_openssl(self) -> None:
        now = int(time.time())
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private = root / "off-host-private-key.pem"
            public = root / "independent-restore-public.pem"
            attestation = root / "independent-restore.json"
            signature = root / "independent-restore.json.sig"
            attestation.write_text(json.dumps(proof(now)), encoding="utf-8")
            for argv in (
                ["openssl", "genpkey", "-algorithm", "RSA",
                 "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)],
                ["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                ["openssl", "dgst", "-sha256", "-sign", str(private),
                 "-out", str(signature), str(attestation)],
            ):
                subprocess.run(argv, check=True, capture_output=True)
            with patch.object(ret, "ATTESTATION", attestation), \
                 patch.object(ret, "SIGNATURE", signature), \
                 patch.object(ret, "PUBLIC_KEY", public), \
                 patch.object(ret, "read_trusted", side_effect=lambda p, _: p.read_bytes()):
                self.assertEqual(ret.independent_proof(now, SNAPS), CURRENT_ID)
                # Content changes but the signature does not: fail closed.
                attestation.write_text(json.dumps({**proof(now), "complete_restore": False}),
                                       encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "openssl failed"):
                    ret.independent_proof(now, SNAPS)

    def test_dry_run_rejects_pop_os_and_attested_snapshot(self) -> None:
        for record in (SNAPS[POP_ID], SNAPS[CURRENT_ID]):
            with self.subTest(snapshot=record["id"]):
                groups = [{"remove": [record], "host": ret.HOST}]
                with patch.object(ret, "restic", return_value=json.dumps(groups)):
                    with self.assertRaisesRegex(RuntimeError, "protected history"):
                        ret.removal_plan(SNAPS, CURRENT_ID)

    def test_snapshot_inventory_waits_for_exclusive_backup_or_prune_lock(self) -> None:
        with patch.object(ret, "restic", return_value=json.dumps([SNAPS[OLD_ID]])) as call:
            self.assertEqual(ret.snapshots(), {OLD_ID: SNAPS[OLD_ID]})
            call.assert_called_once_with("snapshots", "--json", "--retry-lock=6h")

    def test_dry_run_accepts_only_the_target_snapshot(self) -> None:
        groups = [{"remove": [SNAPS[OLD_ID]], "host": ret.HOST}]
        with patch.object(ret, "restic", return_value=json.dumps(groups)) as cmd:
            self.assertEqual(ret.removal_plan(SNAPS, CURRENT_ID), [OLD_ID])
            argv = cmd.call_args.args
            self.assertIn("--dry-run", argv)
            self.assertIn("--json", argv)
            self.assertIn("--host", argv)
            self.assertIn("--tag", argv)
            self.assertIn("--retry-lock=6h", argv)

    def test_non_root_command_rejected_without_looking_at_repository(self) -> None:
        with patch.object(ret.os, "geteuid", return_value=1000):
            with patch.object(ret, "require_repository") as repository:
                with self.assertRaisesRegex(RuntimeError, "root-only"):
                    ret.main()
                repository.assert_not_called()

    def test_irreversible_commands_use_exact_dry_run_ids(self) -> None:
        calls = []
        def record(*argv, **kwargs):
            calls.append(argv)
            return ""
        with patch.object(ret.os, "geteuid", return_value=0), \
             patch.object(ret, "require_repository"), \
             patch.object(ret, "snapshots", return_value=SNAPS), \
             patch.object(ret, "independent_proof", return_value=CURRENT_ID) as checked, \
             patch.object(ret, "removal_plan", return_value=[OLD_ID]), \
             patch.object(ret, "restic", side_effect=record):
            self.assertEqual(ret.main(), 0)
        self.assertEqual(calls[0], ("forget", "--retry-lock=6h", OLD_ID))
        self.assertEqual(calls[1], ("prune", "--retry-lock=6h"))
        self.assertEqual(checked.call_count, 2)

    def test_new_backup_between_dry_run_and_deletion_aborts(self) -> None:
        with patch.object(ret.os, "geteuid", return_value=0), \
             patch.object(ret, "require_repository"), \
             patch.object(ret, "snapshots", side_effect=[SNAPS, {CURRENT_ID: SNAPS[CURRENT_ID]}]), \
             patch.object(ret, "independent_proof", return_value=CURRENT_ID), \
             patch.object(ret, "removal_plan", return_value=[OLD_ID]), \
             patch.object(ret, "restic") as repo_call:
            with self.assertRaisesRegex(RuntimeError, "changed after dry-run"):
                ret.main()
            repo_call.assert_not_called()

    def test_mount_or_repository_swapped_after_dry_run_aborts_before_delete(self) -> None:
        with patch.object(ret.os, "geteuid", return_value=0), \
             patch.object(ret.sys, "argv", ["heim-pc-restic-retention.py"]), \
             patch.object(ret, "require_repository",
                          side_effect=[None, RuntimeError("repository identity changed")]) as identity, \
             patch.object(ret, "snapshots", return_value=SNAPS), \
             patch.object(ret, "independent_proof", return_value=CURRENT_ID), \
             patch.object(ret, "removal_plan", return_value=[OLD_ID]), \
             patch.object(ret, "restic") as repo_call:
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                ret.main()
            self.assertEqual(identity.call_count, 2)
            repo_call.assert_not_called()

    def test_mount_swapped_before_prune_skips_repacking(self) -> None:
        calls = []
        with patch.object(ret.os, "geteuid", return_value=0), \
             patch.object(ret.sys, "argv", ["heim-pc-restic-retention.py"]), \
             patch.object(ret, "require_repository", side_effect=[
                 None, None, RuntimeError("repository identity changed")]), \
             patch.object(ret, "snapshots", return_value=SNAPS), \
             patch.object(ret, "independent_proof", return_value=CURRENT_ID), \
             patch.object(ret, "removal_plan", return_value=[OLD_ID]), \
             patch.object(ret, "restic", side_effect=lambda *a, **k: calls.append(a)):
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                ret.main()
        self.assertEqual(calls, [("forget", "--retry-lock=6h", OLD_ID)])

    def test_empty_dry_run_skips_prune(self) -> None:
        with patch.object(ret.os, "geteuid", return_value=0), \
             patch.object(ret, "require_repository"), \
             patch.object(ret, "snapshots", return_value=SNAPS), \
             patch.object(ret, "independent_proof", return_value=CURRENT_ID), \
             patch.object(ret, "removal_plan", return_value=[]), \
             patch.object(ret, "restic") as repo_call:
            self.assertEqual(ret.main(), 0)
            repo_call.assert_not_called()


if __name__ == "__main__":
    unittest.main()