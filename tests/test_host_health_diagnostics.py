from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "host_health_diagnostics",
    ROOT / "scripts/host_health_diagnostics.py",
)
assert SPEC and SPEC.loader
diagnostics = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostics)


def completed(returncode: int, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class FatRunner:
    def __init__(self, *, mounted: bool = False, fsck_results=None):
        self.mounted = mounted
        self.fsck_results = None if fsck_results is None else list(fsck_results)
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[0] == "findmnt":
            if self.mounted:
                return completed(0, "/boot/efi /dev/test vfat rw\n")
            return completed(1)
        if argv[0] == "lsblk":
            return completed(0, "part vfat\n")
        if argv[0] == "fsck.fat":
            if self.fsck_results is None:
                return completed(0)
            if not self.fsck_results:
                raise AssertionError("unexpected extra fsck.fat call")
            return self.fsck_results.pop(0)
        raise AssertionError(argv)


def write_bios_package(path: Path, members) -> str:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for member in members:
            if len(member) == 2:
                name, data = member
                archive.writestr(name, data)
            else:
                name, data, unix_mode = member
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = unix_mode << 16
                archive.writestr(info, data)
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def bind_test_bios_package(
    config, package: Path, *, cap_name: str, cap_data: bytes
) -> None:
    target = config["bios"]["targets"]["stable"]
    target["package_sha256"] = hashlib.sha256(package.read_bytes()).hexdigest().upper()
    target["package_members"] = [cap_name, "BIOSRenamer.exe"]
    target["cap_member"] = cap_name
    target["cap_size_bytes"] = len(cap_data)


class HostHealthDiagnosticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = diagnostics.load_config(
            ROOT / "config/host-health-remediation.v1.json"
        )
        self.mce_policy = diagnostics._mce_config(self.config)
        self.tmpfiles_policy = diagnostics._tmpfiles_config(self.config)

    @staticmethod
    def record(timestamp: int, message: str, boot: str = "boot-a"):
        return {
            "__REALTIME_TIMESTAMP": str(timestamp),
            "_BOOT_ID": boot,
            "MESSAGE": message,
        }

    def test_mce_monitor_deduplicates_then_reports_recurrence(self) -> None:
        initial_state = {
            "schema_version": 1,
            "kind": "heim_pc_mce_edac_state",
            "total_occurrences": 0,
            "seen_occurrence_ids": [],
        }
        first_records = [
            self.record(1_000_000, "mce: [Hardware Error]: Machine check events logged"),
            self.record(2_000_000, "[Hardware Error]: Corrected error, no action required."),
            self.record(2_500_000, "unrelated kernel line"),
        ]
        state, report = diagnostics.analyze_mce_edac(
            first_records, initial_state, self.mce_policy
        )
        self.assertEqual(report["status"], "first_occurrence")
        self.assertEqual(report["new_occurrences"], 1)
        self.assertFalse(report["recurrent"])
        self.assertLessEqual(
            len(report["sample_messages"]), self.mce_policy["sample_message_limit"]
        )

        replay_state, replay = diagnostics.analyze_mce_edac(
            first_records, state, self.mce_policy
        )
        self.assertEqual(replay["new_occurrences"], 0)
        self.assertEqual(replay["total_occurrences"], 1)

        recurrent_records = first_records + [
            self.record(20_000_000, "EDAC MC0: 1 CE corrected error"),
        ]
        final_state, recurrent = diagnostics.analyze_mce_edac(
            recurrent_records, replay_state, self.mce_policy
        )
        self.assertEqual(recurrent["status"], "recurrent")
        self.assertTrue(recurrent["recurrent"])
        self.assertEqual(recurrent["new_occurrences"], 1)
        self.assertEqual(final_state["total_occurrences"], 2)

    def test_kernel_journal_read_is_bounded_by_policy(self) -> None:
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return completed(
                0,
                json.dumps(
                    self.record(
                        1_000_000,
                        "mce: [Hardware Error]: Machine check events logged",
                    )
                )
                + "\n",
            )

        records = diagnostics.read_bounded_kernel_journal(
            self.mce_policy, runner=runner
        )
        self.assertEqual(len(records), 1)
        self.assertIn("--lines=2000", calls[0])
        self.assertIn("--since=-24h", calls[0])
        self.assertIn("_TRANSPORT=kernel", calls[0])
        self.assertNotIn("--dmesg", calls[0])

    def test_mce_evidence_contract_must_match_query_bound(self) -> None:
        invalid = copy.deepcopy(self.config)
        invalid["mce_edac"]["constituent_evidence_limit"] = 1999
        with self.assertRaisesRegex(diagnostics.DiagnosticError, "evidence contract"):
            diagnostics._mce_config(invalid)

    def test_mce_retention_cannot_forget_entries_still_in_bounded_query(self) -> None:
        initial_state = {
            "schema_version": 1,
            "kind": "heim_pc_mce_edac_state",
            "total_occurrences": 0,
            "seen_occurrence_ids": [],
        }
        records = [
            self.record(
                index * 10_000_000,
                f"EDAC MC0: corrected error {index}",
            )
            for index in range(200)
        ]
        state, first = diagnostics.analyze_mce_edac(
            records, initial_state, self.mce_policy
        )
        replay_state, replay = diagnostics.analyze_mce_edac(
            records, state, self.mce_policy
        )
        self.assertEqual(first["new_occurrences"], 200)
        self.assertEqual(replay["new_occurrences"], 0)
        self.assertEqual(replay_state["total_occurrences"], 200)

    def test_mce_sliding_windows_keep_one_occurrence_when_first_or_last_rows_trim(
        self,
    ) -> None:
        initial_state = diagnostics._empty_mce_state()
        one_event = [
            self.record(
                1_000_000 + index * 1_000_000,
                f"[Hardware Error]: corrected constituent {index}",
            )
            for index in range(8)
        ]

        state, first = diagnostics.analyze_mce_edac(
            one_event[:5], initial_state, self.mce_policy
        )
        state, overlapping_tail = diagnostics.analyze_mce_edac(
            one_event[2:7], state, self.mce_policy
        )
        state, trimmed_prefix = diagnostics.analyze_mce_edac(
            one_event[5:], state, self.mce_policy
        )

        self.assertEqual(first["new_occurrences"], 1)
        self.assertEqual(overlapping_tail["new_occurrences"], 0)
        self.assertEqual(trimmed_prefix["new_occurrences"], 0)
        self.assertEqual(state["total_occurrences"], 1)

    def test_mce_exact_first_line_shift_does_not_create_false_recurrence(
        self,
    ) -> None:
        records = [
            self.record(
                1_000_000,
                "mce: [Hardware Error]: Machine check events logged",
            ),
            self.record(
                2_000_000,
                "[Hardware Error]: Corrected error, no action required.",
            ),
        ]
        state, first = diagnostics.analyze_mce_edac(
            records,
            diagnostics._empty_mce_state(),
            self.mce_policy,
        )
        state, shifted = diagnostics.analyze_mce_edac(
            records[1:],
            state,
            self.mce_policy,
        )
        self.assertEqual(first["new_occurrences"], 1)
        self.assertEqual(shifted["new_occurrences"], 0)
        self.assertFalse(shifted["recurrent"])
        self.assertEqual(state["total_occurrences"], 1)

    def test_mce_boundary_continuation_without_overlap_uses_persisted_span(
        self,
    ) -> None:
        first_half = [
            self.record(
                1_000_000 + index * 1_000_000,
                f"EDAC MC0: corrected error constituent {index}",
            )
            for index in range(3)
        ]
        second_half = [
            self.record(
                4_000_000 + index * 1_000_000,
                f"EDAC MC0: corrected error constituent {index + 3}",
            )
            for index in range(3)
        ]
        state, first = diagnostics.analyze_mce_edac(
            first_half, diagnostics._empty_mce_state(), self.mce_policy
        )
        state, continuation = diagnostics.analyze_mce_edac(
            second_half, state, self.mce_policy
        )
        self.assertEqual(first["new_occurrences"], 1)
        self.assertEqual(continuation["new_occurrences"], 0)
        self.assertEqual(state["total_occurrences"], 1)

    def test_mce_2000_line_sliding_boundary_is_stable_and_state_is_bounded(
        self,
    ) -> None:
        records = [
            self.record(
                1_000_000 + index * 1_000,
                f"[Hardware Error]: bounded constituent {index}",
            )
            for index in range(2001)
        ]
        state, first = diagnostics.analyze_mce_edac(
            records[:2000], diagnostics._empty_mce_state(), self.mce_policy
        )
        state, shifted = diagnostics.analyze_mce_edac(
            records[1:], state, self.mce_policy
        )
        constituent_count = sum(
            len(item["constituents"]) for item in state["occurrence_evidence"]
        )
        self.assertEqual(first["new_occurrences"], 1)
        self.assertEqual(shifted["new_occurrences"], 0)
        self.assertEqual(state["total_occurrences"], 1)
        self.assertLessEqual(
            constituent_count,
            self.mce_policy["max_journal_entries"],
        )

    def test_mce_same_message_remains_distinct_across_boots_and_real_gaps(
        self,
    ) -> None:
        message = "[Hardware Error]: corrected identical message"
        records = [
            self.record(1_000_000, message, boot="boot-a"),
            self.record(1_000_000, message, boot="boot-b"),
            self.record(20_000_000, message, boot="boot-b"),
        ]
        state, report = diagnostics.analyze_mce_edac(
            records, diagnostics._empty_mce_state(), self.mce_policy
        )
        replay_state, replay = diagnostics.analyze_mce_edac(
            records[1:], state, self.mce_policy
        )
        self.assertEqual(report["new_occurrences"], 3)
        self.assertEqual(report["total_occurrences"], 3)
        self.assertEqual(replay["new_occurrences"], 0)
        self.assertEqual(replay_state["total_occurrences"], 3)

    def test_mce_adjacent_distinct_events_beyond_gap_remain_separate(self) -> None:
        gap_us = self.mce_policy["occurrence_gap_seconds"] * 1_000_000
        records = [
            self.record(
                1_000_000,
                "[Hardware Error]: first adjacent corrected event",
            ),
            self.record(
                1_000_000 + gap_us + 1,
                "[Hardware Error]: second adjacent corrected event",
            ),
        ]
        state, report = diagnostics.analyze_mce_edac(
            records,
            diagnostics._empty_mce_state(),
            self.mce_policy,
        )
        replay_state, replay = diagnostics.analyze_mce_edac(
            records[1:],
            state,
            self.mce_policy,
        )
        self.assertEqual(report["new_occurrences"], 2)
        self.assertEqual(state["total_occurrences"], 2)
        self.assertEqual(replay["new_occurrences"], 0)
        self.assertEqual(replay_state["total_occurrences"], 2)

    def test_mce_ambiguous_boundary_match_fails_without_guessing(self) -> None:
        state = {
            "schema_version": 2,
            "kind": "heim_pc_mce_edac_state",
            "total_occurrences": 2,
            "occurrence_evidence": [
                {
                    "id": "first",
                    "boot_id": "boot-a",
                    "first_timestamp_us": 1_000_000,
                    "last_timestamp_us": 1_000_000,
                    "constituents": [],
                },
                {
                    "id": "second",
                    "boot_id": "boot-a",
                    "first_timestamp_us": 9_000_000,
                    "last_timestamp_us": 9_000_000,
                    "constituents": [],
                },
            ],
            "legacy_seen_occurrence_ids": [],
        }
        records = [
            self.record(
                5_000_000,
                "[Hardware Error]: ambiguous truncated boundary",
            )
        ]
        with self.assertRaisesRegex(
            diagnostics.DiagnosticError,
            "ambiguous MCE/EDAC boundary continuation",
        ):
            diagnostics.analyze_mce_edac(records, state, self.mce_policy)

    def test_mce_boot_grouping_survives_interleaved_realtime_clocks(self) -> None:
        records = [
            self.record(1_000_000, "[Hardware Error]: boot a first", boot="boot-a"),
            self.record(3_000_000, "[Hardware Error]: boot a second", boot="boot-a"),
            self.record(2_000_000, "[Hardware Error]: boot b first", boot="boot-b"),
            self.record(4_000_000, "[Hardware Error]: boot b second", boot="boot-b"),
        ]
        occurrences = diagnostics.group_occurrences(
            records,
            gap_seconds=self.mce_policy["occurrence_gap_seconds"],
        )
        self.assertEqual(len(occurrences), 2)
        self.assertEqual({item["boot_id"] for item in occurrences}, {"boot-a", "boot-b"})

    def test_mce_v1_state_migrates_without_recounting_visible_occurrence(self) -> None:
        records = [
            self.record(1_000_000, "mce: [Hardware Error]: Machine check events logged"),
            self.record(2_000_000, "[Hardware Error]: Corrected error"),
        ]
        occurrence = diagnostics.group_occurrences(
            records,
            gap_seconds=self.mce_policy["occurrence_gap_seconds"],
        )[0]
        legacy_state = {
            "schema_version": 1,
            "kind": "heim_pc_mce_edac_state",
            "total_occurrences": 1,
            "seen_occurrence_ids": [
                diagnostics._legacy_occurrence_id(occurrence)
            ],
        }
        state, report = diagnostics.analyze_mce_edac(
            records, legacy_state, self.mce_policy
        )
        self.assertEqual(state["schema_version"], 2)
        self.assertEqual(report["new_occurrences"], 0)
        self.assertEqual(state["total_occurrences"], 1)
        self.assertTrue(state["occurrence_evidence"])



    def test_tmpfiles_journal_reports_success_failure_and_incomplete(self) -> None:
        records = [
            self.record(1_000_000, "Starting Create Volatile Files and Directories...", boot="boot-a"),
            self.record(41_000_000, "Finished Create Volatile Files and Directories.", boot="boot-a"),
            self.record(50_000_000, "Starting Create Volatile Files and Directories...", boot="boot-b"),
            self.record(55_000_000, "systemd-tmpfiles-setup.service: Main process exited, code=killed", boot="boot-b"),
            self.record(70_000_000, "Stopped Create Volatile Files and Directories.", boot="boot-b"),
            self.record(80_000_000, "Starting Create Volatile Files and Directories...", boot="boot-c"),
        ]
        analyzed = diagnostics.analyze_tmpfiles_journal(records, self.tmpfiles_policy)
        by_boot = {item["boot_id"]: item for item in analyzed["recent_runs"]}
        self.assertEqual(by_boot["boot-a"]["status"], "success")
        self.assertEqual(by_boot["boot-a"]["duration_seconds"], 40.0)
        self.assertEqual(by_boot["boot-b"]["status"], "failed")
        self.assertEqual(by_boot["boot-b"]["duration_seconds"], 20.0)
        self.assertEqual(by_boot["boot-c"]["status"], "incomplete")
        self.assertEqual(analyzed["latest_successful_duration_seconds"], 40.0)
        self.assertEqual(analyzed["historical_max_duration_seconds"], 40.0)

    def test_tmpfiles_report_thresholds_preserve_historical_evidence(self) -> None:
        journal = {
            "recent_runs": [
                {"boot_id": "fast", "status": "success", "duration_seconds": 0.02},
                {"boot_id": "slow", "status": "success", "duration_seconds": 121.0},
            ],
            "latest_successful_duration_seconds": 0.02,
            "historical_max_duration_seconds": 121.0,
            "incomplete_or_failed_runs": 0,
        }
        inventory = {
            "groups": [],
            "matched_candidates_scanned": 0,
            "candidate_enumeration_truncated": False,
            "total_entries_bounded": 0,
            "total_bytes_bounded": 0,
            "truncated_candidate_count": 0,
            "top_offenders": [],
        }
        report = diagnostics.build_tmpfiles_boot_report(journal, inventory, self.tmpfiles_policy)
        self.assertEqual(report["status"], "healthy")
        self.assertEqual(report["history_status"], "critical")
        self.assertEqual(report["historical_incident_count"], 1)
        self.assertTrue(report["read_only"])
        self.assertIn(
            "tmpfiles_duration_critical",
            {item["code"] for item in report["historical_reasons"]},
        )

    def test_tmpfiles_latest_critical_controls_current_status(self) -> None:
        journal = {
            "recent_runs": [
                {"boot_id": "now", "status": "success", "duration_seconds": 130.0}
            ],
            "latest_successful_duration_seconds": 130.0,
            "historical_max_duration_seconds": 130.0,
            "incomplete_or_failed_runs": 0,
        }
        inventory = {
            "groups": [],
            "matched_candidates_scanned": 0,
            "candidate_enumeration_truncated": False,
            "total_entries_bounded": 0,
            "total_bytes_bounded": 0,
            "truncated_candidate_count": 0,
            "top_offenders": [],
        }
        report = diagnostics.build_tmpfiles_boot_report(
            journal, inventory, self.tmpfiles_policy
        )
        self.assertEqual(report["status"], "critical")
        self.assertEqual(report["history_status"], "healthy")

    def test_tmpfiles_candidate_mount_is_not_traversed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory)
            device = candidate.lstat().st_dev
            report = diagnostics._bounded_tree_metrics(
                candidate, entry_limit=100, expected_device=device + 1
            )
            self.assertEqual(report["status"], "skipped_mount")
            self.assertEqual(report["entries"], 0)
            self.assertEqual(report["skipped_mounts"], 1)

    def test_tmpfiles_journal_query_is_bounded(self) -> None:
        calls = []
        def runner(argv, **kwargs):
            calls.append(argv)
            return completed(0, "")
        diagnostics.read_bounded_tmpfiles_journal(self.tmpfiles_policy, runner=runner)
        self.assertIn("--unit=systemd-tmpfiles-setup.service", calls[0])
        self.assertIn("--lines=2000", calls[0])
        self.assertIn("--since=-168h", calls[0])
        self.assertIn("--output=json", calls[0])

    def test_tmpfiles_config_rejects_unbounded_unknown_candidate_pattern(self) -> None:
        invalid = copy.deepcopy(self.config)
        invalid["tmpfiles_boot"]["candidates"][0]["pattern"] = "**"
        with self.assertRaisesRegex(diagnostics.DiagnosticError, "unsupported"):
            diagnostics._tmpfiles_config(invalid)

    def test_tmpfiles_config_rejects_reversed_duration_thresholds(self) -> None:
        invalid = copy.deepcopy(self.config)
        invalid["tmpfiles_boot"]["critical_seconds"] = 10
        with self.assertRaisesRegex(diagnostics.DiagnosticError, "critical_seconds"):
            diagnostics._tmpfiles_config(invalid)

    def test_tmpfiles_scan_is_bounded_and_does_not_follow_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            tmp_root = base / "tmp"
            var_tmp_root = base / "var-tmp"
            outside = base / "outside"
            tmp_root.mkdir()
            var_tmp_root.mkdir()
            outside.mkdir()
            private = tmp_root / "systemd-private-test"
            private.mkdir()
            for index in range(20):
                (private / f"entry-{index}").write_bytes(b"x" * 10)
            (outside / "large").write_bytes(b"x" * 100000)
            (private / "outside-link").symlink_to(outside, target_is_directory=True)
            flatpak = var_tmp_root / "flatpak-cache-test"
            flatpak.mkdir()
            (flatpak / "small").write_bytes(b"abc")
            policy = copy.deepcopy(self.tmpfiles_policy)
            policy["max_entries_per_candidate"] = 10
            inventory = diagnostics.scan_tmpfiles_candidates(
                policy,
                root_overrides={"/tmp": tmp_root, "/var/tmp": var_tmp_root},
            )
            self.assertGreaterEqual(inventory["matched_candidates_scanned"], 2)
            self.assertGreaterEqual(inventory["truncated_candidate_count"], 1)
            candidates = [item for group in inventory["groups"] for item in group["candidates"]]
            private_report = next(item for item in candidates if item["path"].endswith("systemd-private-test"))
            self.assertTrue(private_report["truncated"])
            self.assertLess(private_report["bytes"], 100000)

    def test_kvm_truth_distinguishes_bios_flag_from_module_failure(self) -> None:
        bios_disabled = diagnostics.evaluate_kvm_svm(
            vendor="AuthenticAMD",
            flags={"sse", "avx"},
            kvm_module=True,
            vendor_module=False,
            dev_kvm=False,
        )
        self.assertEqual(
            bios_disabled["status"], "bios_virtualization_disabled_or_hidden"
        )
        self.assertFalse(bios_disabled["kernel_module_failure"])
        self.assertFalse(bios_disabled["automatic_bios_fix"])

        module_failure = diagnostics.evaluate_kvm_svm(
            vendor="AuthenticAMD",
            flags={"svm", "sse"},
            kvm_module=True,
            vendor_module=False,
            dev_kvm=False,
        )
        self.assertEqual(module_failure["status"], "kernel_vendor_module_missing")
        self.assertTrue(module_failure["kernel_module_failure"])

        ready = diagnostics.evaluate_kvm_svm(
            vendor="AuthenticAMD",
            flags={"svm"},
            kvm_module=True,
            vendor_module=True,
            dev_kvm=True,
        )
        self.assertEqual(ready["status"], "ready")

    def test_fat_path_refuses_mounted_filesystem_before_fsck(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            device = Path(directory) / "partition"
            device.write_bytes(b"fixture")
            runner = FatRunner(mounted=True)
            with self.assertRaisesRegex(diagnostics.DiagnosticError, "mounted"):
                diagnostics.fat_check_or_repair(
                    device,
                    repair=False,
                    confirmed=False,
                    runner=runner,
                    require_block_device=False,
                )
            self.assertFalse(any(argv[0] == "fsck.fat" for argv in runner.calls))

    def test_fat_check_and_explicit_repair_use_safe_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            device = Path(directory) / "partition"
            device.write_bytes(b"fixture")
            check_runner = FatRunner()
            returncode, report = diagnostics.fat_check_or_repair(
                device,
                repair=False,
                confirmed=False,
                runner=check_runner,
                require_block_device=False,
            )
            self.assertEqual(returncode, 0)
            self.assertIn(
                ["fsck.fat", "-n", str(device.resolve())], check_runner.calls
            )
            self.assertFalse(report["online_modification_allowed"])

            with self.assertRaisesRegex(diagnostics.DiagnosticError, "confirm"):
                diagnostics.fat_check_or_repair(
                    device,
                    repair=True,
                    confirmed=False,
                    runner=FatRunner(),
                    require_block_device=False,
                )
            repair_runner = FatRunner()
            diagnostics.fat_check_or_repair(
                device,
                repair=True,
                confirmed=True,
                runner=repair_runner,
                require_block_device=False,
            )
            self.assertIn(
                ["fsck.fat", "-a", str(device.resolve())], repair_runner.calls
            )
            self.assertIn(
                ["fsck.fat", "-n", str(device.resolve())], repair_runner.calls
            )

    def test_fat_check_rc_one_reports_inconsistencies_with_bounded_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            device = Path(directory) / "partition"
            device.write_bytes(b"fixture")
            runner = FatRunner(
                fsck_results=[
                    completed(
                        1,
                        "€" * diagnostics.FSCK_OUTPUT_LIMIT_BYTES,
                        "inconsistency detail",
                    )
                ]
            )
            returncode, report = diagnostics.fat_check_or_repair(
                device,
                repair=False,
                confirmed=False,
                runner=runner,
                require_block_device=False,
            )
            self.assertEqual(returncode, 1)
            self.assertFalse(report["success"])
            self.assertEqual(report["status"], "inconsistencies_detected")
            self.assertEqual(report["check_returncode"], 1)
            self.assertIsNone(report["verification_returncode"])
            self.assertTrue(report["passes"][0]["stdout_truncated"])
            self.assertLessEqual(
                len(report["passes"][0]["stdout"].encode("utf-8")),
                diagnostics.FSCK_OUTPUT_LIMIT_BYTES,
            )
            self.assertEqual(report["passes"][0]["stderr"], "inconsistency detail")

    def test_fat_repair_rc_one_requires_clean_read_only_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            device = Path(directory) / "partition"
            device.write_bytes(b"fixture")
            runner = FatRunner(
                fsck_results=[
                    completed(1, "repair made changes"),
                    completed(0, "verification clean"),
                ]
            )
            returncode, report = diagnostics.fat_check_or_repair(
                device,
                repair=True,
                confirmed=True,
                runner=runner,
                require_block_device=False,
            )
            self.assertEqual(returncode, 0)
            self.assertTrue(report["success"])
            self.assertEqual(report["status"], "repair_verified_clean")
            self.assertEqual(report["repair_returncode"], 1)
            self.assertEqual(report["verification_returncode"], 0)
            self.assertEqual(
                [item["mode"] for item in report["passes"]],
                ["repair", "verification"],
            )
            self.assertEqual(report["passes"][0]["stdout"], "repair made changes")
            self.assertEqual(report["passes"][1]["stdout"], "verification clean")

    def test_fat_repair_fails_when_verification_is_not_clean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            device = Path(directory) / "partition"
            device.write_bytes(b"fixture")
            runner = FatRunner(
                fsck_results=[completed(0, "repair"), completed(1, "still dirty")]
            )
            returncode, report = diagnostics.fat_check_or_repair(
                device,
                repair=True,
                confirmed=True,
                runner=runner,
                require_block_device=False,
            )
            self.assertEqual(returncode, 1)
            self.assertFalse(report["success"])
            self.assertEqual(
                report["status"], "repair_verification_inconsistencies_detected"
            )
            self.assertEqual(report["repair_returncode"], 0)
            self.assertEqual(report["verification_returncode"], 1)

    def test_fat_rc_two_is_failure_and_skips_repair_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            device = Path(directory) / "partition"
            device.write_bytes(b"fixture")
            runner = FatRunner(fsck_results=[completed(2, stderr="usage failure")])
            returncode, report = diagnostics.fat_check_or_repair(
                device,
                repair=True,
                confirmed=True,
                runner=runner,
                require_block_device=False,
            )
            self.assertEqual(returncode, 1)
            self.assertFalse(report["success"])
            self.assertEqual(report["status"], "repair_failed")
            self.assertEqual(report["repair_returncode"], 2)
            self.assertIsNone(report["verification_returncode"])
            self.assertEqual(len(report["passes"]), 1)

    def test_bios_contract_pins_exact_board_versions_and_hashes(self) -> None:
        bios = self.config["bios"]
        self.assertEqual(bios["board_name"], "ROG STRIX B550-F GAMING")
        self.assertEqual(bios["observed_source_version"], "3202")
        self.assertEqual(bios["targets"]["stable"]["version"], "3636")
        self.assertEqual(
            bios["targets"]["stable"]["package_sha256"],
            "BCB430187AD366238908C6EC6E7715C9EB056E77A620333CCBCCEDA42FB25082",
        )
        self.assertEqual(
            bios["targets"]["stable"]["cap_member"],
            "ROG-STRIX-B550-F-GAMING-ASUS-3636.CAP",
        )
        self.assertEqual(bios["targets"]["beta"]["version"], "3641")
        self.assertEqual(
            bios["targets"]["beta"]["package_sha256"],
            "FBA248F9F6099E55D4F194376D34C652F2971A44875BDA73ED8FEF34418C317B",
        )

    def test_bios_verifier_validates_package_and_derives_cap_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "bios.zip"
            cap_name = "ROG-STRIX-B550-F-GAMING-ASUS-3636.CAP"
            cap_data = b"verified test CAP"
            write_bios_package(
                package,
                [(cap_name, cap_data), ("BIOSRenamer.exe", b"renamer")],
            )
            config = copy.deepcopy(self.config)
            bind_test_bios_package(
                config, package, cap_name=cap_name, cap_data=cap_data
            )
            returncode, report = diagnostics.verify_bios_preparation(
                config,
                target_name="stable",
                board_name="ROG STRIX B550-F GAMING",
                live_version="3202",
                package_path=package,
            )
            self.assertEqual(returncode, 0)
            self.assertTrue(report["package_hash_matches"])
            self.assertEqual(
                report["cap_sha256"],
                hashlib.sha256(cap_data).hexdigest().upper(),
            )
            self.assertEqual(
                report["cap_sha256_provenance"],
                "locally_derived_from_verified_package",
            )
            self.assertTrue(report["ready_for_manual_uefi_flash"])
            self.assertFalse(report["automatic_flash"])
            self.assertTrue(report["requires_reboot_and_uefi"])

            wrong_board_code, wrong_board = diagnostics.verify_bios_preparation(
                config,
                target_name="stable",
                board_name="SOME OTHER BOARD",
                live_version="3202",
                package_path=package,
            )
            self.assertEqual(wrong_board_code, 1)
            self.assertFalse(wrong_board["ready_for_manual_uefi_flash"])

    def test_bios_verifier_rejects_wrong_package_digest_without_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "not-a-zip"
            package.write_bytes(b"not a ZIP package")
            returncode, report = diagnostics.verify_bios_preparation(
                self.config,
                target_name="stable",
                board_name="ROG STRIX B550-F GAMING",
                live_version="3202",
                package_path=package,
            )
            self.assertEqual(returncode, 1)
            self.assertFalse(report["package_hash_matches"])
            self.assertIsNone(report["package_members"])
            self.assertIsNone(report["cap_sha256"])

    def test_bios_verifier_rejects_unsafe_or_ambiguous_members(self) -> None:
        cap_name = "ROG-STRIX-B550-F-GAMING-ASUS-3636.CAP"
        cap_data = b"test CAP"
        cases = {
            "traversal": (
                [
                    (cap_name, cap_data),
                    ("BIOSRenamer.exe", b"renamer"),
                    ("../escape.CAP", b"escape"),
                ],
                "unsafe BIOS package member name",
            ),
            "symlink": (
                [
                    (cap_name, b"target", stat.S_IFLNK | 0o777),
                    ("BIOSRenamer.exe", b"renamer"),
                ],
                "unsafe BIOS package member type",
            ),
            "unexpected": (
                [
                    (cap_name, cap_data),
                    ("BIOSRenamer.exe", b"renamer"),
                    ("extra.txt", b"extra"),
                ],
                "unexpected member names",
            ),
            "missing_cap": (
                [("BIOSRenamer.exe", b"renamer")],
                "exactly one expected CAP member",
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            for label, (members, error) in cases.items():
                with self.subTest(label=label):
                    package = Path(directory) / f"{label}.zip"
                    write_bios_package(package, members)
                    config = copy.deepcopy(self.config)
                    bind_test_bios_package(
                        config, package, cap_name=cap_name, cap_data=cap_data
                    )
                    with self.assertRaisesRegex(diagnostics.DiagnosticError, error):
                        diagnostics.verify_bios_preparation(
                            config,
                            target_name="stable",
                            board_name="ROG STRIX B550-F GAMING",
                            live_version="3202",
                            package_path=package,
                        )

    def test_bios_verifier_rejects_duplicate_member_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "duplicate.zip"
            cap_name = "ROG-STRIX-B550-F-GAMING-ASUS-3636.CAP"
            cap_data = b"test CAP"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                write_bios_package(
                    package,
                    [
                        (cap_name, cap_data),
                        (cap_name, cap_data),
                        ("BIOSRenamer.exe", b"renamer"),
                    ],
                )
            config = copy.deepcopy(self.config)
            bind_test_bios_package(
                config, package, cap_name=cap_name, cap_data=cap_data
            )
            with self.assertRaisesRegex(
                diagnostics.DiagnosticError, "duplicate member names"
            ):
                diagnostics.verify_bios_preparation(
                    config,
                    target_name="stable",
                    board_name="ROG STRIX B550-F GAMING",
                    live_version="3202",
                    package_path=package,
                )


if __name__ == "__main__":
    unittest.main()
