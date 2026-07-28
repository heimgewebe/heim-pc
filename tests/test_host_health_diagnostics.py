from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

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
    def __init__(self, *, mounted: bool = False):
        self.mounted = mounted
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
            return completed(0)
        raise AssertionError(argv)


class HostHealthDiagnosticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = diagnostics.load_config(
            ROOT / "config/host-health-remediation.v1.json"
        )
        self.mce_policy = diagnostics._mce_config(self.config)

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
        self.assertIn("--dmesg", calls[0])

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

    def test_bios_contract_pins_exact_board_versions_and_hashes(self) -> None:
        bios = self.config["bios"]
        self.assertEqual(bios["board_name"], "ROG STRIX B550-F GAMING")
        self.assertEqual(bios["observed_source_version"], "3202")
        self.assertEqual(bios["targets"]["stable"]["version"], "3636")
        self.assertEqual(
            bios["targets"]["stable"]["sha256"],
            "BCB430187AD366238908C6EC6E7715C9EB056E77A620333CCBCCEDA42FB25082",
        )
        self.assertEqual(bios["targets"]["beta"]["version"], "3641")
        self.assertEqual(
            bios["targets"]["beta"]["sha256"],
            "FBA248F9F6099E55D4F194376D34C652F2971A44875BDA73ED8FEF34418C317B",
        )

    def test_bios_verifier_hashes_only_and_never_flashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "bios.cap"
            image.write_bytes(b"verified test image")
            config = copy.deepcopy(self.config)
            config["bios"]["targets"]["stable"]["sha256"] = hashlib.sha256(
                image.read_bytes()
            ).hexdigest().upper()
            returncode, report = diagnostics.verify_bios_preparation(
                config,
                target_name="stable",
                board_name="ROG STRIX B550-F GAMING",
                live_version="3202",
                image_path=image,
            )
            self.assertEqual(returncode, 0)
            self.assertTrue(report["ready_for_manual_uefi_flash"])
            self.assertFalse(report["automatic_flash"])
            self.assertTrue(report["requires_reboot_and_uefi"])

            wrong_board_code, wrong_board = diagnostics.verify_bios_preparation(
                config,
                target_name="stable",
                board_name="SOME OTHER BOARD",
                live_version="3202",
                image_path=image,
            )
            self.assertEqual(wrong_board_code, 1)
            self.assertFalse(wrong_board["ready_for_manual_uefi_flash"])


if __name__ == "__main__":
    unittest.main()
