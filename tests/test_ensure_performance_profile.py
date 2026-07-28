from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ensure_performance_profile",
    ROOT / "scripts/ensure_performance_profile.py",
)
assert SPEC and SPEC.loader
profile = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(profile)


def completed(returncode: int, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class SequenceRunner:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        return self.results.pop(0)


class EnsurePerformanceProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = profile.load_policy(
            ROOT / "config/host-health-remediation.v1.json"
        )

    def test_success_requires_final_performance_profile(self) -> None:
        runner = SequenceRunner(
            [
                completed(0, "profile was already set\n"),
                completed(0, "Power Profile: Performance\n"),
            ]
        )
        returncode, report = profile.ensure_profile(self.policy, runner=runner)
        self.assertEqual(returncode, 0)
        self.assertTrue(report["profile_verified"])
        self.assertEqual(report["set_outcome"], "succeeded")
        self.assertEqual(len(runner.calls), 2)

    def test_missing_scsi_policy_target_is_narrowly_allowed(self) -> None:
        runner = SequenceRunner(
            [
                completed(
                    1,
                    stderr=(
                        "Errors found when setting profile:\n"
                        "- failed to set scsi host profiles: failed to set "
                        "link time power management policy "
                        "/sys/class/scsi_host/host0/link_power_management_policy: "
                        "No such file or directory (os error 2)\n"
                    ),
                ),
                completed(0, "Power Profile: Performance\n"),
            ]
        )
        returncode, report = profile.ensure_profile(self.policy, runner=runner)
        self.assertEqual(returncode, 0)
        self.assertTrue(report["success"])
        self.assertEqual(report["set_outcome"], "allowed_missing_scsi_target")

    def test_allowed_set_error_still_fails_without_final_verification(self) -> None:
        runner = SequenceRunner(
            [
                completed(
                    1,
                    stderr=(
                        "failed to set scsi host profiles: "
                        "link_power_management_policy: No such file or directory"
                    ),
                ),
                completed(0, "Power Profile: Balanced\n"),
            ]
        )
        returncode, report = profile.ensure_profile(self.policy, runner=runner)
        self.assertEqual(returncode, 1)
        self.assertFalse(report["profile_verified"])

    def test_unrelated_set_failure_is_not_hidden_by_existing_profile(self) -> None:
        runner = SequenceRunner(
            [
                completed(1, stderr="D-Bus authorization failed"),
                completed(0, "Power Profile: Performance\n"),
            ]
        )
        returncode, report = profile.ensure_profile(self.policy, runner=runner)
        self.assertEqual(returncode, 1)
        self.assertEqual(report["set_outcome"], "failed")
        self.assertTrue(report["profile_verified"])

    def test_additional_profile_failure_is_not_hidden_by_scsi_error(self) -> None:
        runner = SequenceRunner(
            [
                completed(
                    1,
                    stderr=(
                        "Errors found when setting profile:\n"
                        "- failed to set scsi host profiles: "
                        "link_power_management_policy: No such file or directory\n"
                        "- failed to set pci device profiles: permission denied\n"
                    ),
                ),
                completed(0, "Power Profile: Performance\n"),
            ]
        )
        returncode, report = profile.ensure_profile(self.policy, runner=runner)
        self.assertEqual(returncode, 1)
        self.assertEqual(report["set_outcome"], "failed")


if __name__ == "__main__":
    unittest.main()
