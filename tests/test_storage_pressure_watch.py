from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "storage_pressure_watch", ROOT / "scripts/storage_pressure_watch.py"
)
assert SPEC and SPEC.loader
watch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(watch)


class FakeSystemctl:
    def __init__(self, *, active: set[str] | None = None, fail_start: set[str] | None = None):
        self.active = active or set()
        self.fail_start = fail_start or set()
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        unit = argv[-1]
        if argv[:2] == ["is-active", "--quiet"]:
            return subprocess.CompletedProcess(argv, 0 if unit in self.active else 3, "", "")
        if argv[:2] == ["--no-block", "start"]:
            if unit in self.fail_start:
                return subprocess.CompletedProcess(argv, 1, "", "failed")
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(argv)


def policy() -> dict:
    return {
        "schema_version": 1,
        "kind": "heim_pc_storage_pressure_policy",
        "mountpoint": "/",
        "used_percent_threshold": 70.0,
        "available_bytes_threshold": 500 * 1024**3,
        "growth_bytes_per_hour_threshold": 32 * 1024**3,
        "minimum_growth_sample_seconds": 900,
        "service_triggers": [
            {"unit": "cargo.service", "cooldown_seconds": 21600},
            {"unit": "targets.service", "cooldown_seconds": 43200},
        ],
    }


def sample(*, observed: int, used: int, available: int, percent: float) -> dict:
    return {
        "observed_at_unix_ns": observed,
        "mountpoint": "/",
        "total_bytes": 2 * 1024**4,
        "used_bytes": used,
        "available_bytes": available,
        "used_percent": percent,
    }


class StoragePressureWatchTests(unittest.TestCase):
    def test_policy_file_is_valid(self) -> None:
        loaded = watch.load_policy(ROOT / "config/storage-pressure.v1.json")
        self.assertEqual(loaded["used_percent_threshold"], 70.0)
        self.assertEqual(loaded["available_bytes_threshold"], 500 * 1024**3)
        self.assertEqual(loaded["growth_bytes_per_hour_threshold"], 32 * 1024**3)

    def test_filesystem_percentage_matches_df_usable_denominator(self) -> None:
        fake = SimpleNamespace(
            f_frsize=4096,
            f_bsize=4096,
            f_blocks=100,
            f_bfree=40,
            f_bavail=30,
        )
        with patch.object(watch.os, "statvfs", return_value=fake):
            observed = watch.filesystem_sample("/", observed_at_unix_ns=1)
        self.assertEqual(observed["used_bytes"], 60 * 4096)
        self.assertEqual(observed["available_bytes"], 30 * 4096)
        self.assertEqual(observed["used_percent"], 66.67)

    def test_healthy_sample_does_not_start_maintenance(self) -> None:
        systemctl = FakeSystemctl()
        receipt, returncode = watch.evaluate(
            policy(),
            sample(observed=3_600_000_000_000, used=100, available=700 * 1024**3, percent=60.0),
            None,
            systemctl=systemctl,
        )
        self.assertEqual(returncode, 0)
        self.assertEqual(receipt["status"], "healthy")
        self.assertFalse(receipt["pressure"])
        self.assertEqual(systemctl.calls, [])

    def test_absolute_pressure_requests_both_services(self) -> None:
        systemctl = FakeSystemctl()
        current = sample(
            observed=7_200_000_000_000,
            used=1_600 * 1024**3,
            available=400 * 1024**3,
            percent=78.0,
        )
        receipt, returncode = watch.evaluate(policy(), current, None, systemctl=systemctl)
        self.assertEqual(returncode, 0)
        self.assertEqual(receipt["status"], "pressure-observed")
        self.assertEqual(receipt["reasons"], ["used-percent", "available-bytes"])
        self.assertEqual(
            [attempt["outcome"] for attempt in receipt["trigger_attempts"]],
            ["start-requested", "start-requested"],
        )
        self.assertEqual(
            systemctl.calls,
            [
                ["is-active", "--quiet", "cargo.service"],
                ["--no-block", "start", "cargo.service"],
                ["is-active", "--quiet", "targets.service"],
                ["--no-block", "start", "targets.service"],
            ],
        )

    def test_cooldown_prevents_repeated_heavy_runs(self) -> None:
        systemctl = FakeSystemctl()
        now_ns = 10_000_000_000_000
        previous = {
            "schema_version": 1,
            "sample": sample(observed=now_ns - 3_600_000_000_000, used=100, available=700, percent=60),
            "last_trigger_unix_by_unit": {
                "cargo.service": now_ns // 1_000_000_000 - 100,
                "targets.service": now_ns // 1_000_000_000 - 100,
            },
        }
        receipt, returncode = watch.evaluate(
            policy(),
            sample(observed=now_ns, used=200, available=100, percent=90),
            previous,
            systemctl=systemctl,
        )
        self.assertEqual(returncode, 0)
        self.assertEqual(
            [attempt["outcome"] for attempt in receipt["trigger_attempts"]],
            ["cooldown", "cooldown"],
        )
        self.assertEqual(systemctl.calls, [])

    def test_growth_rate_resets_when_filesystem_identity_changes(self) -> None:
        systemctl = FakeSystemctl()
        previous_sample = sample(
            observed=1_000_000_000_000,
            used=1_000 * 1024**3,
            available=700 * 1024**3,
            percent=60,
        )
        previous_sample["total_bytes"] += 4096
        previous = {
            "schema_version": 1,
            "sample": previous_sample,
            "last_trigger_unix_by_unit": {},
        }
        current = sample(
            observed=4_600_000_000_000,
            used=1_100 * 1024**3,
            available=600 * 1024**3,
            percent=64,
        )
        receipt, returncode = watch.evaluate(policy(), current, previous, systemctl=systemctl)
        self.assertEqual(returncode, 0)
        self.assertIsNone(receipt["growth_bytes_per_hour"])
        self.assertEqual(receipt["reasons"], [])
        self.assertEqual(systemctl.calls, [])

    def test_growth_rate_can_trigger_without_absolute_pressure(self) -> None:
        systemctl = FakeSystemctl(active={"targets.service"})
        previous = {
            "schema_version": 1,
            "sample": sample(
                observed=1_000_000_000_000,
                used=1_000 * 1024**3,
                available=700 * 1024**3,
                percent=60,
            ),
            "last_trigger_unix_by_unit": {},
        }
        current = sample(
            observed=4_600_000_000_000,
            used=1_040 * 1024**3,
            available=660 * 1024**3,
            percent=62,
        )
        receipt, returncode = watch.evaluate(policy(), current, previous, systemctl=systemctl)
        self.assertEqual(returncode, 0)
        self.assertEqual(receipt["reasons"], ["growth-rate"])
        self.assertEqual(receipt["growth_bytes_per_hour"], 40 * 1024**3)
        self.assertEqual(
            [attempt["outcome"] for attempt in receipt["trigger_attempts"]],
            ["start-requested", "already-active"],
        )

    def test_failed_start_is_terminal_failure_and_persisted(self) -> None:
        systemctl = FakeSystemctl(fail_start={"cargo.service"})
        receipt, returncode = watch.evaluate(
            policy(),
            sample(observed=8_000_000_000_000, used=1, available=1, percent=90),
            None,
            systemctl=systemctl,
        )
        self.assertEqual(returncode, 2)
        self.assertEqual(receipt["status"], "pressure-trigger-failed")
        self.assertEqual(receipt["trigger_attempts"][0]["outcome"], "start-failed")

    def test_broken_state_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state/latest.json"
            path.parent.mkdir()
            path.symlink_to(Path(temporary) / "missing")
            with self.assertRaisesRegex(watch.PressureWatchError, "unsafe"):
                watch.read_state(path)
            with self.assertRaisesRegex(watch.PressureWatchError, "unsafe"):
                watch.write_state(path, {"schema_version": 1})

    def test_state_roundtrip_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state/latest.json"
            value = {"schema_version": 1, "sample": {"used_bytes": 1}}
            watch.write_state(path, value)
            self.assertEqual(watch.read_state(path), value)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
