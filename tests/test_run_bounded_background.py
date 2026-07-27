from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
from contextlib import redirect_stdout
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "run_bounded_background",
    ROOT / "scripts" / "run_bounded_background.py",
)
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class RunBoundedBackgroundTests(unittest.TestCase):
    def test_default_policy_builds_argv_only_bounded_systemd_unit(self) -> None:
        policy, policy_sha256 = runner.load_policy(ROOT / "config/runaway-guard.v1.json")
        self.assertEqual(len(policy_sha256), 64)
        with tempfile.TemporaryDirectory() as temporary:
            cwd = Path(temporary).resolve()
            unit, argv = runner.build_systemd_argv(
                name="output-smoke",
                command=["python3", "-c", "print('bounded')"],
                cwd=cwd,
                policy=policy,
                wait=True,
            )
        self.assertEqual(unit, "heim-pc-bounded-output-smoke.service")
        self.assertEqual(argv[0:3], ["systemd-run", "--user", "--collect"])
        self.assertIn("--wait", argv)
        self.assertIn("--property=KillMode=control-group", argv)
        self.assertIn("--property=RuntimeMaxSec=7200s", argv)
        self.assertIn("--property=MemoryMax=8589934592", argv)
        self.assertIn("--property=TasksMax=256", argv)
        self.assertIn("--property=LimitFSIZE=1073741824", argv)
        self.assertIn("--property=CPUWeight=50", argv)
        self.assertIn("--property=IOWeight=50", argv)
        self.assertIn("--property=StandardInput=null", argv)
        self.assertIn("--property=StandardOutput=journal", argv)
        self.assertIn("--property=StandardError=journal", argv)
        self.assertIn("--property=LogRateLimitIntervalSec=30s", argv)
        self.assertIn("--property=LogRateLimitBurst=1000", argv)
        separator = argv.index("--")
        self.assertEqual(argv[separator + 1 :], ["python3", "-c", "print('bounded')"])
        self.assertNotIn("bash", argv[:separator])
        self.assertNotIn("sh", argv[:separator])

    def test_explicit_tighter_limits_replace_defaults(self) -> None:
        policy, _ = runner.load_policy(ROOT / "config/runaway-guard.v1.json")
        with tempfile.TemporaryDirectory() as temporary:
            _, argv = runner.build_systemd_argv(
                name="tight",
                command=["/usr/bin/true"],
                cwd=Path(temporary).resolve(),
                policy=policy,
                runtime_seconds=30,
                memory_max_bytes=256 * 1024 * 1024,
                tasks_max=8,
                file_size_max_bytes=16 * 1024 * 1024,
            )
        self.assertIn("--property=RuntimeMaxSec=30s", argv)
        self.assertIn(f"--property=MemoryMax={256 * 1024 * 1024}", argv)
        self.assertIn("--property=TasksMax=8", argv)
        self.assertIn(f"--property=LimitFSIZE={16 * 1024 * 1024}", argv)

    def test_invalid_name_and_unbounded_values_fail_closed(self) -> None:
        policy, _ = runner.load_policy(ROOT / "config/runaway-guard.v1.json")
        with tempfile.TemporaryDirectory() as temporary:
            cwd = Path(temporary).resolve()
            with self.assertRaisesRegex(runner.GuardError, "name must match"):
                runner.build_systemd_argv(
                    name="bad name",
                    command=["true"],
                    cwd=cwd,
                    policy=policy,
                )
            with self.assertRaisesRegex(runner.GuardError, "runtime_seconds"):
                runner.build_systemd_argv(
                    name="zero-runtime",
                    command=["true"],
                    cwd=cwd,
                    policy=policy,
                    runtime_seconds=0,
                )

    def test_dry_run_redacts_command_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = io.StringIO()
            argv = [
                "run_bounded_background.py",
                "--name", "redaction",
                "--cwd", temporary,
                "--dry-run",
                "--",
                "/usr/bin/echo",
                "super-secret-argument",
            ]
            with patch.object(runner.sys, "argv", argv), redirect_stdout(output):
                self.assertEqual(runner.main(), 0)
        rendered = output.getvalue()
        result = json.loads(rendered)
        self.assertNotIn("super-secret-argument", rendered)
        self.assertNotIn("systemd_argv", result)
        self.assertEqual(result["command_argc"], 2)
        self.assertEqual(len(result["command_sha256"]), 64)
        self.assertEqual(len(result["systemd_argv_sha256"]), 64)

    def test_missing_command_and_non_directory_cwd_fail_closed(self) -> None:
        policy, _ = runner.load_policy(ROOT / "config/runaway-guard.v1.json")
        with tempfile.TemporaryDirectory() as temporary:
            cwd = Path(temporary).resolve()
            with self.assertRaisesRegex(runner.GuardError, "argv-only command"):
                runner.build_systemd_argv(
                    name="missing-command",
                    command=[],
                    cwd=cwd,
                    policy=policy,
                )
            with self.assertRaisesRegex(runner.GuardError, "working directory"):
                runner.build_systemd_argv(
                    name="bad-cwd",
                    command=["true"],
                    cwd=cwd / "absent",
                    policy=policy,
                )


if __name__ == "__main__":
    unittest.main()
