from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "grabowski_memory_guard", ROOT / "scripts/grabowski_memory_guard.py"
)
assert SPEC and SPEC.loader
guard = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = guard
SPEC.loader.exec_module(guard)


class GrabowskiMemoryGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = guard.load_policy(
            ROOT / "config/memory-pressure-guard.v1.json"
        )

    def load_state(self, path, policy):
        with guard._state_lock(path.parent, exclusive=False, create=False) as fd:
            return guard._load_state_at(fd, path.name, policy)

    def observation(
        self,
        *,
        now: int = 100,
        pid: int = 123,
        starttime_ticks: int = 100,
        rss_anon: int = 10 * 1024**3,
        mem_available: int = 32 * 1024**3,
    ) -> guard.Observation:
        return guard.Observation(
            observed_at_unix=now,
            pid=pid,
            active_state="active",
            control_group="/system.slice/grabowski-operator.service",
            process_starttime_ticks=starttime_ticks,
            rss_anon_bytes=rss_anon,
            rss_bytes=rss_anon + 16 * 1024**2,
            swap_bytes=256 * 1024**2,
            mem_available_bytes=mem_available,
            cgroup_memory_current_bytes=rss_anon + 4 * 1024**3,
            cgroup_swap_current_bytes=256 * 1024**2,
        )

    def test_policy_matches_conservative_live_thresholds(self) -> None:
        self.assertEqual(self.policy["warn_rss_anon_bytes"], 18 * 1024**3)
        self.assertEqual(self.policy["restart_rss_anon_bytes"], 24 * 1024**3)
        self.assertEqual(self.policy["emergency_mem_available_bytes"], 8 * 1024**3)
        self.assertEqual(self.policy["emergency_rss_anon_bytes"], 12 * 1024**3)
        self.assertEqual(self.policy["emergency_anon_pressure_bytes"], 24 * 1024**3)
        self.assertEqual(self.policy["confirm_samples"], 2)
        self.assertEqual(self.policy["max_restarts_per_window"], 3)

    def test_unknown_policy_field_is_rejected(self) -> None:
        raw = json.loads(
            (ROOT / "config/memory-pressure-guard.v1.json").read_text()
        )
        raw["unexpected"] = True
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            path.write_text(json.dumps(raw))
            with self.assertRaisesRegex(guard.GuardError, "unknown fields"):
                guard.load_policy(path)

    def test_sustained_rss_requires_two_samples(self) -> None:
        state = guard.default_state(self.policy)
        first, action1, reason1 = guard.evaluate(
            self.policy,
            state,
            self.observation(rss_anon=24 * 1024**3),
        )
        self.assertEqual(
            (action1, reason1),
            ("warn", "rss_restart_confirmation_pending"),
        )
        self.assertEqual(first["consecutive_over_limit"], 1)

        second, action2, reason2 = guard.evaluate(
            self.policy,
            first,
            self.observation(now=115, rss_anon=24 * 1024**3),
        )
        self.assertEqual(
            (action2, reason2),
            ("restart", "sustained_grabowski_rss"),
        )
        self.assertEqual(second["consecutive_over_limit"], 2)

    def test_pid_reuse_resets_sustained_rss_confirmation(self) -> None:
        state = guard.default_state(self.policy)
        first, action1, reason1 = guard.evaluate(
            self.policy,
            state,
            self.observation(
                pid=123,
                starttime_ticks=100,
                rss_anon=24 * 1024**3,
            ),
        )
        self.assertEqual(
            (action1, reason1),
            ("warn", "rss_restart_confirmation_pending"),
        )
        self.assertEqual(first["consecutive_over_limit"], 1)

        reused, action2, reason2 = guard.evaluate(
            self.policy,
            first,
            self.observation(
                now=115,
                pid=123,
                starttime_ticks=200,
                rss_anon=24 * 1024**3,
            ),
        )
        self.assertEqual(
            (action2, reason2),
            ("warn", "rss_restart_confirmation_pending"),
        )
        self.assertEqual(reused["consecutive_over_limit"], 1)
        self.assertEqual(reused["last_process_starttime_ticks"], 200)

        confirmed, action3, reason3 = guard.evaluate(
            self.policy,
            reused,
            self.observation(
                now=130,
                pid=123,
                starttime_ticks=200,
                rss_anon=24 * 1024**3,
            ),
        )
        self.assertEqual(
            (action3, reason3),
            ("restart", "sustained_grabowski_rss"),
        )
        self.assertEqual(confirmed["consecutive_over_limit"], 2)

    def test_warn_threshold_does_not_restart(self) -> None:
        state = guard.default_state(self.policy)
        _, action, reason = guard.evaluate(
            self.policy,
            state,
            self.observation(rss_anon=18 * 1024**3),
        )
        self.assertEqual((action, reason), ("warn", "rss_warn_threshold"))

    def test_host_emergency_restarts_immediately(self) -> None:
        state = guard.default_state(self.policy)
        _, action, reason = guard.evaluate(
            self.policy,
            state,
            self.observation(
                rss_anon=13 * 1024**3,
                mem_available=7 * 1024**3,
            ),
        )
        self.assertEqual((action, reason), ("restart", "host_memory_emergency"))

    def test_emergency_during_cooldown_opens_circuit(self) -> None:
        state = guard.default_state(self.policy)
        state["restart_history_unix"] = [90]
        _, action, reason = guard.evaluate(
            self.policy,
            state,
            self.observation(
                now=100,
                rss_anon=13 * 1024**3,
                mem_available=7 * 1024**3,
            ),
        )
        self.assertEqual(
            (action, reason),
            ("stop-circuit", "emergency_recurred_during_cooldown"),
        )

    def test_restart_rate_limit_opens_circuit(self) -> None:
        state = guard.default_state(self.policy)
        state["restart_history_unix"] = [10, 20, 30]
        _, action, reason = guard.evaluate(
            self.policy,
            state,
            self.observation(
                now=100,
                rss_anon=13 * 1024**3,
                mem_available=7 * 1024**3,
            ),
        )
        self.assertEqual(
            (action, reason),
            ("stop-circuit", "restart_rate_limit_exhausted"),
        )

    def test_existing_open_circuit_is_sticky(self) -> None:
        state = guard.default_state(self.policy)
        state["circuit_open"] = True
        _, action, reason = guard.evaluate(
            self.policy,
            state,
            self.observation(),
        )
        self.assertEqual(
            (action, reason),
            ("stop-circuit", "circuit_already_open"),
        )

    def test_validate_persistent_state_accepts_absent_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary) / "absent-state"
            result = guard.validate_persistent_state(self.policy, state_dir)
        self.assertEqual(result["status"], "valid")
        self.assertFalse(result["state_present"])
        self.assertFalse(result["circuit_open"])

    def test_validate_persistent_state_rejects_invalid_full_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary) / "state"
            state_dir.mkdir(mode=0o700)
            state = guard.default_state(self.policy)
            state["restart_history_unix"] = ["invalid"]
            (state_dir / "state.json").write_text(json.dumps(state))
            (state_dir / "state.json").chmod(0o600)
            with self.assertRaisesRegex(
                guard.GuardError,
                "restart history is invalid",
            ):
                guard.validate_persistent_state(self.policy, state_dir)

    def test_load_state_migrates_known_legacy_shape_in_memory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = guard.default_state(self.policy)
            state["last_pid"] = 123
            state["consecutive_over_limit"] = 1
            state["restart_history_unix"] = [10, 20]
            state["circuit_open"] = True
            state.pop("last_process_starttime_ticks")
            state.pop("pending_action")
            path = Path(temporary) / "state.json"
            path.write_text(json.dumps(state))
            path.chmod(0o600)

            migrated = self.load_state(path, self.policy)

        self.assertEqual(migrated["last_pid"], 123)
        self.assertEqual(migrated["last_process_starttime_ticks"], 0)
        self.assertEqual(migrated["consecutive_over_limit"], 1)
        self.assertEqual(migrated["restart_history_unix"], [10, 20])
        self.assertTrue(migrated["circuit_open"])
        self.assertIsNone(migrated["pending_action"])

    def test_load_state_migrates_pre_starttime_shape_in_memory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = guard.default_state(self.policy)
            state["last_pid"] = 123
            state["consecutive_over_limit"] = 1
            state["restart_history_unix"] = [10, 20]
            state.pop("last_process_starttime_ticks")
            path = Path(temporary) / "state.json"
            path.write_text(json.dumps(state))
            path.chmod(0o600)

            migrated = self.load_state(path, self.policy)

        self.assertEqual(migrated["last_pid"], 123)
        self.assertEqual(migrated["last_process_starttime_ticks"], 0)
        self.assertEqual(migrated["consecutive_over_limit"], 1)
        self.assertEqual(migrated["restart_history_unix"], [10, 20])
        self.assertIsNone(migrated["pending_action"])

    def test_load_state_rejects_dangling_state_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            path = base / "state.json"
            path.symlink_to(base / "missing-state.json")
            self.assertTrue(path.is_symlink())
            self.assertFalse(path.exists())

            with self.assertRaisesRegex(
                guard.GuardError,
                "unsafe guard state file",
            ):
                self.load_state(path, self.policy)

    def test_preflight_rejects_dangling_state_directory_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            state_dir = base / "state"
            state_dir.symlink_to(base / "missing-state-dir", target_is_directory=True)
            self.assertTrue(state_dir.is_symlink())
            self.assertFalse(state_dir.exists())

            with self.assertRaisesRegex(
                guard.GuardError,
                "unsafe guard state directory",
            ):
                guard.preflight(self.policy, state_dir)

    def test_cli_preflight_preserves_state_directory_symlink_for_rejection(self) -> None:
        for target_exists in (False, True):
            with self.subTest(target_exists=target_exists):
                with tempfile.TemporaryDirectory() as temporary:
                    base = Path(temporary)
                    target = base / "target-state"
                    if target_exists:
                        target.mkdir()
                    state_dir = base / "state"
                    state_dir.symlink_to(target, target_is_directory=True)

                    completed = subprocess.run(
                        [
                            sys.executable,
                            str(ROOT / "scripts/grabowski_memory_guard.py"),
                            "--policy",
                            str(ROOT / "config/memory-pressure-guard.v1.json"),
                            "--state-dir",
                            str(state_dir),
                            "--preflight-only",
                        ],
                        text=True,
                        capture_output=True,
                        check=False,
                    )

                    self.assertEqual(completed.returncode, 1)
                    self.assertIn("unsafe guard state directory", completed.stderr)
                    self.assertTrue(state_dir.is_symlink())

    def test_run_once_rejects_dangling_state_directory_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            state_dir = base / "state"
            state_dir.symlink_to(base / "missing-state-dir", target_is_directory=True)
            self.assertTrue(state_dir.is_symlink())
            self.assertFalse(state_dir.exists())

            with self.assertRaisesRegex(
                guard.GuardError,
                "unsafe guard state directory",
            ):
                guard.run_once(self.policy, state_dir)

    def test_cli_preflight_rejects_dangling_state_dir_symlink_before_systemctl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            state_dir = base / "state"
            state_dir.symlink_to(base / "missing-state-dir", target_is_directory=True)
            argv = [
                "grabowski_memory_guard.py",
                "--policy",
                str(ROOT / "config/memory-pressure-guard.v1.json"),
                "--state-dir",
                str(state_dir),
                "--preflight-only",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.object(
                    guard,
                    "_run",
                    side_effect=AssertionError("systemctl must not run"),
                ),
            ):
                self.assertEqual(guard.main(), 1)

    def test_cli_preflight_rejects_existing_state_dir_symlink_before_systemctl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            target = base / "real-state"
            target.mkdir()
            state_dir = base / "state"
            state_dir.symlink_to(target, target_is_directory=True)
            argv = [
                "grabowski_memory_guard.py",
                "--policy",
                str(ROOT / "config/memory-pressure-guard.v1.json"),
                "--state-dir",
                str(state_dir),
                "--preflight-only",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.object(
                    guard,
                    "_run",
                    side_effect=AssertionError("systemctl must not run"),
                ),
            ):
                self.assertEqual(guard.main(), 1)

    def test_cli_preflight_rejects_symlinked_state_dir_ancestor_before_systemctl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            real_parent = base / "real-parent"
            real_parent.mkdir()
            linked_parent = base / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            state_dir = linked_parent / "state"
            argv = [
                "grabowski_memory_guard.py",
                "--policy",
                str(ROOT / "config/memory-pressure-guard.v1.json"),
                "--state-dir",
                str(state_dir),
                "--preflight-only",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.object(
                    guard,
                    "_run",
                    side_effect=AssertionError("systemctl must not run"),
                ),
            ):
                self.assertEqual(guard.main(), 1)
            self.assertFalse((real_parent / "state").exists())

    def test_preflight_rejects_state_directory_with_symlinked_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            real_parent = base / "real-parent"
            real_parent.mkdir()
            linked_parent = base / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            state_dir = linked_parent / "state"

            with (
                patch.object(
                    guard,
                    "_run",
                    side_effect=AssertionError("systemctl must not run"),
                ),
                self.assertRaisesRegex(
                    guard.GuardError,
                    "unsafe guard state directory",
                ),
            ):
                guard.preflight(self.policy, state_dir)

            self.assertFalse((real_parent / "state").exists())

    def test_run_once_rejects_state_directory_with_symlinked_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            real_parent = base / "real-parent"
            real_parent.mkdir()
            linked_parent = base / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            state_dir = linked_parent / "state"

            with (
                patch.object(
                    guard,
                    "_run",
                    side_effect=AssertionError("systemctl must not run"),
                ),
                self.assertRaisesRegex(
                    guard.GuardError,
                    "unsafe guard state directory",
                ),
            ):
                guard.run_once(self.policy, state_dir)

            self.assertFalse((real_parent / "state").exists())

    def test_load_state_rejects_boolean_negative_and_unsorted_values(self) -> None:
        cases = (
            ("last_pid", True, "last_pid"),
            (
                "last_process_starttime_ticks",
                True,
                "last_process_starttime_ticks",
            ),
            (
                "last_process_starttime_ticks",
                -1,
                "last_process_starttime_ticks",
            ),
            ("consecutive_over_limit", -1, "consecutive_over_limit"),
            ("restart_history_unix", [20, 10], "restart history"),
            ("restart_history_unix", [True], "restart history"),
        )
        for field, value, pattern in cases:
            with self.subTest(field=field, value=value):
                with tempfile.TemporaryDirectory() as temporary:
                    state_dir = Path(temporary)
                    state = guard.default_state(self.policy)
                    state[field] = value
                    path = state_dir / "state.json"
                    path.write_text(json.dumps(state))
                    path.chmod(0o600)
                    with self.assertRaisesRegex(guard.GuardError, pattern):
                        self.load_state(path, self.policy)

    def test_validate_persistent_state_reports_open_circuit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary) / "state"
            state_dir.mkdir(mode=0o700)
            state = guard.default_state(self.policy)
            state["circuit_open"] = True
            (state_dir / "state.json").write_text(json.dumps(state))
            (state_dir / "state.json").chmod(0o600)
            result = guard.validate_persistent_state(self.policy, state_dir)
        self.assertTrue(result["state_present"])
        self.assertTrue(result["circuit_open"])

    def test_reset_circuit_requires_inactive_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary) / "state"

            def active_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
                return self.active_show(argv)

            with self.assertRaisesRegex(
                guard.GuardError,
                "requires the target operator to be inactive",
            ):
                guard.reset_circuit(
                    self.policy,
                    state_dir,
                    runner=active_runner,
                )

    def test_reset_circuit_clears_persistent_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary) / "state"
            state_dir.mkdir(mode=0o700)
            state = guard.default_state(self.policy)
            state["circuit_open"] = True
            state["restart_history_unix"] = [10, 20, 30]
            (state_dir / "state.json").write_text(json.dumps(state))
            (state_dir / "state.json").chmod(0o600)

            def inactive_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    "MainPID=0\n"
                    "ActiveState=inactive\n"
                    "SubState=dead\n"
                    "ControlGroup=\n",
                    "",
                )

            event = guard.reset_circuit(
                self.policy,
                state_dir,
                runner=inactive_runner,
            )
            stored = json.loads((state_dir / "state.json").read_text())
            self.assertEqual(event["action"], "reset-circuit")
            self.assertFalse(stored["circuit_open"])
            self.assertEqual(stored["restart_history_unix"], [])

    def _fake_proc(
        self,
        base: Path,
        *,
        pid: int = 123,
        process_cgroup: str = "/system.slice/grabowski-operator.service",
        rss_anon_kib: int = 13 * 1024**2,
        mem_available_kib: int = 7 * 1024**2,
    ) -> tuple[Path, Path]:
        proc = base / "proc"
        cgroup = base / "cgroup"
        process = proc / str(pid)
        process.mkdir(parents=True)
        (process / "status").write_text(
            "Name:\tpython\n"
            f"RssAnon:\t{rss_anon_kib} kB\n"
            f"VmRSS:\t{rss_anon_kib + 16384} kB\n"
            "VmSwap:\t262144 kB\n"
        )
        (process / "cgroup").write_text(f"0::{process_cgroup}\n")
        (process / "stat").write_text(
            f"{pid} (python) S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 100\n"
        )
        (proc / "meminfo").write_text(
            "MemTotal:       65740408 kB\n"
            f"MemAvailable:   {mem_available_kib} kB\n"
        )
        unit_cgroup = cgroup / "system.slice/grabowski-operator.service"
        unit_cgroup.mkdir(parents=True)
        (unit_cgroup / "memory.current").write_text(str(17 * 1024**3))
        (unit_cgroup / "memory.swap.current").write_text(str(512 * 1024**2))
        return proc, cgroup

    @staticmethod
    def active_show(argv: list[str], *, pid: int = 123) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            argv,
            0,
            f"MainPID={pid}\n"
            "ActiveState=active\n"
            "SubState=running\n"
            "ControlGroup=/system.slice/grabowski-operator.service\n",
            "",
        )

    def test_observe_rejects_process_cgroup_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proc, cgroup = self._fake_proc(
                Path(temporary),
                process_cgroup="/system.slice/other.service",
            )
            with self.assertRaisesRegex(
                guard.GuardError,
                "target process cgroup mismatch",
            ):
                guard.observe(
                    self.policy,
                    runner=self.active_show,
                    proc_root=proc,
                    cgroup_root=cgroup,
                    now_unix=100,
                )

    def test_observe_only_never_restarts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            proc, cgroup = self._fake_proc(base)
            calls: list[list[str]] = []

            def fake_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
                calls.append(argv)
                if argv[1] == "show":
                    return self.active_show(argv)
                raise AssertionError(f"unexpected mutating call: {argv}")

            result = guard.run_once(
                self.policy,
                base / "state",
                runner=fake_runner,
                proc_root=proc,
                cgroup_root=cgroup,
                allow_actions=False,
                now_unix=100,
            )
            self.assertEqual(result["action"], "restart")
            self.assertEqual(result["result"], "observe-only")
            self.assertFalse(any("restart" in call for call in calls))

    def test_unverified_restart_opens_persistent_circuit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            proc, cgroup = self._fake_proc(base)

            def fake_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
                if argv[1] == "restart":
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[1] == "show":
                    return self.active_show(argv, pid=123)
                raise AssertionError(argv)

            with (
                patch.object(guard.time, "sleep", return_value=None),
                self.assertRaisesRegex(
                    guard.GuardError,
                    "restart outcome could not be verified; circuit remains open",
                ),
            ):
                guard.run_once(
                    self.policy,
                    base / "state",
                    runner=fake_runner,
                    proc_root=proc,
                    cgroup_root=cgroup,
                    allow_actions=True,
                    now_unix=100,
                )

            stored = json.loads((base / "state/state.json").read_text())
            self.assertTrue(stored["circuit_open"])
            self.assertEqual(stored["consecutive_over_limit"], 0)
            latest = json.loads((base / "state/latest.json").read_text())
            self.assertEqual(
                latest["result"],
                "restart-outcome-unverified-circuit-open",
            )

    def test_restart_intent_is_durable_before_systemctl_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            proc, cgroup = self._fake_proc(base)
            state_path = base / "state/state.json"
            calls: list[str] = []

            def fake_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
                if argv[1] == "show":
                    pid = 456 if "restart" in calls else 123
                    return self.active_show(argv, pid=pid)
                if argv[1] == "restart":
                    prepared = json.loads(state_path.read_text())
                    self.assertTrue(prepared["circuit_open"])
                    self.assertEqual(prepared["restart_history_unix"], [100])
                    self.assertEqual(
                        prepared["pending_action"]["action"],
                        "restart",
                    )
                    self.assertEqual(prepared["pending_action"]["pid"], 123)
                    calls.append("restart")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                raise AssertionError(argv)

            with (
                patch.object(guard.time, "sleep", return_value=None),
                patch.object(guard.time, "time", return_value=100),
            ):
                result = guard.run_once(
                    self.policy,
                    base / "state",
                    runner=fake_runner,
                    proc_root=proc,
                    cgroup_root=cgroup,
                    allow_actions=True,
                    now_unix=100,
                )

            self.assertEqual(result["result"], "restarted-verified")
            final = json.loads(state_path.read_text())
            self.assertFalse(final["circuit_open"])
            self.assertIsNone(final["pending_action"])
            self.assertEqual(final["restart_history_unix"], [100])
            self.assertEqual(final["last_pid"], 456)
            self.assertEqual(final["last_process_starttime_ticks"], 0)

    def test_stale_restart_observation_does_not_mutate_or_consume_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            proc, cgroup = self._fake_proc(base)
            show_count = 0
            mutations: list[str] = []

            def fake_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
                nonlocal show_count
                if argv[1] == "show":
                    show_count += 1
                    return self.active_show(
                        argv,
                        pid=123 if show_count <= 2 else 456,
                    )
                if argv[1] == "restart":
                    mutations.append("restart")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                raise AssertionError(argv)

            result = guard.run_once(
                self.policy,
                base / "state",
                runner=fake_runner,
                proc_root=proc,
                cgroup_root=cgroup,
                allow_actions=True,
                now_unix=100,
            )

            self.assertEqual(mutations, [])
            self.assertEqual(result["result"], "restart-aborted-stale-observation")
            self.assertFalse(result["readback"]["systemctl_attempted"])
            self.assertFalse(result["readback"]["precondition_match"])
            self.assertEqual(result["readback"]["pre_pid"], 456)
            final = json.loads((base / "state/state.json").read_text())
            self.assertEqual(final["last_pid"], 456)
            self.assertEqual(final["last_process_starttime_ticks"], 0)
            self.assertEqual(final["consecutive_over_limit"], 0)
            self.assertEqual(final["restart_history_unix"], [])
            self.assertFalse(final["circuit_open"])
            self.assertIsNone(final["pending_action"])

    def test_pending_restart_reentry_stops_instead_of_restarting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            proc, cgroup = self._fake_proc(
                base,
                rss_anon_kib=8 * 1024**2,
                mem_available_kib=32 * 1024**2,
            )
            state_dir = base / "state"
            state_dir.mkdir(mode=0o700)
            state = guard.default_state(self.policy)
            state["last_pid"] = 123
            state["restart_history_unix"] = [100]
            state["circuit_open"] = True
            state["pending_action"] = {
                "action": "restart",
                "initiated_at_unix": 100,
                "pid": 123,
                "reason": "host_memory_emergency",
            }
            (state_dir / "state.json").write_text(json.dumps(state))
            (state_dir / "state.json").chmod(0o600)
            mutations: list[str] = []

            def fake_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
                if argv[1] == "show":
                    if mutations:
                        return subprocess.CompletedProcess(
                            argv,
                            0,
                            "MainPID=0\n"
                            "ActiveState=inactive\n"
                            "SubState=dead\n"
                            "ControlGroup=\n",
                            "",
                        )
                    return self.active_show(argv, pid=123)
                if argv[1] == "stop":
                    mutations.append("stop")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[1] == "restart":
                    mutations.append("restart")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                raise AssertionError(argv)

            result = guard.run_once(
                self.policy,
                state_dir,
                runner=fake_runner,
                proc_root=proc,
                cgroup_root=cgroup,
                allow_actions=True,
                now_unix=115,
            )

            self.assertEqual(mutations, ["stop"])
            self.assertEqual(result["result"], "stopped-circuit-open")
            final = json.loads((state_dir / "state.json").read_text())
            self.assertTrue(final["circuit_open"])
            self.assertIsNone(final["pending_action"])

    def test_preflight_reads_persistent_state_without_mutating_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            proc, cgroup = self._fake_proc(
                base,
                rss_anon_kib=18 * 1024**2,
                mem_available_kib=32 * 1024**2,
            )
            state_dir = base / "state"
            state_dir.mkdir(mode=0o700)
            state = guard.default_state(self.policy)
            state["last_pid"] = 123
            state["consecutive_over_limit"] = 1
            raw = json.dumps(state, sort_keys=True) + "\n"
            (state_dir / "state.json").write_text(raw)
            (state_dir / "state.json").chmod(0o600)

            event = guard.preflight(
                self.policy,
                state_dir,
                runner=self.active_show,
                proc_root=proc,
                cgroup_root=cgroup,
                now_unix=115,
            )

            self.assertEqual(event["result"], "preflight")
            self.assertEqual(event["action"], "warn")
            self.assertEqual((state_dir / "state.json").read_text(), raw)
            self.assertFalse((state_dir / "latest.json").exists())
            self.assertFalse((state_dir / "events.jsonl").exists())

    def test_systemctl_timeout_becomes_guard_error(self) -> None:
        with patch.object(
            guard.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["systemctl"], 1),
        ):
            with self.assertRaisesRegex(guard.GuardError, "command timed out"):
                guard._run(["/usr/bin/systemctl", "show", "x"], timeout_seconds=1)

    def test_nonzero_restart_returncode_is_not_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proc, _cgroup = self._fake_proc(Path(temporary))
            restarted = False

            def fake_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
                nonlocal restarted
                if argv[1] == "restart":
                    restarted = True
                    return subprocess.CompletedProcess(argv, 1, "", "failed")
                if argv[1] == "show":
                    return self.active_show(argv, pid=456 if restarted else 123)
                raise AssertionError(argv)

            with patch.object(guard.time, "sleep", return_value=None):
                success, readback = guard._verified_restart(
                    self.policy,
                    self.observation(pid=123, starttime_ticks=100),
                    fake_runner,
                    proc_root=proc,
                    before_mutation=lambda: None,
                )
        self.assertFalse(success)
        self.assertTrue(readback["systemctl_attempted"])
        self.assertEqual(readback["systemctl_returncode"], 1)
        self.assertEqual(readback["post_pid"], 456)

    def test_nonzero_stop_returncode_is_not_success(self) -> None:
        def fake_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
            if argv[1] == "stop":
                return subprocess.CompletedProcess(argv, 1, "", "failed")
            if argv[1] == "show":
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    "MainPID=0\n"
                    "ActiveState=inactive\n"
                    "SubState=dead\n"
                    "ControlGroup=\n",
                    "",
                )
            raise AssertionError(argv)

        success, readback = guard._verified_stop(self.policy, fake_runner)
        self.assertFalse(success)
        self.assertEqual(readback["systemctl_returncode"], 1)

    def test_observe_returns_none_if_mainpid_changes_mid_sample(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proc, cgroup = self._fake_proc(Path(temporary))
            shows = 0

            def fake_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
                nonlocal shows
                if argv[1] != "show":
                    raise AssertionError(argv)
                shows += 1
                return self.active_show(argv, pid=123 if shows == 1 else 456)

            result = guard.observe(
                self.policy,
                runner=fake_runner,
                proc_root=proc,
                cgroup_root=cgroup,
                now_unix=100,
            )
            self.assertIsNone(result)

    def test_observe_rejects_pid_reuse_during_proc_reads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proc, cgroup = self._fake_proc(Path(temporary))
            with (
                patch.object(
                    guard,
                    "_read_process_starttime",
                    side_effect=[100, 101],
                ),
                self.assertRaisesRegex(
                    guard.GuardError,
                    "identity changed during observation",
                ),
            ):
                guard.observe(
                    self.policy,
                    runner=self.active_show,
                    proc_root=proc,
                    cgroup_root=cgroup,
                    now_unix=100,
                )

    def test_state_directory_lock_serializes_mutators(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary) / "state"
            with (
                patch.object(guard, "STATE_LOCK_TIMEOUT_SECONDS", 0.01),
                guard._state_lock(state_dir, exclusive=True, create=True),
            ):
                with self.assertRaisesRegex(
                    guard.GuardError,
                    "state lock acquisition timed out",
                ):
                    with guard._state_lock(
                        state_dir,
                        exclusive=True,
                        create=True,
                    ):
                        self.fail("second exclusive lock unexpectedly succeeded")

    def test_verified_restart_uses_completion_time_for_cooldown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            proc, cgroup = self._fake_proc(base)
            calls: list[str] = []

            def fake_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
                if argv[1] == "show":
                    pid = 456 if "restart" in calls else 123
                    return self.active_show(argv, pid=pid)
                if argv[1] == "restart":
                    calls.append("restart")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                raise AssertionError(argv)

            with (
                patch.object(guard.time, "sleep", return_value=None),
                patch.object(guard.time, "time", return_value=145),
            ):
                result = guard.run_once(
                    self.policy,
                    base / "state",
                    runner=fake_runner,
                    proc_root=proc,
                    cgroup_root=cgroup,
                    allow_actions=True,
                    now_unix=100,
                )

            self.assertEqual(result["result"], "restarted-verified")
            final = json.loads((base / "state/state.json").read_text())
            self.assertEqual(final["restart_history_unix"], [145])

    def test_preflight_uses_persistent_confirmation_counter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            proc, cgroup = self._fake_proc(
                base,
                rss_anon_kib=24 * 1024**2,
                mem_available_kib=32 * 1024**2,
            )
            state_dir = base / "state"
            state_dir.mkdir(mode=0o700)
            state = guard.default_state(self.policy)
            state["last_pid"] = 123
            state["last_process_starttime_ticks"] = 100
            state["consecutive_over_limit"] = 1
            (state_dir / "state.json").write_text(json.dumps(state))
            (state_dir / "state.json").chmod(0o600)

            event = guard.preflight(
                self.policy,
                state_dir,
                runner=self.active_show,
                proc_root=proc,
                cgroup_root=cgroup,
                now_unix=115,
            )

            self.assertEqual(event["action"], "restart")
            self.assertEqual(event["reason"], "sustained_grabowski_rss")
            self.assertEqual(event["result"], "preflight")

    def test_locked_state_fd_survives_visible_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            proc, cgroup = self._fake_proc(
                base,
                rss_anon_kib=13 * 1024**2,
                mem_available_kib=7 * 1024**2,
            )
            state_dir = base / "state"
            moved_state_dir = base / "state-locked"
            replacement_created = False
            mutations: list[str] = []

            def fake_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
                nonlocal replacement_created
                if argv[1] == "show":
                    if not replacement_created:
                        state_dir.rename(moved_state_dir)
                        state_dir.mkdir(mode=0o700)
                        sentinel = guard.default_state(self.policy)
                        sentinel["last_pid"] = 999
                        (state_dir / "state.json").write_text(json.dumps(sentinel))
                        (state_dir / "state.json").chmod(0o600)
                        replacement_created = True
                    pid = 456 if mutations else 123
                    return self.active_show(argv, pid=pid)
                if argv[1] == "restart":
                    prepared = json.loads((moved_state_dir / "state.json").read_text())
                    self.assertTrue(prepared["circuit_open"])
                    self.assertEqual(prepared["pending_action"]["action"], "restart")
                    self.assertEqual(prepared["pending_action"]["pid"], 123)
                    replacement = json.loads((state_dir / "state.json").read_text())
                    self.assertEqual(replacement["last_pid"], 999)
                    mutations.append("restart")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                raise AssertionError(argv)

            with (
                patch.object(guard.time, "sleep", return_value=None),
                patch.object(guard.time, "time", return_value=100),
            ):
                result = guard.run_once(
                    self.policy,
                    state_dir,
                    runner=fake_runner,
                    proc_root=proc,
                    cgroup_root=cgroup,
                    allow_actions=True,
                    now_unix=100,
                )

            self.assertEqual(result["result"], "restarted-verified")
            self.assertEqual(mutations, ["restart"])
            final = json.loads((moved_state_dir / "state.json").read_text())
            self.assertEqual(final["last_pid"], 456)
            self.assertEqual(final["last_process_starttime_ticks"], 0)
            self.assertFalse(final["circuit_open"])
            self.assertIsNone(final["pending_action"])
            self.assertTrue((moved_state_dir / "latest.json").is_file())
            self.assertTrue((moved_state_dir / "events.jsonl").is_file())

            replacement = json.loads((state_dir / "state.json").read_text())
            self.assertEqual(replacement["last_pid"], 999)
            self.assertFalse((state_dir / "latest.json").exists())
            self.assertFalse((state_dir / "events.jsonl").exists())

    def test_healthy_second_tick_does_not_rewrite_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            proc, cgroup = self._fake_proc(
                base,
                rss_anon_kib=8 * 1024**2,
                mem_available_kib=32 * 1024**2,
            )
            state_dir = base / "state"

            with patch.object(
                guard,
                "_atomic_json_at",
                wraps=guard._atomic_json_at,
            ) as atomic_json:
                guard.run_once(
                    self.policy,
                    state_dir,
                    runner=self.active_show,
                    proc_root=proc,
                    cgroup_root=cgroup,
                    allow_actions=True,
                    now_unix=100,
                )
                guard.run_once(
                    self.policy,
                    state_dir,
                    runner=self.active_show,
                    proc_root=proc,
                    cgroup_root=cgroup,
                    allow_actions=True,
                    now_unix=115,
                )

            state_writes = [
                call
                for call in atomic_json.call_args_list
                if call.args[1] == "state.json"
            ]
            self.assertEqual(len(state_writes), 1)

    def test_atomic_json_fsyncs_parent_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with guard._state_lock(Path(temporary), exclusive=True, create=False) as fd:
                with patch.object(guard.os, "fsync", wraps=guard.os.fsync) as synced:
                    guard._atomic_json_at(fd, "state.json", {"ok": True})
                self.assertEqual(synced.call_args_list[-1].args, (fd,))
                self.assertGreaterEqual(synced.call_count, 2)

    def test_verified_restart_requires_new_active_pid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proc, _cgroup = self._fake_proc(Path(temporary))
            calls: list[list[str]] = []
            restarted = False

            def fake_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
                nonlocal restarted
                calls.append(argv)
                if argv[1] == "restart":
                    restarted = True
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[1] == "show":
                    return self.active_show(argv, pid=456 if restarted else 123)
                raise AssertionError(argv)

            with patch.object(guard.time, "sleep", return_value=None):
                success, readback = guard._verified_restart(
                    self.policy,
                    self.observation(pid=123, starttime_ticks=100),
                    fake_runner,
                    proc_root=proc,
                    before_mutation=lambda: None,
                )
        self.assertTrue(success)
        self.assertTrue(readback["precondition_match"])
        self.assertTrue(readback["systemctl_attempted"])
        self.assertEqual(readback["post_pid"], 456)
        self.assertEqual(calls[0][1], "show")
        self.assertEqual(calls[1][1], "restart")

    def test_verified_restart_aborts_if_pid_changes_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proc, _cgroup = self._fake_proc(Path(temporary))
            calls: list[list[str]] = []

            def fake_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
                calls.append(argv)
                if argv[1] == "show":
                    return self.active_show(argv, pid=456)
                if argv[1] == "restart":
                    self.fail("restart must not run for a stale observation")
                raise AssertionError(argv)

            success, readback = guard._verified_restart(
                self.policy,
                self.observation(pid=123, starttime_ticks=100),
                fake_runner,
                proc_root=proc,
                    before_mutation=lambda: None,
            )
        self.assertFalse(success)
        self.assertFalse(readback["precondition_match"])
        self.assertFalse(readback["systemctl_attempted"])
        self.assertEqual(readback["pre_pid"], 456)
        self.assertEqual([call[1] for call in calls], ["show"])

    def test_verified_restart_aborts_if_starttime_changes_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proc, _cgroup = self._fake_proc(Path(temporary))
            calls: list[list[str]] = []

            def fake_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
                calls.append(argv)
                if argv[1] == "show":
                    return self.active_show(argv, pid=123)
                if argv[1] == "restart":
                    self.fail("restart must not run for PID reuse")
                raise AssertionError(argv)

            success, readback = guard._verified_restart(
                self.policy,
                self.observation(pid=123, starttime_ticks=99),
                fake_runner,
                proc_root=proc,
                    before_mutation=lambda: None,
            )
        self.assertFalse(success)
        self.assertFalse(readback["precondition_match"])
        self.assertFalse(readback["systemctl_attempted"])
        self.assertEqual(readback["pre_process_starttime_ticks"], 100)
        self.assertEqual([call[1] for call in calls], ["show"])


    def test_precondition_timeout_has_no_prepared_state_or_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            proc, cgroup = self._fake_proc(base)
            shows = 0
            def runner(argv):
                nonlocal shows
                self.assertEqual(argv[1], "show")
                shows += 1
                if shows == 3:
                    raise guard.GuardError("precondition show timeout")
                return self.active_show(argv)
            try:
                result = guard.run_once(self.policy, base / "state", runner=runner,
                    proc_root=proc, cgroup_root=cgroup, now_unix=100)
            except guard.GuardError:
                result = None
            state = json.loads((base / "state/state.json").read_text())
            self.assertEqual(state["restart_history_unix"], [])
            self.assertFalse(state["circuit_open"])
            self.assertIsNone(state["pending_action"])
            self.assertIsNotNone(result)
            self.assertFalse(result["readback"]["systemctl_attempted"])
            self.assertIn("timeout", (base / "state/events.jsonl").read_text())

    def test_mutation_timeouts_and_readback_errors_are_audited(self) -> None:
        for action, fault in (("restart", "command"), ("stop", "command"),
                              ("restart", "readback"), ("stop", "readback")):
            with self.subTest(action=action, fault=fault), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                proc, cgroup = self._fake_proc(base)
                state_dir = base / "state"
                state_dir.mkdir(mode=0o700)
                state = guard.default_state(self.policy)
                state["circuit_open"] = action == "stop"
                with guard._state_lock(state_dir, exclusive=True, create=False) as fd:
                    guard._atomic_json_at(fd, "state.json", state)
                attempted = False
                def runner(argv):
                    nonlocal attempted
                    if argv[1] == action:
                        stored = json.loads((state_dir / "state.json").read_text())
                        self.assertTrue(stored["circuit_open"])
                        self.assertIsNotNone(stored["pending_action"])
                        attempted = True
                        if fault == "command":
                            raise guard.GuardError("systemctl timeout")
                        return subprocess.CompletedProcess(argv, 0, "", "")
                    if attempted:
                        raise guard.GuardError("post-mutation readback failed")
                    return self.active_show(argv)
                with patch.object(guard.time, "sleep"), self.assertRaises(guard.GuardError):
                    guard.run_once(self.policy, state_dir, runner=runner,
                        proc_root=proc, cgroup_root=cgroup, now_unix=100)
                stored = json.loads((state_dir / "state.json").read_text())
                self.assertTrue(stored["circuit_open"])
                self.assertIsNotNone(stored["pending_action"])
                event = json.loads((state_dir / "latest.json").read_text())
                self.assertIn("unverified", event["result"])
                self.assertTrue(event["readback"]["systemctl_attempted"])
                self.assertIn("error", event["readback"])
                self.assertEqual(json.loads((state_dir / "events.jsonl").read_text()), event)

    def test_pending_recovery_inactive_and_circuit_transitional_targets(self) -> None:
        for pending in ("restart", "stop-circuit"):
            for active in ("inactive", "failed", "activating", "reloading"):
                with self.subTest(pending=pending, active=active), tempfile.TemporaryDirectory() as temporary:
                    state_dir = Path(temporary)
                    state = guard.default_state(self.policy)
                    state.update(circuit_open=True, restart_history_unix=[100],
                        pending_action={"action": pending, "pid": 123,
                            "initiated_at_unix": 100, "reason": "recovery"})
                    with guard._state_lock(state_dir, exclusive=True, create=False) as fd:
                        guard._atomic_json_at(fd, "state.json", state)
                    calls = []
                    def runner(argv):
                        if argv[1] == "stop":
                            calls.append("stop")
                            return subprocess.CompletedProcess(argv, 0, "", "")
                        self.assertEqual(argv[1], "show")
                        current = "inactive" if calls else active
                        return subprocess.CompletedProcess(argv, 0,
                            f"MainPID=0\nActiveState={current}\nSubState=dead\n"
                            "ControlGroup=/system.slice/grabowski-operator.service\n", "")
                    guard.run_once(self.policy, state_dir, runner=runner, now_unix=115)
                    stored = json.loads((state_dir / "state.json").read_text())
                    self.assertIsNone(stored["pending_action"])
                    self.assertTrue(stored["circuit_open"])
                    self.assertEqual(stored["restart_history_unix"], [100])
                    self.assertEqual(calls, [] if active in {"inactive", "failed"} else ["stop"])
                    self.assertTrue((state_dir / "events.jsonl").exists())
                    calls.clear()
                    # The converged inactive target must not receive another stop.
                    guard.run_once(self.policy, state_dir,
                        runner=lambda argv: subprocess.CompletedProcess(argv, 0,
                            "MainPID=0\nActiveState=inactive\nSubState=dead\nControlGroup=\n", ""),
                        now_unix=130)

    def test_prepared_history_survives_backward_clock(self) -> None:
        state = guard.default_state(self.policy)
        state["restart_history_unix"] = [1000, 1500]
        prepared = guard._prepared_action_state(state, self.observation(now=1498),
            action="restart", reason="clock-test")
        self.assertEqual(prepared["restart_history_unix"], [1000, 1500, 1500])
        guard._validate_state_value(prepared, self.policy)

    def test_reset_recovers_corrupt_values_but_preserves_evidence(self) -> None:
        for data in ('{"broken": true}', '{broken json', '{"schema_version": 99}'):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as temporary:
                state_dir = Path(temporary)
                path = state_dir / "state.json"
                path.write_text(data)
                path.chmod(0o600)
                result = guard.reset_circuit(self.policy, state_dir,
                    runner=lambda argv: subprocess.CompletedProcess(argv, 0,
                        "MainPID=0\nActiveState=inactive\nSubState=dead\nControlGroup=\n", ""))
                self.assertEqual(result["result"], "reset")
                self.assertEqual(json.loads(path.read_text()), guard.default_state(self.policy))
                archives = list(state_dir.glob("state.corrupt.*.json"))
                self.assertEqual(len(archives), 1)
                self.assertEqual(archives[0].read_text(), data)
                self.assertIn(archives[0].name, (state_dir / "events.jsonl").read_text())

    def test_zombie_without_rss_is_disappeared_observation(self) -> None:
        for process_state in ("Z", "X"):
            with self.subTest(process_state=process_state), tempfile.TemporaryDirectory() as temporary:
                proc, cgroup = self._fake_proc(Path(temporary))
                path = proc / "123/stat"
                path.write_text(path.read_text().replace(") S ", f") {process_state} "))
                (proc / "123/status").write_text("Name:\tpython\n")
                self.assertIsNone(guard.observe(self.policy, runner=self.active_show,
                    proc_root=proc, cgroup_root=cgroup, now_unix=100))

    def test_readonly_and_mutating_state_paths_reject_unsafe_modes(self) -> None:
        for create in (False, True):
            with self.subTest(create=create), tempfile.TemporaryDirectory() as temporary:
                state_dir = Path(temporary) / "state"
                state_dir.mkdir(mode=0o777)
                state_dir.chmod(0o777)
                with self.assertRaises(guard.GuardError):
                    guard._open_state_directory_fd(state_dir, create=create)
                self.assertEqual(state_dir.stat().st_mode & 0o777, 0o777)
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            path = state_dir / "state.json"
            path.write_text(json.dumps(guard.default_state(self.policy)))
            path.chmod(0o666)
            with self.assertRaises(guard.GuardError):
                guard.validate_persistent_state(self.policy, state_dir)
            with self.assertRaises(guard.GuardError):
                guard.reset_circuit(self.policy, state_dir,
                    runner=lambda argv: subprocess.CompletedProcess(argv, 0,
                        "MainPID=0\nActiveState=inactive\nSubState=dead\nControlGroup=\n", ""))

    def test_termination_after_restart_is_deferred_through_final_state(self) -> None:
        import signal
        # Only the disposable child receives a real signal; systemctl is fake.
        for signum in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signum=signum), tempfile.TemporaryDirectory() as temporary:
                program = """
import importlib.util, os, signal, sys
from pathlib import Path
from unittest.mock import patch
spec = importlib.util.spec_from_file_location("guard_tests", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
case = module.GrabowskiMemoryGuardTests()
case.setUp()
base = Path(sys.argv[2])
proc, cgroup = case._fake_proc(base)
attempted = False
def runner(argv):
    global attempted
    if argv[1] == "restart":
        attempted = True
        os.kill(os.getpid(), int(sys.argv[3]))
        return module.subprocess.CompletedProcess(argv, 0, "", "")
    return case.active_show(argv, pid=456 if attempted else 123)
with patch.object(module.guard.time, "sleep"):
    module.guard.run_once(case.policy, base / "state", runner=runner,
        proc_root=proc, cgroup_root=cgroup, now_unix=100)
"""
                completed = subprocess.run([sys.executable, "-c", program, __file__,
                    temporary, str(int(signum))], capture_output=True, text=True, timeout=10)
                self.assertEqual(completed.returncode, -signum, completed.stderr)
                state = json.loads((Path(temporary) / "state/state.json").read_text())
                self.assertIsNone(state["pending_action"])
                self.assertFalse(state["circuit_open"])
                self.assertEqual(state["last_pid"], 456)
                event = json.loads((Path(temporary) / "state/latest.json").read_text())
                self.assertEqual(event["result"], "restarted-verified")


    def test_failed_intent_persistence_prevents_restart_and_stop(self) -> None:
        for circuit in (False, True):
            with self.subTest(circuit=circuit), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                proc, cgroup = self._fake_proc(base)
                state_dir = base / "state"
                state_dir.mkdir(mode=0o700)
                state = guard.default_state(self.policy)
                state["circuit_open"] = circuit
                with guard._state_lock(state_dir, exclusive=True, create=False) as fd:
                    guard._atomic_json_at(fd, "state.json", state)
                real_write = guard._atomic_json_at
                def fail_intent(fd, name, value):
                    if name == "state.json":
                        raise OSError("simulated storage failure")
                    return real_write(fd, name, value)
                def runner(argv):
                    self.assertEqual(argv[1], "show", "target mutation before durable intent")
                    return self.active_show(argv)
                with patch.object(guard, "_atomic_json_at", side_effect=fail_intent):
                    with self.assertRaises(OSError):
                        guard.run_once(self.policy, state_dir, runner=runner,
                            proc_root=proc, cgroup_root=cgroup, now_unix=100)
                event = json.loads((state_dir / "latest.json").read_text())
                self.assertFalse(event["readback"]["systemctl_attempted"])

    def test_state_owner_checks_apply_to_opened_fds_and_reset(self) -> None:
        import os
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            with patch.object(guard.os, "geteuid", return_value=os.geteuid() + 1):
                for create in (False, True):
                    with self.assertRaises(guard.GuardError):
                        guard._open_state_directory_fd(state_dir, create=create)
            path = state_dir / "state.json"
            path.write_text('{"corrupt": true}')
            path.chmod(0o600)
            real_fstat = guard.os.fstat
            inode = path.stat().st_ino
            def wrong_owner(fd):
                metadata = real_fstat(fd)
                if metadata.st_ino != inode:
                    return metadata
                return SimpleNamespace(st_mode=metadata.st_mode, st_dev=metadata.st_dev,
                    st_ino=metadata.st_ino, st_uid=os.geteuid()+1,
                    st_nlink=metadata.st_nlink, st_size=metadata.st_size)
            with patch.object(guard.os, "fstat", side_effect=wrong_owner):
                with self.assertRaises(guard.GuardError):
                    guard.validate_persistent_state(self.policy, state_dir)
                with self.assertRaises(guard.GuardError):
                    guard.reset_circuit(self.policy, state_dir,
                        runner=lambda argv: subprocess.CompletedProcess(argv, 0,
                            "MainPID=0\nActiveState=inactive\nSubState=dead\nControlGroup=\n", ""))
            self.assertEqual(path.read_text(), '{"corrupt": true}')
            self.assertEqual(list(state_dir.glob("state.corrupt.*.json")), [])

    def test_reset_rejects_symlinks_even_when_target_state_is_corrupt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            outside = base / "outside"
            outside.write_text("{broken")
            outside.chmod(0o600)
            state_dir = base / "state"
            state_dir.mkdir(mode=0o700)
            (state_dir / "state.json").symlink_to(outside)
            with self.assertRaises(guard.GuardError):
                guard.reset_circuit(self.policy, state_dir,
                    runner=lambda argv: subprocess.CompletedProcess(argv, 0,
                        "MainPID=0\nActiveState=inactive\nSubState=dead\nControlGroup=\n", ""))
            self.assertEqual(outside.read_text(), "{broken")
            self.assertTrue((state_dir / "state.json").is_symlink())

    def test_swapped_anonymous_pressure_requires_host_pressure(self) -> None:
        from dataclasses import replace
        state = guard.default_state(self.policy)
        sample = replace(self.observation(rss_anon=11 * 1024**3,
            mem_available=512 * 1024**2), swap_bytes=22 * 1024**3)
        _, action, reason = guard.evaluate(self.policy, state, sample)
        self.assertEqual((action, reason), ("restart", "host_memory_emergency"))
        healthy_host = replace(sample, mem_available_bytes=32 * 1024**3)
        self.assertEqual(guard.evaluate(self.policy, state, healthy_host)[1], "none")
        # Conservative RSS+Swap upper bound of all 240 historical healthy samples.
        historical_upper_bound = replace(sample, rss_anon_bytes=11 * 1024**3,
            swap_bytes=18_709_430_272 - 11 * 1024**3)
        self.assertEqual(guard.evaluate(self.policy, state, historical_upper_bound)[1], "none")
        threshold = replace(sample, swap_bytes=13 * 1024**3)
        self.assertEqual(guard.evaluate(self.policy, state, threshold)[1], "restart")
        self.assertEqual(guard.evaluate(self.policy, state,
            replace(threshold, swap_bytes=threshold.swap_bytes - 1))[1], "none")

    def test_cgroup_total_is_not_used_as_uncalibrated_child_anon_signal(self) -> None:
        from dataclasses import replace
        sample = replace(self.observation(rss_anon=4 * 1024**3,
            mem_available=512 * 1024**2), cgroup_memory_current_bytes=50 * 1024**3)
        self.assertEqual(guard.evaluate(self.policy, guard.default_state(self.policy), sample)[1], "none")


if __name__ == "__main__":
    unittest.main()
