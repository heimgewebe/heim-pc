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

    def observation(
        self,
        *,
        now: int = 100,
        pid: int = 123,
        rss_anon: int = 10 * 1024**3,
        mem_available: int = 32 * 1024**3,
    ) -> guard.Observation:
        return guard.Observation(
            observed_at_unix=now,
            pid=pid,
            active_state="active",
            control_group="/system.slice/grabowski-operator.service",
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
            state_dir.mkdir()
            state = guard.default_state(self.policy)
            state["circuit_open"] = True
            state["restart_history_unix"] = [10, 20, 30]
            (state_dir / "state.json").write_text(json.dumps(state))

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

    def test_verified_restart_requires_new_active_pid(self) -> None:
        calls: list[list[str]] = []

        def fake_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
            calls.append(argv)
            if argv[1] == "restart":
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[1] == "show":
                return self.active_show(argv, pid=456)
            raise AssertionError(argv)

        with patch.object(guard.time, "sleep", return_value=None):
            success, readback = guard._verified_restart(
                self.policy,
                123,
                fake_runner,
            )
        self.assertTrue(success)
        self.assertEqual(readback["post_pid"], 456)
        self.assertEqual(calls[0][1], "restart")


if __name__ == "__main__":
    unittest.main()