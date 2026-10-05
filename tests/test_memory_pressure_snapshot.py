from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "memory_pressure_snapshot", ROOT / "scripts/memory_pressure_snapshot.py"
)
assert SPEC and SPEC.loader
snapshot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(snapshot)


class MemoryPressureSnapshotTests(unittest.TestCase):
    def _run_snapshot(
        self,
        root: Path,
        *,
        mem_available: int,
        mem_total: int = 1000,
        swap_total: int = 1000,
        swap_free: int = 1000,
        some_avg10: float = 0.0,
        full_avg10: float = 0.0,
        pressure_present: bool = True,
        root_events_text: str = "",
        controllers_text: str = "cpu memory io\n",
    ) -> dict:
        state = root / "state"
        history = state / "history.jsonl"
        latest = state / "latest.json"
        pressure = (
            {
                "some": {"avg10": some_avg10, "avg60": 0.0, "avg300": 0.0, "total": 0},
                "full": {"avg10": full_avg10, "avg60": 0.0, "avg300": 0.0, "total": 0},
            }
            if pressure_present
            else {}
        )
        kernel_text = {
            Path("/sys/fs/cgroup/memory.events"): root_events_text,
            Path("/sys/fs/cgroup/cgroup.controllers"): controllers_text,
        }
        with (
            patch.object(snapshot, "STATE_DIR", state),
            patch.object(snapshot, "HISTORY", history),
            patch.object(snapshot, "LATEST", latest),
            patch.object(
                snapshot,
                "meminfo",
                return_value={
                    "MemTotal": mem_total,
                    "MemAvailable": mem_available,
                    "SwapTotal": swap_total,
                    "SwapFree": swap_free,
                },
            ),
            patch.object(snapshot, "pressure", return_value=pressure),
            patch.object(snapshot, "process_rows", return_value=[]),
            patch.object(snapshot, "cgroup_rows", return_value=[]),
            patch.object(snapshot, "read_text", side_effect=kernel_text.__getitem__),
        ):
            self.assertEqual(snapshot.main(), 0)
        self.assertEqual(state.stat().st_mode & 0o777, 0o700)
        self.assertEqual(history.stat().st_mode & 0o777, 0o600)
        self.assertEqual(latest.stat().st_mode & 0o777, 0o600)
        return json.loads(latest.read_text(encoding="utf-8"))

    def test_critical_memory_or_swap_pressure_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = self._run_snapshot(
                Path(temporary),
                mem_available=40,
                swap_free=50,
            )
        self.assertEqual(payload["severity"], "critical")
        self.assertEqual(payload["memory"]["available_ratio"], 0.04)
        self.assertEqual(payload["memory"]["swap_used_ratio"], 0.95)

    def test_warning_psi_is_recorded_without_process_effects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = self._run_snapshot(
                Path(temporary),
                mem_available=500,
                some_avg10=10.0,
            )
        self.assertEqual(payload["severity"], "warning")
        self.assertEqual(payload["top_processes"], [])
        self.assertEqual(payload["top_cgroups"], [])
        self.assertTrue(payload["observation_complete"])
        self.assertEqual(payload["observation_errors"], [])
        self.assertEqual(payload["bounds"]["history_samples"], 240)
        self.assertEqual(payload["bounds"]["history_bytes"], snapshot.MAX_HISTORY_BYTES)

    def test_absent_root_events_are_normal_on_a_healthy_host(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = self._run_snapshot(Path(temporary), mem_available=500)
        self.assertTrue(payload["observation_complete"])
        self.assertEqual(payload["observation_errors"], [])
        self.assertEqual(payload["severity"], "ok")
        self.assertFalse(payload["root_memory_events_available"])
        self.assertEqual(payload["root_memory_events"], {})

    def test_available_root_events_are_retained_as_optional_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = self._run_snapshot(
                Path(temporary), mem_available=500,
                root_events_text="oom 2\noom_kill 1\n",
            )
        self.assertTrue(payload["observation_complete"])
        self.assertTrue(payload["root_memory_events_available"])
        self.assertEqual(payload["root_memory_events"], {"oom": 2, "oom_kill": 1})

    def test_unavailable_memory_controller_is_not_a_healthy_observation(self) -> None:
        for controllers in ("", "cpu io\n"):
            with self.subTest(controllers=controllers), tempfile.TemporaryDirectory() as temporary:
                payload = self._run_snapshot(
                    Path(temporary), mem_available=500, controllers_text=controllers,
                )
            self.assertFalse(payload["observation_complete"])
            self.assertEqual(payload["severity"], "unknown")
            self.assertEqual(
                payload["observation_errors"], ["cgroup_memory_controller_unavailable"]
            )

    def test_history_is_bounded_to_240_samples(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir(mode=0o700)
            history = state / "history.jsonl"
            history.write_text(
                "".join(f'{{"sample":{index}}}\n' for index in range(300)),
                encoding="utf-8",
            )
            history.chmod(0o600)
            self._run_snapshot(root, mem_available=500)
            lines = history.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 240)
        self.assertEqual(json.loads(lines[0]), {"sample": 61})
        self.assertEqual(json.loads(lines[-1])["schema_version"], 1)

    def test_history_is_bounded_by_serialized_bytes(self) -> None:
        for text in ("x" * 22_000, "ä" * 12_000):
            with self.subTest(multibyte=text.startswith("ä")):
                line = json.dumps({"sample": text}, ensure_ascii=False, separators=(",", ":"))
                result = snapshot.bounded_history([line] * 239, line)
                self.assertLessEqual(len(result.encode("utf-8")), snapshot.MAX_HISTORY_BYTES)
                self.assertLess(len(result.splitlines()), 240)
                self.assertEqual(json.loads(result.splitlines()[-1]), json.loads(line))

    def test_oversized_regular_history_recovers_on_next_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir(mode=0o700)
            history = state / "history.jsonl"
            line = json.dumps({"sample": "x" * 22_000}, separators=(",", ":"))
            history.write_text((line + "\n") * 240, encoding="utf-8")
            history.chmod(0o600)
            self.assertGreater(history.stat().st_size, snapshot.MAX_HISTORY_BYTES)
            self.assertLess(history.stat().st_size, snapshot.MAX_HISTORY_RECOVERY_BYTES)

            payload = self._run_snapshot(root, mem_available=500)
            self.assertTrue(payload["observation_complete"])
            self.assertLessEqual(history.stat().st_size, snapshot.MAX_HISTORY_BYTES)
            self.assertLess(len(history.read_text(encoding="utf-8").splitlines()), 240)
            # Recovery must also leave the following tick able to update latest.
            next_payload = self._run_snapshot(root, mem_available=600)
            self.assertEqual(next_payload["memory"]["available_bytes"], 600)
            self.assertLessEqual(history.stat().st_size, snapshot.MAX_HISTORY_BYTES)
            self.assertEqual(
                json.loads(history.read_text(encoding="utf-8").splitlines()[-1]),
                next_payload,
            )

    def test_incomplete_required_sources_never_report_ok(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = self._run_snapshot(
                Path(temporary),
                mem_available=500,
                pressure_present=False,
                controllers_text="",
            )
        self.assertFalse(payload["observation_complete"])
        self.assertEqual(payload["severity"], "unknown")
        self.assertIn("memory_psi_incomplete", payload["observation_errors"])
        self.assertIn("cgroup_memory_controller_unavailable", payload["observation_errors"])

    def test_unsafe_history_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir(mode=0o700)
            target = root / "target"
            target.write_text("{}\n", encoding="utf-8")
            history = state / "history.jsonl"
            history.symlink_to(target)
            with (
                patch.object(snapshot, "STATE_DIR", state),
                patch.object(snapshot, "HISTORY", history),
                patch.object(snapshot, "LATEST", state / "latest.json"),
                self.assertRaisesRegex(RuntimeError, "unsafe"),
            ):
                snapshot.validate_history()

    def test_unsafe_history_hardlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_text("{}\n", encoding="utf-8")
            history = root / "history.jsonl"
            history.hardlink_to(target)
            with (
                patch.object(snapshot, "HISTORY", history),
                self.assertRaisesRegex(RuntimeError, "unsafe"),
            ):
                snapshot.validate_history()
            self.assertEqual(target.read_text(encoding="utf-8"), "{}\n")


if __name__ == "__main__":
    unittest.main()
