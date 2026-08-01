from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
DROP_IN = ROOT / "systemd/user/fluidsynth.service.d/zz-heim-pc-interactive-user.conf"
CONTRACT = ROOT / "config/host-health-remediation.v1.json"

FIXTURE = """
import signal
import sys
import time

if sys.argv[1] == "hang":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
print("ready", flush=True)
while True:
    time.sleep(1)
"""


def assignments(text: str, section_name: str) -> list[str]:
    section: str | None = None
    result: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
        elif section == section_name:
            result.append(line)
    return result


class FluidSynthShutdownContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.processes: list[subprocess.Popen[str]] = []

    def tearDown(self) -> None:
        for process in self.processes:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.fail(f"fixture process group {process.pid} could not be reaped")
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()

    def start_fixture(self, mode: str = "normal") -> subprocess.Popen[str]:
        process = subprocess.Popen(
            [sys.executable, "-c", FIXTURE, mode],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        self.processes.append(process)
        assert process.stdout is not None
        self.assertEqual(process.stdout.readline().strip(), "ready")
        self.assertIsNone(process.poll())
        return process

    def bounded_stop(
        self,
        process: subprocess.Popen[str],
        *,
        first_signal: signal.Signals = signal.SIGTERM,
        timeout: float = 1.0,
    ) -> dict[str, object]:
        started = time.monotonic()
        os.killpg(process.pid, first_signal)
        used_sigkill = False
        timed_out = False
        try:
            return_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            used_sigkill = True
            os.killpg(process.pid, signal.SIGKILL)
            return_code = process.wait(timeout=2)
        return {
            "elapsed": time.monotonic() - started,
            "return_code": return_code,
            "timed_out": timed_out,
            "used_sigkill": used_sigkill,
            "failure": (
                "timeout_then_sigkill_visible_as_failure" if timed_out else None
            ),
        }

    def assert_reaped(self, process: subprocess.Popen[str]) -> None:
        self.assertIsNotNone(process.poll())
        self.assertFalse(Path(f"/proc/{process.pid}").exists())
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()

    def test_drop_in_and_json_define_exact_shutdown_contract(self) -> None:
        drop_in = DROP_IN.read_text(encoding="utf-8")
        service = assignments(drop_in, "Service")
        deployment = json.loads(CONTRACT.read_text(encoding="utf-8"))["deployment"]

        self.assertIn("Type=notify", service)
        self.assertIn("NotifyAccess=main", service)
        self.assertIn("ExecStart=", service)
        self.assertIn(
            "ExecStart=/usr/bin/env SDL_NO_SIGNAL_HANDLERS=1 "
            "/usr/bin/fluidsynth -is $OTHER_OPTS $SOUND_FONT",
            service,
        )
        self.assertNotIn("/bin/sh", drop_in)
        self.assertNotIn("/bin/bash", drop_in)
        self.assertNotIn("Environment=SDL_NO_SIGNAL_HANDLERS=1", service)
        self.assertIn("ExecStop=", service)
        self.assertIn("KillMode=control-group", service)
        self.assertIn("KillSignal=SIGTERM", service)
        self.assertIn("RestartKillSignal=SIGTERM", service)
        self.assertIn("TimeoutStopSec=15s", service)
        self.assertIn("SendSIGKILL=yes", service)
        self.assertIn("FinalKillSignal=SIGKILL", service)
        self.assertEqual(deployment["fluidsynth_exec_stop"], [])
        self.assertEqual(deployment["fluidsynth_timeout_stop_sec"], "15s")
        self.assertTrue(deployment["fluidsynth_send_sigkill"])
        self.assertEqual(
            deployment["fluidsynth_shutdown_failure"],
            "timeout_then_sigkill_visible_as_failure",
        )

    def test_drop_in_preserves_scope_routing_rate_limits_and_autostart(self) -> None:
        drop_in = DROP_IN.read_text(encoding="utf-8")
        unit = assignments(drop_in, "Unit")
        service = assignments(drop_in, "Service")

        self.assertEqual(unit, ["ConditionUser=", "ConditionUser=alex"])
        self.assertIn("LogRateLimitIntervalSec=30s", service)
        self.assertIn("LogRateLimitBurst=200", service)
        self.assertNotIn("[Install]", drop_in)
        self.assertNotIn("WantedBy=", drop_in)
        forbidden = (
            "audio.driver",
            "midi.driver",
            "pipewire",
            "motu",
            "defaultsink",
            "defaultsource",
            "pactl",
            "wpctl",
        )
        lowered = drop_in.lower()
        for token in forbidden:
            self.assertNotIn(token, lowered)

    def test_sigterm_and_sigint_exit_normally_without_fallback(self) -> None:
        for stop_signal in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=stop_signal.name):
                process = self.start_fixture()
                result = self.bounded_stop(process, first_signal=stop_signal)
                self.assertFalse(result["timed_out"])
                self.assertFalse(result["used_sigkill"])
                self.assertEqual(result["return_code"], -stop_signal)
                self.assertLess(result["elapsed"], 15)
                self.assert_reaped(process)

    def test_restart_reaps_old_process_before_starting_replacement(self) -> None:
        old = self.start_fixture()
        old_result = self.bounded_stop(old)
        self.assertFalse(old_result["used_sigkill"])
        self.assert_reaped(old)

        replacement = self.start_fixture()
        self.assertNotEqual(replacement.pid, old.pid)
        replacement_result = self.bounded_stop(replacement)
        self.assertFalse(replacement_result["used_sigkill"])
        self.assert_reaped(replacement)

    def test_hanging_process_group_is_killed_and_failure_is_visible(self) -> None:
        process = self.start_fixture("hang")
        result = self.bounded_stop(process, timeout=0.1)

        self.assertTrue(result["timed_out"])
        self.assertTrue(result["used_sigkill"])
        self.assertEqual(result["return_code"], -signal.SIGKILL)
        self.assertEqual(
            result["failure"],
            "timeout_then_sigkill_visible_as_failure",
        )
        self.assertLess(result["elapsed"], 2)
        self.assert_reaped(process)


if __name__ == "__main__":
    unittest.main()
