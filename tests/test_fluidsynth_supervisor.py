from __future__ import annotations

import importlib.util
from pathlib import Path
import signal
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "fluidsynth_supervisor", ROOT / "scripts" / "fluidsynth_supervisor.py"
)
assert SPEC and SPEC.loader
supervisor = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = supervisor
SPEC.loader.exec_module(supervisor)


class FakeStdin:
    def __init__(self, child: "FakeChild", *, exit_on_close: bool) -> None:
        self.child = child
        self.exit_on_close = exit_on_close
        self.writes: list[str] = []
        self.flushed = False
        self.closed = False

    def write(self, value: str) -> int:
        self.writes.append(value)
        return len(value)

    def flush(self) -> None:
        self.flushed = True

    def close(self) -> None:
        self.closed = True
        if self.exit_on_close:
            self.child.returncode = 0


class FakeChild:
    def __init__(
        self,
        *,
        exit_on_stdin_close: bool,
        exit_on_term: bool = True,
    ) -> None:
        self.returncode: int | None = None
        self.stdin = FakeStdin(self, exit_on_close=exit_on_stdin_close)
        self.exit_on_term = exit_on_term
        self.sent_signals: list[int] = []
        self.killed = False
        self.waited = False

    def poll(self) -> int | None:
        return self.returncode

    def send_signal(self, signum: int) -> None:
        self.sent_signals.append(signum)
        if self.exit_on_term:
            self.returncode = -signum

    def kill(self) -> None:
        self.killed = True
        self.returncode = -signal.SIGKILL

    def wait(self, timeout: float) -> int:
        del timeout
        self.waited = True
        assert self.returncode is not None
        return self.returncode


class FluidSynthSupervisorTests(unittest.TestCase):
    def test_validate_accepts_bounded_non_server_command(self) -> None:
        command = supervisor.validate_child_argv(
            [
                "/usr/bin/fluidsynth",
                "-q",
                "-a",
                "alsa",
                "-m",
                "alsa_seq",
                "/usr/share/sounds/sf3/default-GM.sf3",
            ]
        )
        self.assertEqual(command[0], "/usr/bin/fluidsynth")

    def test_validate_requires_exact_fluidsynth_executable(self) -> None:
        with self.assertRaisesRegex(supervisor.SupervisorError, "exactly"):
            supervisor.validate_child_argv(["/tmp/fluidsynth"])

    def test_validate_rejects_server_and_no_shell_forms(self) -> None:
        for token in (
            "-i",
            "-s",
            "-is",
            "-si",
            "--no-shell",
            "--no-shell=true",
            "--no-s",
            "--server",
            "--server=true",
            "--ser",
        ):
            with self.subTest(token=token), self.assertRaisesRegex(
                supervisor.SupervisorError, "forbidden"
            ):
                supervisor.validate_child_argv(
                    ["/usr/bin/fluidsynth", token, "/tmp/font.sf3"]
                )

    def test_main_reports_child_start_failure_without_traceback(self) -> None:
        with patch.object(
            supervisor.signal, "signal"
        ), patch.object(
            supervisor, "supervise", side_effect=OSError("missing")
        ):
            result = supervisor.main(["--", "/usr/bin/fluidsynth", "/tmp/font.sf3"])

        self.assertEqual(result, supervisor.EXIT_START_FAILURE)

    def test_graceful_stop_writes_quit_without_signals(self) -> None:
        child = FakeChild(exit_on_stdin_close=True)
        request = supervisor.StopRequest(signum=signal.SIGTERM, count=1)

        result = supervisor.supervise(
            ["/usr/bin/fluidsynth", "-q", "/tmp/font.sf3"],
            request,
            popen_factory=lambda *_args, **_kwargs: child,
            sleep=lambda _seconds: None,
        )

        self.assertEqual(result, 0)
        self.assertEqual(child.stdin.writes, ["quit\n"])
        self.assertTrue(child.stdin.flushed)
        self.assertTrue(child.stdin.closed)
        self.assertEqual(child.sent_signals, [])
        self.assertFalse(child.killed)

    def test_signal_fallback_is_visible_as_failure(self) -> None:
        child = FakeChild(exit_on_stdin_close=False, exit_on_term=True)
        request = supervisor.StopRequest(signum=signal.SIGTERM, count=1)
        moments = iter((0.0, supervisor.QUIT_GRACE_SECONDS + 0.1))

        result = supervisor.supervise(
            ["/usr/bin/fluidsynth", "/tmp/font.sf3"],
            request,
            popen_factory=lambda *_args, **_kwargs: child,
            monotonic=lambda: next(moments),
            sleep=lambda _seconds: None,
        )

        self.assertEqual(result, supervisor.EXIT_FALLBACK_SIGNAL)
        self.assertEqual(child.stdin.writes, ["quit\n"])
        self.assertEqual(child.sent_signals, [signal.SIGTERM])
        self.assertFalse(child.killed)


if __name__ == "__main__":
    unittest.main()
