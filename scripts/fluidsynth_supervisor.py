#!/usr/bin/python3
"""Supervise FluidSynth without exposing its legacy TCP shell server."""

from __future__ import annotations

from dataclasses import dataclass
import signal
import subprocess
import sys
import time
from typing import Any, Callable, Sequence

EXIT_USAGE = 64
EXIT_START_FAILURE = 69
EXIT_FALLBACK_SIGNAL = 70
QUIT_GRACE_SECONDS = 5.0
TERM_GRACE_SECONDS = 3.0
POLL_INTERVAL_SECONDS = 0.05
FLUIDSYNTH_EXECUTABLE = "/usr/bin/fluidsynth"
FORBIDDEN_LONG_FLAGS = ("--no-shell", "--server")
FORBIDDEN_SHORT_FLAGS = frozenset({"i", "s"})


class SupervisorError(RuntimeError):
    """Raised when the child command violates the lifecycle contract."""


@dataclass
class StopRequest:
    signum: int = 0
    count: int = 0

    def request(self, signum: int, _frame: object = None) -> None:
        if self.signum == 0:
            self.signum = signum
        self.count += 1


def _forbidden_lifecycle_flag(token: str) -> bool:
    if token.startswith("--"):
        option = token.split("=", 1)[0]
        return any(
            option == forbidden
            or (len(option) > 2 and forbidden.startswith(option))
            for forbidden in FORBIDDEN_LONG_FLAGS
        )
    if token.startswith("-"):
        return bool(FORBIDDEN_SHORT_FLAGS.intersection(token[1:]))
    return False


def validate_child_argv(argv: Sequence[str]) -> list[str]:
    child_argv = list(argv)
    if not child_argv or child_argv[0] != FLUIDSYNTH_EXECUTABLE:
        raise SupervisorError(
            f"child executable must be exactly {FLUIDSYNTH_EXECUTABLE}"
        )
    forbidden = [token for token in child_argv[1:] if _forbidden_lifecycle_flag(token)]
    if forbidden:
        raise SupervisorError(
            "forbidden FluidSynth lifecycle flag(s): " + ", ".join(forbidden)
        )
    return child_argv


def supervise(
    child_argv: Sequence[str],
    stop_request: StopRequest,
    *,
    popen_factory: Callable[..., Any] = subprocess.Popen,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    argv = validate_child_argv(child_argv)
    child = popen_factory(
        argv,
        stdin=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    stop_started: float | None = None
    quit_sent = False
    term_sent = False
    fallback_used = False
    kill_sent = False

    try:
        while True:
            returncode = child.poll()
            if returncode is not None:
                if fallback_used:
                    print(
                        "FluidSynth required the supervisor signal fallback",
                        file=sys.stderr,
                    )
                    return EXIT_FALLBACK_SIGNAL
                return int(returncode)

            if stop_request.signum:
                now = monotonic()
                if stop_started is None:
                    stop_started = now
                if not quit_sent:
                    try:
                        if child.stdin is not None:
                            child.stdin.write("quit\n")
                            child.stdin.flush()
                            child.stdin.close()
                    except (BrokenPipeError, OSError, ValueError):
                        pass
                    quit_sent = True

                elapsed = now - stop_started
                if (elapsed >= QUIT_GRACE_SECONDS or stop_request.count > 1) and not term_sent:
                    child.send_signal(signal.SIGTERM)
                    term_sent = True
                    fallback_used = True
                if (
                    elapsed >= QUIT_GRACE_SECONDS + TERM_GRACE_SECONDS
                    and not kill_sent
                ):
                    child.kill()
                    kill_sent = True
                    fallback_used = True

            sleep(POLL_INTERVAL_SECONDS)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=2)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "--":
        arguments = arguments[1:]
    try:
        child_argv = validate_child_argv(arguments)
    except SupervisorError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE

    stop_request = StopRequest()
    signal.signal(signal.SIGTERM, stop_request.request)
    signal.signal(signal.SIGINT, stop_request.request)
    try:
        return supervise(child_argv, stop_request)
    except OSError as exc:
        print(f"cannot start FluidSynth: {exc}", file=sys.stderr)
        return EXIT_START_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
