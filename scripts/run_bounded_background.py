#!/usr/bin/env python3
"""Start one explicitly risky background command in a bounded user systemd unit."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "config/runaway-guard.v1.json"
UNIT_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,47}\Z")


class GuardError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bounded_int(value: Any, *, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise GuardError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise GuardError(f"{name} must be between {minimum} and {maximum}")
    return value


def load_policy(path: Path) -> tuple[dict[str, Any], str]:
    try:
        data = path.read_bytes()
        policy = json.loads(data)
    except (OSError, json.JSONDecodeError) as exc:
        raise GuardError(f"cannot read policy {path}: {exc}") from exc
    if not isinstance(policy, dict):
        raise GuardError("policy must be a JSON object")
    if policy.get("schema_version") != 1 or policy.get("kind") != "heim_pc_minimal_runaway_guard":
        raise GuardError("unsupported policy identity")
    bounded = policy.get("bounded_background")
    if not isinstance(bounded, dict):
        raise GuardError("bounded_background policy is missing")
    prefix = bounded.get("unit_prefix")
    if not isinstance(prefix, str) or not UNIT_NAME_PATTERN.fullmatch(prefix):
        raise GuardError("unit_prefix is invalid")
    validated = {
        "unit_prefix": prefix,
        "runtime_max_seconds": _bounded_int(
            bounded.get("runtime_max_seconds"),
            name="runtime_max_seconds",
            minimum=1,
            maximum=86400,
        ),
        "memory_max_bytes": _bounded_int(
            bounded.get("memory_max_bytes"),
            name="memory_max_bytes",
            minimum=64 * 1024 * 1024,
            maximum=64 * 1024**3,
        ),
        "tasks_max": _bounded_int(
            bounded.get("tasks_max"), name="tasks_max", minimum=1, maximum=4096
        ),
        "file_size_max_bytes": _bounded_int(
            bounded.get("file_size_max_bytes"),
            name="file_size_max_bytes",
            minimum=1024 * 1024,
            maximum=64 * 1024**3,
        ),
        "cpu_weight": _bounded_int(
            bounded.get("cpu_weight"), name="cpu_weight", minimum=1, maximum=10000
        ),
        "io_weight": _bounded_int(
            bounded.get("io_weight"), name="io_weight", minimum=1, maximum=10000
        ),
        "log_rate_limit_interval_seconds": _bounded_int(
            bounded.get("log_rate_limit_interval_seconds"),
            name="log_rate_limit_interval_seconds",
            minimum=1,
            maximum=3600,
        ),
        "log_rate_limit_burst": _bounded_int(
            bounded.get("log_rate_limit_burst"),
            name="log_rate_limit_burst",
            minimum=1,
            maximum=100000,
        ),
    }
    return validated, sha256(data)


def _override(default: int, requested: int | None, *, name: str, minimum: int, maximum: int) -> int:
    value = default if requested is None else requested
    return _bounded_int(value, name=name, minimum=minimum, maximum=maximum)


def build_systemd_argv(
    *,
    name: str,
    command: list[str],
    cwd: Path,
    policy: dict[str, Any],
    runtime_seconds: int | None = None,
    memory_max_bytes: int | None = None,
    tasks_max: int | None = None,
    file_size_max_bytes: int | None = None,
    wait: bool = False,
) -> tuple[str, list[str]]:
    if not UNIT_NAME_PATTERN.fullmatch(name):
        raise GuardError("name must match [A-Za-z0-9][A-Za-z0-9_.-]{0,47}")
    if not command or not command[0]:
        raise GuardError("one argv-only command is required")
    if not cwd.is_absolute() or not cwd.is_dir():
        raise GuardError(f"working directory must be an existing absolute directory: {cwd}")
    runtime = _override(
        policy["runtime_max_seconds"], runtime_seconds,
        name="runtime_seconds", minimum=1, maximum=86400,
    )
    memory = _override(
        policy["memory_max_bytes"], memory_max_bytes,
        name="memory_max_bytes", minimum=64 * 1024 * 1024, maximum=64 * 1024**3,
    )
    tasks = _override(
        policy["tasks_max"], tasks_max,
        name="tasks_max", minimum=1, maximum=4096,
    )
    file_size = _override(
        policy["file_size_max_bytes"], file_size_max_bytes,
        name="file_size_max_bytes", minimum=1024 * 1024, maximum=64 * 1024**3,
    )
    unit = f"{policy['unit_prefix']}-{name}.service"
    argv = [
        "systemd-run",
        "--user",
        "--collect",
        f"--unit={unit}",
        f"--description=Bounded heim-pc background command ({name})",
        f"--working-directory={cwd}",
        "--property=Type=exec",
        "--property=KillMode=control-group",
        f"--property=RuntimeMaxSec={runtime}s",
        "--property=TimeoutStopSec=10s",
        f"--property=MemoryMax={memory}",
        f"--property=TasksMax={tasks}",
        f"--property=LimitFSIZE={file_size}",
        f"--property=CPUWeight={policy['cpu_weight']}",
        f"--property=IOWeight={policy['io_weight']}",
        "--property=StandardInput=null",
        "--property=StandardOutput=journal",
        "--property=StandardError=journal",
        f"--property=LogRateLimitIntervalSec={policy['log_rate_limit_interval_seconds']}s",
        f"--property=LogRateLimitBurst={policy['log_rate_limit_burst']}",
    ]
    if wait:
        argv.append("--wait")
    argv.extend(["--", *command])
    return unit, argv


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--cwd", type=Path, default=Path.cwd())
    parser.add_argument("--runtime-seconds", type=int)
    parser.add_argument("--memory-max-bytes", type=int)
    parser.add_argument("--tasks-max", type=int)
    parser.add_argument("--file-size-max-bytes", type=int)
    parser.add_argument("--wait", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    try:
        policy, policy_sha256 = load_policy(args.policy.expanduser().resolve())
        unit, argv = build_systemd_argv(
            name=args.name,
            command=command,
            cwd=args.cwd.expanduser().resolve(),
            policy=policy,
            runtime_seconds=args.runtime_seconds,
            memory_max_bytes=args.memory_max_bytes,
            tasks_max=args.tasks_max,
            file_size_max_bytes=args.file_size_max_bytes,
            wait=args.wait,
        )
    except (GuardError, OSError) as exc:
        print(json.dumps({"kind": "heim_pc_bounded_background_error", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2

    command_sha256 = sha256(
        json.dumps(command, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )
    if args.dry_run:
        systemd_argv_sha256 = sha256(
            json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
        print(json.dumps({
            "schema_version": 1,
            "kind": "heim_pc_bounded_background_plan",
            "unit": unit,
            "policy_sha256": policy_sha256,
            "command_sha256": command_sha256,
            "command_argc": len(command),
            "systemd_argv_sha256": systemd_argv_sha256,
            "does_not_establish": ["command_started", "command_success"],
        }, ensure_ascii=False, sort_keys=True))
        return 0

    completed = subprocess.run(argv, text=True, capture_output=True, check=False)
    result = {
        "schema_version": 1,
        "kind": "heim_pc_bounded_background_result",
        "unit": unit,
        "policy_sha256": policy_sha256,
        "command_sha256": command_sha256,
        "wait": args.wait,
        "systemd_run_returncode": completed.returncode,
        "launcher_stdout": completed.stdout.strip()[:1000],
        "launcher_stderr": completed.stderr.strip()[:1000],
        "does_not_establish": [] if args.wait and completed.returncode == 0 else ["command_completion", "command_success"],
    }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
