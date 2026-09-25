#!/usr/bin/env python3
"""Independent system-level guard for runaway Grabowski memory growth."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable

DEFAULT_POLICY = Path("/etc/heim-pc/memory-pressure-guard.v1.json")
DEFAULT_STATE_DIR = Path("/var/lib/heim-pc/grabowski-memory-guard")
SYSTEMCTL = "/usr/bin/systemctl"
PROC_ROOT = Path("/proc")
CGROUP_ROOT = Path("/sys/fs/cgroup")
Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


class GuardError(RuntimeError):
    pass


@dataclass(frozen=True)
class Observation:
    observed_at_unix: int
    pid: int
    active_state: str
    control_group: str
    rss_anon_bytes: int
    rss_bytes: int
    swap_bytes: int
    mem_available_bytes: int
    cgroup_memory_current_bytes: int | None
    cgroup_swap_current_bytes: int | None


def _bounded_int(value: Any, *, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise GuardError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def load_policy(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GuardError(f"cannot load policy {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise GuardError("policy must be an object")
    allowed = {"schema_version", "kind", "grabowski_guard", "does_not_establish"}
    unknown = set(value) - allowed
    if unknown:
        raise GuardError(f"policy contains unknown fields: {sorted(unknown)}")
    if value.get("schema_version") != 1 or value.get("kind") != "heim_pc_grabowski_memory_guard":
        raise GuardError("unsupported policy identity")
    guard = value.get("grabowski_guard")
    if not isinstance(guard, dict):
        raise GuardError("grabowski_guard policy is missing")
    required = {
        "target_unit",
        "expected_control_group",
        "sample_interval_seconds",
        "warn_rss_anon_bytes",
        "restart_rss_anon_bytes",
        "confirm_samples",
        "emergency_mem_available_bytes",
        "emergency_rss_anon_bytes",
        "restart_cooldown_seconds",
        "restart_window_seconds",
        "max_restarts_per_window",
        "post_restart_wait_seconds",
        "event_segment_max_bytes",
    }
    if set(guard) != required:
        raise GuardError("grabowski_guard policy fields are invalid")
    target_unit = guard["target_unit"]
    expected_control_group = guard["expected_control_group"]
    if target_unit != "grabowski-operator.service":
        raise GuardError("grabowski_guard.target_unit must be grabowski-operator.service")
    if expected_control_group != "/system.slice/grabowski-operator.service":
        raise GuardError("grabowski_guard.expected_control_group is invalid")
    result = {
        "target_unit": target_unit,
        "expected_control_group": expected_control_group,
        "sample_interval_seconds": _bounded_int(
            guard["sample_interval_seconds"], name="grabowski_guard.sample_interval_seconds", minimum=5, maximum=60
        ),
        "warn_rss_anon_bytes": _bounded_int(
            guard["warn_rss_anon_bytes"], name="grabowski_guard.warn_rss_anon_bytes", minimum=1024**3, maximum=64 * 1024**3
        ),
        "restart_rss_anon_bytes": _bounded_int(
            guard["restart_rss_anon_bytes"], name="grabowski_guard.restart_rss_anon_bytes", minimum=1024**3, maximum=64 * 1024**3
        ),
        "confirm_samples": _bounded_int(
            guard["confirm_samples"], name="grabowski_guard.confirm_samples", minimum=1, maximum=10
        ),
        "emergency_mem_available_bytes": _bounded_int(
            guard["emergency_mem_available_bytes"], name="grabowski_guard.emergency_mem_available_bytes", minimum=1024**3, maximum=64 * 1024**3
        ),
        "emergency_rss_anon_bytes": _bounded_int(
            guard["emergency_rss_anon_bytes"], name="grabowski_guard.emergency_rss_anon_bytes", minimum=1024**3, maximum=64 * 1024**3
        ),
        "restart_cooldown_seconds": _bounded_int(
            guard["restart_cooldown_seconds"], name="grabowski_guard.restart_cooldown_seconds", minimum=30, maximum=86400
        ),
        "restart_window_seconds": _bounded_int(
            guard["restart_window_seconds"], name="grabowski_guard.restart_window_seconds", minimum=300, maximum=86400
        ),
        "max_restarts_per_window": _bounded_int(
            guard["max_restarts_per_window"], name="grabowski_guard.max_restarts_per_window", minimum=1, maximum=20
        ),
        "post_restart_wait_seconds": _bounded_int(
            guard["post_restart_wait_seconds"], name="grabowski_guard.post_restart_wait_seconds", minimum=1, maximum=60
        ),
        "event_segment_max_bytes": _bounded_int(
            guard["event_segment_max_bytes"], name="grabowski_guard.event_segment_max_bytes", minimum=256 * 1024, maximum=64 * 1024**2
        ),
    }
    if result["warn_rss_anon_bytes"] >= result["restart_rss_anon_bytes"]:
        raise GuardError("warn RSS threshold must be below restart RSS threshold")
    if result["emergency_rss_anon_bytes"] > result["restart_rss_anon_bytes"]:
        raise GuardError("emergency RSS threshold must not exceed restart RSS threshold")
    if result["restart_cooldown_seconds"] > result["restart_window_seconds"]:
        raise GuardError("restart cooldown must not exceed restart window")
    return result


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True, check=False)


def _parse_show(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def read_unit_state(policy: dict[str, Any], runner: Runner = _run) -> dict[str, Any]:
    argv = [
        SYSTEMCTL,
        "show",
        policy["target_unit"],
        "--property=MainPID",
        "--property=ActiveState",
        "--property=SubState",
        "--property=ControlGroup",
        "--no-pager",
    ]
    completed = runner(argv)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise GuardError(f"cannot inspect target unit: {detail[:500]}")
    props = _parse_show(completed.stdout)
    try:
        pid = int(props.get("MainPID", "0"))
    except ValueError as exc:
        raise GuardError("target unit MainPID is invalid") from exc
    control_group = props.get("ControlGroup", "")
    active_state = props.get("ActiveState", "")
    return {
        "pid": pid,
        "active_state": active_state,
        "sub_state": props.get("SubState", ""),
        "control_group": control_group,
    }


def _read_status(pid: int, proc_root: Path) -> dict[str, int]:
    try:
        text = (proc_root / str(pid) / "status").read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise GuardError(f"cannot read target process status: {exc}") from exc
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key] = value.strip()

    def kib(name: str) -> int:
        parts = fields.get(name, "").split()
        if not parts:
            raise GuardError(f"target process status lacks {name}")
        try:
            return int(parts[0]) * 1024
        except ValueError as exc:
            raise GuardError(f"target process {name} is invalid") from exc

    return {"rss_anon_bytes": kib("RssAnon"), "rss_bytes": kib("VmRSS"), "swap_bytes": kib("VmSwap")}


def _read_process_cgroup(pid: int, proc_root: Path) -> str:
    try:
        lines = (proc_root / str(pid) / "cgroup").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise GuardError(f"cannot read target process cgroup: {exc}") from exc
    for line in lines:
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == "0" and parts[1] == "":
            return parts[2]
    raise GuardError("target process has no unified cgroup")


def _read_mem_available(proc_root: Path) -> int:
    try:
        lines = (proc_root / "meminfo").read_text(encoding="ascii").splitlines()
    except OSError as exc:
        raise GuardError(f"cannot read meminfo: {exc}") from exc
    for line in lines:
        if line.startswith("MemAvailable:"):
            parts = line.split()
            try:
                return int(parts[1]) * 1024
            except (IndexError, ValueError) as exc:
                raise GuardError("MemAvailable is invalid") from exc
    raise GuardError("MemAvailable is missing")


def _read_optional_int(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None


def observe(
    policy: dict[str, Any],
    *,
    runner: Runner = _run,
    proc_root: Path = PROC_ROOT,
    cgroup_root: Path = CGROUP_ROOT,
    now_unix: int | None = None,
) -> Observation | None:
    unit = read_unit_state(policy, runner)
    if unit["active_state"] != "active" or unit["pid"] <= 0:
        return None
    if unit["control_group"] != policy["expected_control_group"]:
        raise GuardError(
            f"target unit cgroup mismatch: {unit['control_group']!r} != {policy['expected_control_group']!r}"
        )
    process_cgroup = _read_process_cgroup(unit["pid"], proc_root)
    if process_cgroup != policy["expected_control_group"]:
        raise GuardError(
            f"target process cgroup mismatch: {process_cgroup!r} != {policy['expected_control_group']!r}"
        )
    status = _read_status(unit["pid"], proc_root)
    relative = policy["expected_control_group"].lstrip("/")
    cgroup = cgroup_root / relative
    return Observation(
        observed_at_unix=int(time.time()) if now_unix is None else int(now_unix),
        pid=unit["pid"],
        active_state=unit["active_state"],
        control_group=unit["control_group"],
        rss_anon_bytes=status["rss_anon_bytes"],
        rss_bytes=status["rss_bytes"],
        swap_bytes=status["swap_bytes"],
        mem_available_bytes=_read_mem_available(proc_root),
        cgroup_memory_current_bytes=_read_optional_int(cgroup / "memory.current"),
        cgroup_swap_current_bytes=_read_optional_int(cgroup / "memory.swap.current"),
    )


def default_state(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "heim_pc_grabowski_memory_guard_state",
        "target_unit": policy["target_unit"],
        "last_pid": 0,
        "consecutive_over_limit": 0,
        "restart_history_unix": [],
        "circuit_open": False,
    }


def load_state(path: Path, policy: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return default_state(policy)
    if path.is_symlink() or not path.is_file():
        raise GuardError(f"unsafe guard state file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GuardError(f"cannot read guard state: {exc}") from exc
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("kind") != "heim_pc_grabowski_memory_guard_state"
        or value.get("target_unit") != policy["target_unit"]
    ):
        raise GuardError("guard state identity is invalid")
    history = value.get("restart_history_unix")
    if not isinstance(history, list) or not all(isinstance(item, int) and item >= 0 for item in history):
        raise GuardError("guard restart history is invalid")
    if not isinstance(value.get("last_pid"), int) or not isinstance(value.get("consecutive_over_limit"), int):
        raise GuardError("guard state counters are invalid")
    if not isinstance(value.get("circuit_open"), bool):
        raise GuardError("guard circuit state is invalid")
    return value


def evaluate(policy: dict[str, Any], state: dict[str, Any], observation: Observation) -> tuple[dict[str, Any], str, str]:
    now = observation.observed_at_unix
    history = [
        item
        for item in state["restart_history_unix"]
        if now - item <= policy["restart_window_seconds"]
    ]
    same_pid = state["last_pid"] == observation.pid
    consecutive = state["consecutive_over_limit"] if same_pid else 0
    over_restart = observation.rss_anon_bytes >= policy["restart_rss_anon_bytes"]
    consecutive = consecutive + 1 if over_restart else 0

    next_state = {
        **state,
        "last_pid": observation.pid,
        "consecutive_over_limit": consecutive,
        "restart_history_unix": history,
    }

    if state["circuit_open"]:
        return next_state, "stop-circuit", "circuit_already_open"

    emergency = (
        observation.mem_available_bytes <= policy["emergency_mem_available_bytes"]
        and observation.rss_anon_bytes >= policy["emergency_rss_anon_bytes"]
    )
    sustained = over_restart and consecutive >= policy["confirm_samples"]
    if not emergency and not sustained:
        if over_restart:
            return next_state, "warn", "rss_restart_confirmation_pending"
        if observation.rss_anon_bytes >= policy["warn_rss_anon_bytes"]:
            return next_state, "warn", "rss_warn_threshold"
        return next_state, "none", "healthy"

    if len(history) >= policy["max_restarts_per_window"]:
        return next_state, "stop-circuit", "restart_rate_limit_exhausted"

    last_restart = history[-1] if history else 0
    within_cooldown = bool(last_restart and now - last_restart < policy["restart_cooldown_seconds"])
    if within_cooldown:
        if emergency:
            return next_state, "stop-circuit", "emergency_recurred_during_cooldown"
        return next_state, "cooldown", "restart_cooldown_active"

    reason = "host_memory_emergency" if emergency else "sustained_grabowski_rss"
    return next_state, "restart", reason


def _safe_state_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise GuardError(f"unsafe guard state directory: {path}")
    os.chmod(path, 0o700)


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise GuardError(f"unsafe guard state target: {path}")
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _append_event(path: Path, event: dict[str, Any], *, max_bytes: int) -> None:
    line = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(line) > max_bytes:
        raise GuardError("one guard event exceeds event segment limit")
    previous = path.with_name(path.name + ".previous")
    for candidate in (path, previous):
        if candidate.is_symlink() or (candidate.exists() and not candidate.is_file()):
            raise GuardError(f"unsafe guard event file: {candidate}")
    if path.exists() and path.stat().st_size + len(line) > max_bytes:
        previous.unlink(missing_ok=True)
        os.replace(path, previous)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)


def _event(observation: Observation | None, *, action: str, reason: str, result: str) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": 1,
        "kind": "heim_pc_grabowski_memory_guard_event",
        "observed_at_unix": int(time.time()) if observation is None else observation.observed_at_unix,
        "action": action,
        "reason": reason,
        "result": result,
    }
    if observation is not None:
        value["observation"] = {
            "pid": observation.pid,
            "rss_anon_bytes": observation.rss_anon_bytes,
            "rss_bytes": observation.rss_bytes,
            "swap_bytes": observation.swap_bytes,
            "mem_available_bytes": observation.mem_available_bytes,
            "cgroup_memory_current_bytes": observation.cgroup_memory_current_bytes,
            "cgroup_swap_current_bytes": observation.cgroup_swap_current_bytes,
        }
    return value


def _verified_restart(policy: dict[str, Any], old_pid: int, runner: Runner) -> tuple[bool, dict[str, Any]]:
    completed = runner([SYSTEMCTL, "restart", policy["target_unit"]])
    time.sleep(policy["post_restart_wait_seconds"])
    post = read_unit_state(policy, runner)
    success = (
        post["active_state"] == "active"
        and post["pid"] > 0
        and post["pid"] != old_pid
        and post["control_group"] == policy["expected_control_group"]
    )
    return success, {
        "systemctl_returncode": completed.returncode,
        "post_active_state": post["active_state"],
        "post_pid": post["pid"],
        "post_control_group": post["control_group"],
    }


def _verified_stop(policy: dict[str, Any], runner: Runner) -> tuple[bool, dict[str, Any]]:
    completed = runner([SYSTEMCTL, "stop", policy["target_unit"]])
    post = read_unit_state(policy, runner)
    success = post["active_state"] != "active" and post["pid"] == 0
    return success, {
        "systemctl_returncode": completed.returncode,
        "post_active_state": post["active_state"],
        "post_pid": post["pid"],
    }


def run_once(
    policy: dict[str, Any],
    state_dir: Path,
    *,
    runner: Runner = _run,
    proc_root: Path = PROC_ROOT,
    cgroup_root: Path = CGROUP_ROOT,
    allow_actions: bool = True,
    now_unix: int | None = None,
) -> dict[str, Any]:
    _safe_state_dir(state_dir)
    state_path = state_dir / "state.json"
    latest_path = state_dir / "latest.json"
    event_path = state_dir / "events.jsonl"
    state = load_state(state_path, policy)
    observation = observe(
        policy,
        runner=runner,
        proc_root=proc_root,
        cgroup_root=cgroup_root,
        now_unix=now_unix,
    )
    if observation is None:
        state["last_pid"] = 0
        state["consecutive_over_limit"] = 0
        _atomic_json(state_path, state)
        event = _event(None, action="none", reason="target_not_active", result="observed")
        _atomic_json(latest_path, event)
        return event

    next_state, action, reason = evaluate(policy, state, observation)
    event = _event(observation, action=action, reason=reason, result="observed")

    if action in {"restart", "stop-circuit"} and not allow_actions:
        event["result"] = "observe-only"
        _atomic_json(state_path, next_state)
        _atomic_json(latest_path, event)
        _append_event(event_path, event, max_bytes=policy["event_segment_max_bytes"])
        return event

    if action == "restart":
        success, readback = _verified_restart(policy, observation.pid, runner)
        event["readback"] = readback
        if success:
            next_state["restart_history_unix"] = [
                *next_state["restart_history_unix"],
                observation.observed_at_unix,
            ]
            next_state["consecutive_over_limit"] = 0
            next_state["last_pid"] = int(readback["post_pid"])
            event["result"] = "restarted-verified"
        else:
            next_state["circuit_open"] = True
            next_state["consecutive_over_limit"] = 0
            event["result"] = "restart-outcome-unverified-circuit-open"
            _atomic_json(state_path, next_state)
            _atomic_json(latest_path, event)
            _append_event(event_path, event, max_bytes=policy["event_segment_max_bytes"])
            raise GuardError("restart outcome could not be verified; circuit opened")

    elif action == "stop-circuit":
        success, readback = _verified_stop(policy, runner)
        event["readback"] = readback
        if success:
            next_state["circuit_open"] = True
            next_state["consecutive_over_limit"] = 0
            event["result"] = "stopped-circuit-open"
        else:
            event["result"] = "stop-outcome-unverified"
            _atomic_json(state_path, next_state)
            _atomic_json(latest_path, event)
            _append_event(event_path, event, max_bytes=policy["event_segment_max_bytes"])
            raise GuardError("circuit-breaker stop outcome could not be verified")

    _atomic_json(state_path, next_state)
    _atomic_json(latest_path, event)
    if action != "none":
        _append_event(event_path, event, max_bytes=policy["event_segment_max_bytes"])
    return event


def reset_circuit(
    policy: dict[str, Any],
    state_dir: Path,
    *,
    runner: Runner = _run,
) -> dict[str, Any]:
    _safe_state_dir(state_dir)
    unit = read_unit_state(policy, runner)
    if unit["active_state"] == "active" or unit["pid"] > 0:
        raise GuardError("circuit reset requires the target operator to be inactive")
    state = load_state(state_dir / "state.json", policy)
    state["last_pid"] = 0
    state["consecutive_over_limit"] = 0
    state["restart_history_unix"] = []
    state["circuit_open"] = False
    _atomic_json(state_dir / "state.json", state)
    event = {
        "schema_version": 1,
        "kind": "heim_pc_grabowski_memory_guard_event",
        "observed_at_unix": int(time.time()),
        "action": "reset-circuit",
        "reason": "explicit_operator_recovery",
        "result": "reset",
    }
    _atomic_json(state_dir / "latest.json", event)
    _append_event(
        state_dir / "events.jsonl",
        event,
        max_bytes=policy["event_segment_max_bytes"],
    )
    return event


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--observe-only", action="store_true")
    parser.add_argument("--reset-circuit", action="store_true")
    args = parser.parse_args()

    try:
        policy = load_policy(args.policy.resolve())
        if args.reset_circuit:
            if args.loop or args.observe_only:
                raise GuardError("--reset-circuit cannot be combined with --loop/--observe-only")
            event = reset_circuit(policy, args.state_dir.resolve())
            print(json.dumps(event, sort_keys=True), flush=True)
            return 0
        while True:
            try:
                event = run_once(
                    policy,
                    args.state_dir.resolve(),
                    allow_actions=not args.observe_only,
                )
                print(json.dumps(event, sort_keys=True), flush=True)
            except GuardError as exc:
                print(
                    json.dumps(
                        {
                            "kind": "heim_pc_grabowski_memory_guard_error",
                            "error": str(exc),
                            "observed_at_unix": int(time.time()),
                        },
                        sort_keys=True,
                    ),
                    file=sys.stderr,
                    flush=True,
                )
                if not args.loop:
                    return 1
            if not args.loop:
                return 0
            time.sleep(policy["sample_interval_seconds"])
    except (GuardError, OSError, ValueError) as exc:
        print(
            json.dumps(
                {"kind": "heim_pc_grabowski_memory_guard_error", "error": str(exc)},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())