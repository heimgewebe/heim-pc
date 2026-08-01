#!/usr/bin/env python3
"""Observe root filesystem pressure and request bounded maintenance only when needed."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable


class PressureWatchError(RuntimeError):
    pass


def _checked_number(value: Any, *, field: str, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PressureWatchError(f"{field} must be numeric")
    checked = float(value)
    if checked < minimum:
        raise PressureWatchError(f"{field} must be at least {minimum}")
    return checked


def load_policy(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PressureWatchError(f"cannot read pressure policy: {exc}") from exc
    if not isinstance(value, dict):
        raise PressureWatchError("pressure policy must be an object")
    allowed = {
        "schema_version",
        "kind",
        "mountpoint",
        "used_percent_threshold",
        "available_bytes_threshold",
        "growth_bytes_per_hour_threshold",
        "minimum_growth_sample_seconds",
        "service_triggers",
    }
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise PressureWatchError(f"pressure policy contains unknown fields: {unknown}")
    if value.get("schema_version") != 1:
        raise PressureWatchError("pressure policy schema_version must be 1")
    if value.get("kind") != "heim_pc_storage_pressure_policy":
        raise PressureWatchError("pressure policy kind is invalid")
    mountpoint = value.get("mountpoint")
    if not isinstance(mountpoint, str) or not mountpoint.startswith("/") or "\x00" in mountpoint:
        raise PressureWatchError("mountpoint must be an absolute path")
    checked: dict[str, Any] = {
        "schema_version": 1,
        "kind": value["kind"],
        "mountpoint": mountpoint,
        "used_percent_threshold": _checked_number(
            value.get("used_percent_threshold"), field="used_percent_threshold"
        ),
        "available_bytes_threshold": int(
            _checked_number(value.get("available_bytes_threshold"), field="available_bytes_threshold")
        ),
        "growth_bytes_per_hour_threshold": int(
            _checked_number(
                value.get("growth_bytes_per_hour_threshold"),
                field="growth_bytes_per_hour_threshold",
            )
        ),
        "minimum_growth_sample_seconds": int(
            _checked_number(
                value.get("minimum_growth_sample_seconds"),
                field="minimum_growth_sample_seconds",
                minimum=60,
            )
        ),
    }
    if checked["used_percent_threshold"] > 100:
        raise PressureWatchError("used_percent_threshold must not exceed 100")
    triggers = value.get("service_triggers")
    if not isinstance(triggers, list) or not triggers:
        raise PressureWatchError("service_triggers must be a non-empty list")
    normalized_triggers: list[dict[str, Any]] = []
    seen_units: set[str] = set()
    for index, trigger in enumerate(triggers):
        if not isinstance(trigger, dict) or set(trigger) != {"unit", "cooldown_seconds"}:
            raise PressureWatchError(f"service_triggers[{index}] fields are invalid")
        unit = trigger.get("unit")
        if (
            not isinstance(unit, str)
            or not unit.endswith(".service")
            or "/" in unit
            or "\x00" in unit
            or unit in seen_units
        ):
            raise PressureWatchError(f"service_triggers[{index}].unit is invalid")
        cooldown = int(
            _checked_number(
                trigger.get("cooldown_seconds"),
                field=f"service_triggers[{index}].cooldown_seconds",
                minimum=3600,
            )
        )
        seen_units.add(unit)
        normalized_triggers.append({"unit": unit, "cooldown_seconds": cooldown})
    checked["service_triggers"] = normalized_triggers
    return checked


def filesystem_sample(mountpoint: str, *, observed_at_unix_ns: int | None = None) -> dict[str, Any]:
    observation = observed_at_unix_ns if observed_at_unix_ns is not None else time.time_ns()
    statvfs = os.statvfs(mountpoint)
    block_size = statvfs.f_frsize or statvfs.f_bsize
    total = statvfs.f_blocks * block_size
    free = statvfs.f_bfree * block_size
    available = statvfs.f_bavail * block_size
    used = total - free
    usable_total = used + available
    if total <= 0 or usable_total <= 0:
        raise PressureWatchError("filesystem usable bytes must be positive")
    return {
        "observed_at_unix_ns": observation,
        "mountpoint": mountpoint,
        "total_bytes": total,
        "used_bytes": used,
        "available_bytes": available,
        "used_percent": round(used * 100.0 / usable_total, 2),
    }


def read_state(path: Path) -> dict[str, Any] | None:
    if path.is_symlink():
        raise PressureWatchError(f"state path is unsafe: {path}")
    if not path.exists():
        return None
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise PressureWatchError(f"state path is unsafe: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PressureWatchError(f"cannot read pressure state: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise PressureWatchError("pressure state is invalid")
    return value


def _safe_state_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise PressureWatchError(f"state directory is unsafe: {path}")
    os.chmod(path, 0o700)


def write_state(path: Path, value: dict[str, Any]) -> None:
    _safe_state_directory(path.parent)
    if path.is_symlink():
        raise PressureWatchError(f"state path is unsafe: {path}")
    if path.exists():
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise PressureWatchError(f"state path is unsafe: {path}")
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise PressureWatchError(f"state write readback failed: {path}")


def _run_systemctl(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["systemctl", "--user", *argv],
        text=True,
        capture_output=True,
        check=False,
    )


def evaluate(
    policy: dict[str, Any],
    current: dict[str, Any],
    previous_state: dict[str, Any] | None,
    *,
    systemctl: Callable[[list[str]], subprocess.CompletedProcess[str]] = _run_systemctl,
) -> tuple[dict[str, Any], int]:
    previous_sample = previous_state.get("sample") if isinstance(previous_state, dict) else None
    last_trigger = dict(previous_state.get("last_trigger_unix_by_unit", {})) if isinstance(previous_state, dict) else {}
    growth_bytes = 0
    growth_bytes_per_hour: int | None = None
    growth_sample_seconds: float | None = None
    if isinstance(previous_sample, dict):
        previous_ns = previous_sample.get("observed_at_unix_ns")
        previous_used = previous_sample.get("used_bytes")
        same_filesystem = (
            previous_sample.get("mountpoint") == current.get("mountpoint")
            and previous_sample.get("total_bytes") == current.get("total_bytes")
        )
        if same_filesystem and isinstance(previous_ns, int) and isinstance(previous_used, int):
            elapsed = (current["observed_at_unix_ns"] - previous_ns) / 1_000_000_000
            if elapsed > 0:
                growth_sample_seconds = round(elapsed, 3)
                growth_bytes = max(0, current["used_bytes"] - previous_used)
                if elapsed >= policy["minimum_growth_sample_seconds"]:
                    growth_bytes_per_hour = int(growth_bytes * 3600 / elapsed)
    reasons: list[str] = []
    if current["used_percent"] >= policy["used_percent_threshold"]:
        reasons.append("used-percent")
    if current["available_bytes"] <= policy["available_bytes_threshold"]:
        reasons.append("available-bytes")
    if (
        growth_bytes_per_hour is not None
        and growth_bytes_per_hour >= policy["growth_bytes_per_hour_threshold"]
    ):
        reasons.append("growth-rate")
    pressure = bool(reasons)
    attempts: list[dict[str, Any]] = []
    now_unix = current["observed_at_unix_ns"] // 1_000_000_000
    failed = False
    if pressure:
        for trigger in policy["service_triggers"]:
            unit = trigger["unit"]
            prior = last_trigger.get(unit)
            if isinstance(prior, int) and now_unix - prior < trigger["cooldown_seconds"]:
                attempts.append(
                    {
                        "unit": unit,
                        "outcome": "cooldown",
                        "remaining_seconds": trigger["cooldown_seconds"] - (now_unix - prior),
                    }
                )
                continue
            active = systemctl(["is-active", "--quiet", unit])
            if active.returncode == 0:
                attempts.append({"unit": unit, "outcome": "already-active"})
                continue
            started = systemctl(["--no-block", "start", unit])
            if started.returncode == 0:
                last_trigger[unit] = now_unix
                attempts.append({"unit": unit, "outcome": "start-requested"})
            else:
                failed = True
                attempts.append(
                    {
                        "unit": unit,
                        "outcome": "start-failed",
                        "returncode": started.returncode,
                        "stderr": started.stderr.strip()[:500],
                    }
                )
    status = "healthy"
    if pressure:
        status = "pressure-trigger-failed" if failed else "pressure-observed"
    receipt = {
        "schema_version": 1,
        "kind": "heim_pc_storage_pressure_watch_receipt",
        "status": status,
        "pressure": pressure,
        "reasons": reasons,
        "sample": current,
        "previous_sample_observed_at_unix_ns": (
            previous_sample.get("observed_at_unix_ns") if isinstance(previous_sample, dict) else None
        ),
        "growth_sample_seconds": growth_sample_seconds,
        "growth_bytes": growth_bytes,
        "growth_bytes_per_hour": growth_bytes_per_hour,
        "trigger_attempts": attempts,
        "last_trigger_unix_by_unit": last_trigger,
        "does_not_establish": [
            "maintenance_completion",
            "cleanup_candidate_eligibility",
            "permission_to_delete_sources_or_worktrees",
            "future_storage_convergence",
        ],
    }
    return receipt, 2 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    try:
        policy = load_policy(args.policy.expanduser().resolve())
        state_path = args.state.expanduser().resolve()
        previous = read_state(state_path)
        current = filesystem_sample(policy["mountpoint"])
        receipt, returncode = evaluate(policy, current, previous)
        write_state(state_path, receipt)
    except (PressureWatchError, OSError, ValueError) as exc:
        print(
            json.dumps(
                {"kind": "heim_pc_storage_pressure_watch_error", "error": str(exc)},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(receipt, sort_keys=True, ensure_ascii=False))
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
