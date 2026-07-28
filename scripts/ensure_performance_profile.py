#!/usr/bin/env python3
"""Set and verify the System76 performance profile with one narrow ENOENT exception."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Callable

DEFAULT_CONFIG = Path("/etc/heim-pc/host-health-remediation.v1.json")
Runner = Callable[..., subprocess.CompletedProcess[str]]


class ProfileError(RuntimeError):
    pass


def load_policy(path: Path) -> dict[str, Any]:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProfileError(f"cannot load profile policy: {exc}") from exc
    if (
        not isinstance(policy, dict)
        or policy.get("schema_version") != 1
        or policy.get("kind") != "heim_pc_host_health_log_remediation"
    ):
        raise ProfileError("unsupported profile policy")
    profile = policy.get("performance_profile")
    if not isinstance(profile, dict):
        raise ProfileError("performance_profile policy is missing")
    for key in ("set_command", "query_command"):
        command = profile.get(key)
        if (
            not isinstance(command, list)
            or not command
            or not all(isinstance(item, str) and item for item in command)
        ):
            raise ProfileError(f"{key} must be a non-empty argv list")
    expected = profile.get("expected_query_line")
    if not isinstance(expected, str) or not expected:
        raise ProfileError("expected_query_line is missing")
    allowed = profile.get("allowed_missing_scsi_failure")
    if not isinstance(allowed, dict):
        raise ProfileError("allowed_missing_scsi_failure is missing")
    for key in ("required_all", "required_any"):
        markers = allowed.get(key)
        if (
            not isinstance(markers, list)
            or not markers
            or not all(isinstance(item, str) and item for item in markers)
        ):
            raise ProfileError(f"allowed_missing_scsi_failure.{key} is invalid")
    timeout = profile.get("command_timeout_seconds")
    if not isinstance(timeout, int) or not 1 <= timeout <= 60:
        raise ProfileError("command_timeout_seconds must be between 1 and 60")
    return profile


def harmless_missing_scsi_failure(output: str, policy: dict[str, Any]) -> bool:
    normalized = output.casefold()
    allowed = policy["allowed_missing_scsi_failure"]
    required_all = [str(item).casefold() for item in allowed["required_all"]]
    required_any = [str(item).casefold() for item in allowed["required_any"]]
    profile_failures = [
        item.strip()
        for item in re.findall(r"failed to set ([a-z0-9 _-]+) profiles", normalized)
    ]
    forbidden = ("authorization", "permission denied", "timed out", "panic", "fatal")
    return (
        bool(profile_failures)
        and all(item == "scsi host" for item in profile_failures)
        and all(marker in normalized for marker in required_all)
        and any(marker in normalized for marker in required_any)
        and not any(marker in normalized for marker in forbidden)
    )


def _run(
    runner: Runner,
    argv: list[str],
    *,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    try:
        return runner(argv, text=True, capture_output=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProfileError(f"cannot execute {argv[0]}: {exc}") from exc


def ensure_profile(policy: dict[str, Any], *, runner: Runner = subprocess.run) -> tuple[int, dict[str, Any]]:
    timeout = policy["command_timeout_seconds"]
    set_result = _run(runner, list(policy["set_command"]), timeout=timeout)
    set_output = "\n".join(part for part in (set_result.stdout, set_result.stderr) if part)
    allowed_failure = set_result.returncode != 0 and harmless_missing_scsi_failure(
        set_output, policy
    )

    query_result = _run(runner, list(policy["query_command"]), timeout=timeout)
    query_lines = [line.strip() for line in query_result.stdout.splitlines()]
    profile_verified = (
        query_result.returncode == 0 and policy["expected_query_line"] in query_lines
    )
    success = profile_verified and (set_result.returncode == 0 or allowed_failure)
    if set_result.returncode == 0:
        set_outcome = "succeeded"
    elif allowed_failure:
        set_outcome = "allowed_missing_scsi_target"
    else:
        set_outcome = "failed"

    report = {
        "schema_version": 1,
        "kind": "heim_pc_performance_profile_result",
        "success": success,
        "set_outcome": set_outcome,
        "set_returncode": set_result.returncode,
        "query_returncode": query_result.returncode,
        "profile_verified": profile_verified,
        "expected_query_line": policy["expected_query_line"],
        "does_not_establish": [
            "future_profile_persistence_after_firmware_or_kernel_changes",
            "that_non_scsi_profile_errors_are harmless",
        ],
    }
    return (0 if success else 1), report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()
    try:
        policy = load_policy(args.config)
        returncode, report = ensure_profile(policy)
    except ProfileError as exc:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "heim_pc_performance_profile_error",
                    "error": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(report, sort_keys=True))
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
