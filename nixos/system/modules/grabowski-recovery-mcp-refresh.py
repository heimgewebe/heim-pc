#!/usr/bin/env python3
"""Refresh the native NixOS recovery proof through the running Grabowski MCP MainPID.

The fixed loopback MCP method delegates the root-owned Restic restore, source
marker and canonical publication to the already-authorized operator/broker.
This executable has no privileged command, secret input or variable target.
"""
from __future__ import annotations

import asyncio
from datetime import timedelta
import json
import re
import subprocess
import sys
import time

MCP_URL = "http://127.0.0.1:18181/mcp"
REFRESH_AFTER_SECONDS = 11 * 60 * 60
TOOL_TIMEOUT = timedelta(minutes=90)
BUSY_RETRY_INTERVAL_SECONDS = 60
BUSY_RETRY_ATTEMPTS = 25
# Leave two minutes below TimeoutStartSec=100min for context-manager cleanup.
REFRESH_BUDGET_SECONDS = 98 * 60
STATUS_TIMEOUT = timedelta(seconds=50)
PREREQUISITE_CHECKS = (
    "backup_timer_enabled",
    "backup_timer_active",
    "privileged_broker_ready",
    "kill_switch_clear",
)
TOOL_ARGUMENTS = {
    "reason": "Refresh verified NixOS Restic recovery after native backup",
    "user_intent": "Keep the root restore, source marker and canonical record current",
}


def latest_completed_backup_unix(*, now: int) -> int | None:
    """Read an immutable systemd success outcome, without starting a backup.

    The root probe later authenticates the source snapshot independently.
    Missing/GC'ed or still-running unit evidence cannot supersede a valid proof.
    """
    try:
        result = subprocess.run(
            [
                "/run/current-system/sw/bin/systemctl", "--system",
                "--timestamp=unix", "show", "restic-backups-heim-pc.service",
                "-p", "LoadState", "-p", "ActiveState", "-p", "Result",
                "-p", "ExecMainCode", "-p", "ExecMainStatus",
                "-p", "ExecMainExitTimestamp",
            ], capture_output=True, text=True, timeout=8, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 or len(result.stdout) > 4096:
        return None
    lines = result.stdout.splitlines()
    if any(line.count("=") != 1 for line in lines):
        return None
    fields = dict(line.split("=", 1) for line in lines)
    if (
        len(lines) != len(fields) or len(fields) != 6
        or fields.get("LoadState") != "loaded"
        or fields.get("ActiveState") != "inactive"
        or fields.get("Result") != "success"
        or fields.get("ExecMainCode") != "1"
        or fields.get("ExecMainStatus") != "0"
    ):
        return None
    stamp = fields.get("ExecMainExitTimestamp", "")
    if re.fullmatch(r"@[0-9]+", stamp) is None:
        return None
    finished = int(stamp[1:])
    return finished if 0 < finished <= now + 2 else None


def decide(status: dict, *, now: int, latest_backup_finished_unix: int | None = None) -> str:
    """Reuse intact proof or request a new root-validated recovery proof."""
    if not isinstance(status, dict) or type(now) is not int or now <= 0:
        raise RuntimeError("recovery status is malformed")
    checks = status.get("checks")
    if not isinstance(checks, dict):
        raise RuntimeError("recovery checks are unavailable")
    canonical = status.get("server_recovery")
    publication = status.get("server_recovery_source_publication")
    verified_at = canonical.get("generated_at_unix") if isinstance(canonical, dict) else None
    newer_backup_completed = (
        type(verified_at) is int
        and type(latest_backup_finished_unix) is int
        and latest_backup_finished_unix > verified_at
    )
    if (
        status.get("ready_for_privileged_actions") is True
        and isinstance(canonical, dict)
        and canonical.get("valid") is True
        and isinstance(publication, dict)
        and publication.get("current") is True
    ):
        if (
            type(verified_at) is int
            and 0 <= now - verified_at < REFRESH_AFTER_SECONDS
            and not newer_backup_completed
        ):
            return "skip"
    if any(checks.get(key) is not True for key in PREREQUISITE_CHECKS):
        raise RuntimeError("native backup timer or rootbroker is not ready")
    backup = status.get("local_backup")
    if not isinstance(backup, dict) or backup.get("valid") is not True:
        # An intact old proof must not be displaced by a failed/running
        # backup. But the old source marker necessarily becomes invalid after
        # a *new* completed backup, before this refresh publishes its proof.
        if (
            isinstance(canonical, dict)
            and canonical.get("valid") is True
            and isinstance(publication, dict)
            and publication.get("current") is True
            and not newer_backup_completed
        ):
            return "skip"
        # Native root probe alone checks the latest completed systemd backup
        # invocation, matching Restic snapshot, byte restore and repository
        # integrity before publishing; never use the old marker as admission.
    return "refresh"


def require_published_proof(proof: dict) -> str:
    """Require the actual NixOS-local Rootbroker publication result."""
    if not isinstance(proof, dict):
        raise RuntimeError("native recovery tool returned malformed proof")
    root = proof.get("root_proof")
    canonical = proof.get("canonical_recovery")
    source = proof.get("source_recovery")
    publication = proof.get("publication")
    snapshot_id = proof.get("snapshot_id")
    if not (
        proof.get("restore_probe_valid") is True
        and proof.get("repository_check_valid") is True
        and isinstance(snapshot_id, str)
        and len(snapshot_id) >= 8
        and isinstance(root, dict)
        and root.get("validated") is True
        and isinstance(canonical, dict)
        and canonical.get("valid") is True
        and canonical.get("snapshot_id") == snapshot_id
        and isinstance(source, dict)
        and source.get("valid") is True
        and isinstance(publication, dict)
        and publication.get("success") is True
    ):
        raise RuntimeError("root restore or canonical publication not proven")
    return snapshot_id


class RecoveryRepositoryBusy(RuntimeError):
    """Only the exact server-side exclusive Restic operation-lock conflict."""


async def _call(session, name: str, *, timeout: timedelta) -> dict:
    try:
        result = await session.call_tool(
            name, dict(TOOL_ARGUMENTS), read_timeout_seconds=timeout,
        )
    except Exception as exc:
        if (name == "grabowski_recovery_server_probe"
                and "local recovery repository operation is busy" in str(exc)):
            raise RecoveryRepositoryBusy("recovery repository operation is busy") from exc
        raise
    if result.isError:
        parts = result.content or ()
        if (name == "grabowski_recovery_server_probe"
                and any(isinstance(getattr(part, "text", None), str)
                        and "local recovery repository operation is busy"
                        in part.text for part in parts)):
            raise RecoveryRepositoryBusy("recovery repository operation is busy")
        raise RuntimeError(name + " failed; no verified recovery proof")
    value = result.structuredContent
    if not isinstance(value, dict):
        raise RuntimeError(name + " did not return valid structured evidence")
    return value


def _new_backup_proven(status: dict, *, now: int) -> bool:
    """Accept another worker's proof only after complete canonical readback."""
    if not isinstance(status, dict):
        return False
    finished = latest_completed_backup_unix(now=now)
    canonical = status.get("server_recovery")
    if (type(finished) is not int or not isinstance(canonical, dict)
            or type(canonical.get("generated_at_unix")) is not int
            or canonical["generated_at_unix"] < finished
            or not isinstance(status.get("checks"), dict)
            or not all(v is True for v in status["checks"].values())):
        return False
    return decide(
        status, now=now, latest_backup_finished_unix=finished
    ) == "skip"


def _remaining_timeout(deadline: float, limit: timedelta, *, reserve: float = 0) -> timedelta:
    remaining = deadline - time.monotonic() - reserve
    if remaining <= 0:
        raise RuntimeError("recovery refresh time budget exhausted")
    return min(limit, timedelta(seconds=remaining))


async def _probe_or_wait(session, *, deadline: float) -> tuple[dict | None, dict | None]:
    """Wait for an existing Restic probe; never bypass its exclusive lock."""
    for attempt in range(BUSY_RETRY_ATTEMPTS + 1):
        try:
            return await _call(
                session, "grabowski_recovery_server_probe", timeout=_remaining_timeout(
                    deadline, TOOL_TIMEOUT, reserve=STATUS_TIMEOUT.total_seconds()
                )
            ), None
        except RecoveryRepositoryBusy:
            if attempt == BUSY_RETRY_ATTEMPTS:
                raise RuntimeError("recovery repository remains busy after bounded wait")
            await asyncio.sleep(_remaining_timeout(
                deadline, timedelta(seconds=BUSY_RETRY_INTERVAL_SECONDS),
                reserve=STATUS_TIMEOUT.total_seconds(),
            ).total_seconds())
            status = await _call(
                session, "grabowski_recovery_status",
                timeout=_remaining_timeout(deadline, STATUS_TIMEOUT)
            )
            if _new_backup_proven(status, now=int(time.time())):
                return None, status
    raise AssertionError("unreachable retry state")


async def refresh() -> None:
    deadline = time.monotonic() + REFRESH_BUDGET_SECONDS
    # Keep one authenticated service entrypoint. The already running Grabowski
    # systemd MainPID, never this unprivileged timer client, talks to Rootbroker.
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    async with streamablehttp_client(
        MCP_URL, timeout=12, sse_read_timeout=TOOL_TIMEOUT.total_seconds()
    ) as (reader, writer, _):
        async with ClientSession(
            reader, writer, read_timeout_seconds=TOOL_TIMEOUT
        ) as session:
            await asyncio.wait_for(
                session.initialize(),
                timeout=_remaining_timeout(deadline, STATUS_TIMEOUT).total_seconds(),
            )
            before = await _call(
                session, "grabowski_recovery_status",
                timeout=_remaining_timeout(deadline, STATUS_TIMEOUT)
            )
            now = int(time.time())
            decision = decide(
                before, now=now,
                latest_backup_finished_unix=latest_completed_backup_unix(now=now),
            )
            if decision == "skip":
                print(json.dumps({
                    "status": "current", "source": "canonical-restic-recovery",
                    "snapshot_id": before.get("server_recovery", {}).get("snapshot_id"),
                }, sort_keys=True), flush=True)
                return
            proof, concurrent = await _probe_or_wait(session, deadline=deadline)
            if concurrent is not None:
                print(json.dumps({
                    "status": "current", "source": "concurrent-verified-recovery",
                    "snapshot_id": concurrent["server_recovery"]["snapshot_id"],
                }, sort_keys=True), flush=True)
                return
            require_published_proof(proof)
            after = await _call(
                session, "grabowski_recovery_status",
                timeout=_remaining_timeout(deadline, STATUS_TIMEOUT)
            )
            canonical = after.get("server_recovery")
            source = after.get("server_recovery_source_publication")
            if not (
                after.get("ready_for_privileged_actions") is True
                and isinstance(canonical, dict)
                and canonical.get("valid") is True
                and canonical.get("snapshot_id") == proof["snapshot_id"]
                and isinstance(source, dict)
                and source.get("current") is True
                and isinstance(after.get("checks"), dict)
                and all(v is True for v in after["checks"].values())
            ):
                raise RuntimeError("root/source/canonical recovery readback mismatch")
            print(json.dumps({
                "status": "verified_and_published",
                "snapshot_id": proof["snapshot_id"],
                "checks": len(after["checks"]),
            }, sort_keys=True), flush=True)


def main() -> int:
    if len(sys.argv) != 1:
        raise RuntimeError("fixed scheduled NixOS recovery client accepts no arguments")
    asyncio.run(refresh())
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        # MCP/AnyIO context managers wrap application errors in nested
        # ExceptionGroups. Show the root cause in systemd's journal.
        while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
            exc = exc.exceptions[0]
        print("recovery-refresh-failed: " + type(exc).__name__ + ": " + str(exc)[:240],
              file=sys.stderr, flush=True)
        sys.exit(1)