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
import sys
import time

MCP_URL = "http://127.0.0.1:18181/mcp"
REFRESH_AFTER_SECONDS = 11 * 60 * 60
TOOL_TIMEOUT = timedelta(minutes=90)
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


def decide(status: dict, *, now: int) -> str:
    """Return skip or refresh; refuse to invalidate proof without a valid backup."""
    if not isinstance(status, dict) or type(now) is not int or now <= 0:
        raise RuntimeError("recovery status is malformed")
    checks = status.get("checks")
    if not isinstance(checks, dict):
        raise RuntimeError("recovery checks are unavailable")
    canonical = status.get("server_recovery")
    publication = status.get("server_recovery_source_publication")
    if (
        status.get("ready_for_privileged_actions") is True
        and isinstance(canonical, dict)
        and canonical.get("valid") is True
        and isinstance(publication, dict)
        and publication.get("current") is True
    ):
        verified_at = canonical.get("generated_at_unix")
        if type(verified_at) is int and 0 <= now - verified_at < REFRESH_AFTER_SECONDS:
            return "skip"
    if any(checks.get(key) is not True for key in PREREQUISITE_CHECKS):
        raise RuntimeError("native backup timer or rootbroker is not ready")
    backup = status.get("local_backup")
    if not isinstance(backup, dict) or backup.get("valid") is not True:
        raise RuntimeError("no journal-bound successful native backup: defer proof")
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


async def _call(session, name: str, *, timeout: timedelta) -> dict:
    result = await session.call_tool(
        name, dict(TOOL_ARGUMENTS), read_timeout_seconds=timeout,
    )
    value = result.structuredContent
    if result.isError or not isinstance(value, dict):
        raise RuntimeError(name + " did not return valid structured evidence")
    return value


async def refresh() -> None:
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
            await session.initialize()
            before = await _call(
                session, "grabowski_recovery_status", timeout=timedelta(seconds=50)
            )
            decision = decide(before, now=int(time.time()))
            if decision == "skip":
                print(json.dumps({
                    "status": "current", "source": "canonical-restic-recovery",
                    "snapshot_id": before.get("server_recovery", {}).get("snapshot_id"),
                }, sort_keys=True), flush=True)
                return
            proof = await _call(
                session, "grabowski_recovery_server_probe", timeout=TOOL_TIMEOUT
            )
            require_published_proof(proof)
            after = await _call(
                session, "grabowski_recovery_status", timeout=timedelta(seconds=50)
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
        # This is a systemd failure, not an opportunity to suppress a red gate.
        print("recovery-refresh-failed: " + type(exc).__name__ + ": " + str(exc)[:240],
              file=sys.stderr, flush=True)
        sys.exit(1)