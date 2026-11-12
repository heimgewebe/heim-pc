"""NixOS adapter for the installed Grabowski signed MCP snapshot observer.

No second tool registry, platform publication claim or runtime mutable source.
The actual tool names and schemas come from the existing MCP tools/list path.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import subprocess
import time

import grabowski_client_snapshot as snapshots


SYSTEMCTL = "/run/current-system/sw/bin/systemctl"
TUNNEL_UNIT = "tunnel-client-grabowski.service"


def _tunnel_identity() -> tuple[int, int]:
    result = subprocess.run(
        [SYSTEMCTL, "--user", "show", TUNNEL_UNIT,
         "--property=ActiveState", "--property=MainPID"],
        capture_output=True, text=True, check=True, timeout=10,
    )
    properties: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, sep, value = line.partition("=")
        if not sep or key not in {"ActiveState", "MainPID"} or key in properties:
            raise ValueError("tunnel systemd identity invalid")
        properties[key] = value
    if set(properties) != {"ActiveState", "MainPID"} or properties["ActiveState"] != "active":
        raise RuntimeError("tunnel is not active")
    pid = int(properties["MainPID"])
    if pid <= 0:
        raise RuntimeError("tunnel main PID unavailable")
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    fields = raw.rpartition(")")[2].strip().split()
    if len(fields) < 20:
        raise ValueError("tunnel process start identity unavailable")
    start_ticks = int(fields[19])
    if start_ticks <= 0:
        raise ValueError("tunnel process start identity invalid")
    return pid, start_ticks


def refresh(expected_release_id: str, *, now_unix: int | None = None) -> dict:
    pid, ticks = _tunnel_identity()
    session_id = snapshots.connector_session_id(pid, ticks)
    now = int(time.time()) if now_unix is None else now_unix
    previous, observer_invalid = snapshots._observer_session_state()
    reason = snapshots._snapshot_refresh_reason(
        session_id=session_id,
        expected_release_id=expected_release_id,
        now_unix=now,
        last_observed_session_id=previous,
        observer_state_invalid=observer_invalid,
    )
    if reason is None:
        if previous is None:
            snapshots._write_observer_state(
                session_id=session_id, release_id=expected_release_id, now_unix=now,
            )
        return {"state": "not_due"}

    capability = snapshots._read_transport_connector_capability(
        snapshots.AUTO_REFRESH_CONNECTOR_TOKEN_PATH
    )
    result = asyncio.run(snapshots._observe_and_bind_snapshot(
        mcp_url=snapshots.AUTO_REFRESH_MCP_URL,
        session_id=session_id,
        connector_capability=capability,
        timeout_seconds=25.0,
    ))
    if (
        result.get("state") != "renewed"
        or result.get("release_id") != expected_release_id
        or result.get("schema_contract_matches") is not True
    ):
        raise RuntimeError("signed MCP snapshot refresh did not verify this NixOS release")
    snapshots._write_observer_state(
        session_id=session_id, release_id=expected_release_id, now_unix=now,
    )
    return {
        "state": "renewed",
        "reason": reason,
        "tool_count": result.get("tool_count"),
        "schema_contract_matches": True,
        "receipt_sha256": result.get("receipt_sha256"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-release-id", required=True)
    args = parser.parse_args()
    try:
        result = refresh(args.expected_release_id)
    except Exception as exc:
        # Provider or transport exceptions can carry private details.
        print(json.dumps({"state": "failed", "error_type": type(exc).__name__}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
