"""NixOS adapter for the installed Grabowski signed MCP snapshot observer.

No second tool registry, platform publication claim or runtime mutable source.
The actual tool names and schemas come from the existing MCP tools/list path.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import re
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


def _previous_observation_session(tunnel_session_id: str) -> str:
    """Reuse only a verified receipt from this tunnel when deciding renewal.

    Each renewed MCP ClientSession is a distinct signed observation. The
    watchdog's persistent marker remains tied to the long-lived tunnel PID.
    """
    try:
        with snapshots._state_lock():
            receipt = snapshots._read_private_json(snapshots.SNAPSHOT_PATH)
        snapshots._validate_receipt(receipt)
    except (OSError, ValueError, snapshots.ClientSnapshotError):
        return tunnel_session_id

    declaration = receipt.get("client_declaration")
    if not isinstance(declaration, dict):
        return tunnel_session_id
    if declaration.get("client_id") != snapshots.AUTO_REFRESH_CLIENT_ID:
        return tunnel_session_id
    observed_session = declaration.get("session_id")
    if observed_session == tunnel_session_id:
        return tunnel_session_id  # Original watchdog receipt, before this fix.
    if isinstance(observed_session, str) and re.fullmatch(
        re.escape(tunnel_session_id) + r"-observation-[0-9]{10,13}",
        observed_session,
    ):
        return observed_session
    return tunnel_session_id


def refresh(expected_release_id: str, *, now_unix: int | None = None) -> dict:
    pid, ticks = _tunnel_identity()
    tunnel_session_id = snapshots.connector_session_id(pid, ticks)
    now = int(time.time()) if now_unix is None else now_unix
    previous, observer_invalid = snapshots._observer_session_state()
    observed_session_id = _previous_observation_session(tunnel_session_id)
    reason = snapshots._snapshot_refresh_reason(
        session_id=observed_session_id,
        expected_release_id=expected_release_id,
        now_unix=now,
        last_observed_session_id=None,
        observer_state_invalid=observer_invalid,
    )
    if previous is not None and previous != tunnel_session_id:
        reason = "connector-session-changed"
    if reason is None:
        if previous is None:
            snapshots._write_observer_state(
                session_id=tunnel_session_id,
                release_id=expected_release_id,
                now_unix=now,
            )
        return {"state": "not_due"}

    # A new tools/list call is a new real MCP client session, not a replay of
    # the previously signed one-call mutation. The server still rejects any
    # repeated exact packet. Never resend a session identity from a receipt.
    new_observation_session_id = f"{tunnel_session_id}-observation-{now}"
    if new_observation_session_id == observed_session_id:
        raise RuntimeError("same observation session was already recorded")

    capability = snapshots._read_transport_connector_capability(
        snapshots.AUTO_REFRESH_CONNECTOR_TOKEN_PATH
    )
    result = asyncio.run(snapshots._observe_and_bind_snapshot(
        mcp_url=snapshots.AUTO_REFRESH_MCP_URL,
        session_id=new_observation_session_id,
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
        session_id=tunnel_session_id, release_id=expected_release_id, now_unix=now,
    )
    return {
        "state": "renewed",
        "reason": reason,
        "tool_count": result.get("tool_count"),
        "schema_contract_matches": True,
        "receipt_sha256": result.get("receipt_sha256"),
    }


def _accepted_generation(package: Path) -> tuple[str, str, int, int, str] | None:
    """Bind publication to the active, persistently approved system, not a build."""
    system = Path("/nix/var/nix/profiles/system")
    approved = Path("/nix/var/nix/profiles/system-profiles/heim-pc-approved")
    try:
        current = Path("/run/current-system").resolve(strict=True)
        if current != system.resolve(strict=True) or current != approved.resolve(strict=True):
            return None
        generation = system.readlink().name
    except FileNotFoundError:
        # A first installation or provisional boot need not have an approved profile.
        return None
    if not re.fullmatch(r"system-[0-9]+-link", generation):
        raise RuntimeError("system generation identity unavailable")
    result = subprocess.run(
        [SYSTEMCTL, "show", "grabowski-operator.service", "--property=MainPID", "--value"],
        capture_output=True, text=True, check=True, timeout=10,
    )
    pid = int(result.stdout.strip())
    if pid <= 0:
        raise RuntimeError("operator service inactive")
    proc = Path(f"/proc/{pid}")
    if not any(
        arg.startswith(str(package).encode() + b"/")
        for arg in (proc / "cmdline").read_bytes().split(b"\x00")
    ):
        raise RuntimeError("serving process is not bound to the immutable package")
    fields = (proc / "stat").read_text(encoding="utf-8").rpartition(")")[2].split()
    if len(fields) < 20 or int(fields[19]) <= 0:
        raise RuntimeError("operator process start identity unavailable")
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    return str(current), generation, pid, int(fields[19]), boot_id


def reconcile_publication(manifest_path: Path, expected_release_id: str) -> dict:
    """Reconcile the existing journal, never assert external catalog convergence."""
    manifest_path = manifest_path.resolve(strict=True)
    package = manifest_path.parents[2]
    if not Path(snapshots.__file__).resolve().is_relative_to(package):
        raise RuntimeError("snapshot implementation is not from the expected package")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["release_id"] != expected_release_id:
        raise RuntimeError("immutable release identity mismatch")
    before = _accepted_generation(package)
    if before is None:
        return {"state": "deferred", "reason": "system-not-approved"}
    with snapshots._state_lock():
        receipt = snapshots._read_private_json(snapshots.SNAPSHOT_PATH)
        snapshots._validate_receipt(receipt)
        current = snapshots._read_publication_current()
    now = int(time.time())
    binding = receipt["server_binding"]
    declaration = receipt["client_declaration"]
    names = manifest["entrypoint_contract"]["expected_tools"]
    count = len(names)
    names_sha = snapshots._sha256_json(sorted(names))
    evidence = receipt.get("schema_evidence") or {}
    artifact = evidence.get("observed_artifact") or {}
    probe = evidence.get("probe") or {}
    schema_sha = artifact.get("complete_schema_sha256")
    if not (
        receipt.get("verified") is True
        and receipt.get("mismatches") == []
        and receipt["created_at_unix"] <= now <= receipt["expires_at_unix"]
        and receipt.get("cutover_transition") is None
        and binding["release_id"] == expected_release_id
        and binding["repo_head"] == manifest["repo_head"]
        and declaration["observed_release_id"] == expected_release_id
        and binding["registered_tool_count"] == count
        and binding["registered_names_sha256"] == names_sha
        and declaration["observed_tool_count"] == count
        and declaration["observed_names_sha256"] == names_sha
        and binding["agent_instructions_sha256"] == manifest["agent_instructions_sha256"]
        and declaration["observed_agent_instructions_sha256"] == manifest["agent_instructions_sha256"]
        and declaration.get("observation_scope") in {
            snapshots.OBSERVATION_SCOPE_SERVER_LOOPBACK,
            snapshots.OBSERVATION_SCOPE_EXTERNAL_CLIENT,
        }
        and probe.get("matches") is True
        and probe.get("schema_contract_matches") is True
        and artifact.get("complete_schema_observable") is True
        and artifact.get("complete_schema_count") == count
        and declaration.get("observed_complete_schema_count") == count
        and declaration.get("observed_complete_schema_sha256") == schema_sha
        and isinstance(schema_sha, str)
        and re.fullmatch(r"[0-9a-f]{64}", schema_sha)
    ):
        return {"state": "deferred", "reason": "complete-current-schema-evidence-required"}
    contract = snapshots._platform_publication_contract(
        registered_tool_count=count, registered_names_sha256=names_sha,
        complete_schema_count=count, complete_schema_sha256=schema_sha,
    )
    # The same generation can be restored after a later activation. Bind a
    # new request to its observed activation epoch, not just its generation.
    # An unchanged semantic contract still reuses the native current request.
    cutover_id = "nixos-snapshot-" + snapshots._sha256_json({
        "activation": before, "repo_head": manifest["repo_head"],
    })
    if _accepted_generation(package) != before:
        return {"state": "deferred", "reason": "generation-changed"}
    request_id = None
    if current is not None and current["state"] == "pending_activation":
        # Recover our own interrupted preparation. The journal's semantic
        # identity, rather than a boot ID, determines whether reuse is valid.
        # A foreign cutover retains its own activation authority.
        request = snapshots._read_publication_request(current["request_id"])
        if not re.fullmatch(
            r"nixos-snapshot-[0-9a-f]{64}",
            request["cutover_id"],
        ):
            return {"state": "deferred", "reason": "foreign-pending-activation"}
        if request["expected_contract"] == contract:
            request_id = request["request_id"]
        # A different verified active contract gets a native successor;
        # activation supersedes the earlier interrupted request.
    if request_id is None:
        prepared = snapshots.prepare_platform_publication_for_runtime(
            registered_tool_count=count, registered_names_sha256=names_sha,
            complete_schema_count=count, complete_schema_sha256=schema_sha,
            cutover_id=cutover_id,
        )
        request_id = prepared["request_id"]
        if prepared["state"] != "pending_activation":
            return {"state": "unchanged", "request_id": request_id}
    if _accepted_generation(package) != before:
        return {"state": "deferred", "reason": "generation-changed-after-prepare"}
    activated = snapshots.activate_platform_publication_request(request_id=request_id)
    if _accepted_generation(package) != before:
        raise RuntimeError("generation changed during publication activation")
    return {"state": activated["state"], "request_id": request_id}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-release-id", required=True)
    parser.add_argument("--runtime-manifest", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = refresh(args.expected_release_id)
        result["publication"] = reconcile_publication(
            args.runtime_manifest, args.expected_release_id,
        )
    except Exception as exc:
        # Provider or transport exceptions can carry private details.
        print(json.dumps({"state": "failed", "error_type": type(exc).__name__}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
