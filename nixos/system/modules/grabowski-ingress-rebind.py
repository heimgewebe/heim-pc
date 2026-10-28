#!/usr/bin/env python3
"""Align the existing signed MCP ingress selector with the pinned NixOS operator.

Only the canonical slot is touched. The upstream ingress module owns the
actual selector lock, compare-and-swap, atomic publication and readback.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys


def _binding(manifest_path: Path) -> dict[str, str]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    release = manifest.get("release_id")
    head = manifest.get("repo_head")
    agent_sha = manifest.get("agent_instructions_sha256")
    expected = manifest.get("entrypoint_contract", {}).get("expected_tools")
    if not isinstance(release, str) or not re.fullmatch(r"[a-zA-Z0-9._-]{1,160}", release):
        raise ValueError("NixOS Grabowski release identity is invalid")
    if not isinstance(head, str) or re.fullmatch(r"[0-9a-f]{40}", head) is None:
        raise ValueError("NixOS Grabowski source revision is invalid")
    if not isinstance(agent_sha, str) or re.fullmatch(r"[0-9a-f]{64}", agent_sha) is None:
        raise ValueError("NixOS Grabowski agent instructions identity is invalid")
    if (
        not isinstance(expected, list) or not expected
        or not all(isinstance(n, str) and n and n.isidentifier() for n in expected)
        or len(set(expected)) != len(expected)
    ):
        raise ValueError("NixOS Grabowski tool registry identity is invalid")
    names_sha = hashlib.sha256(
        json.dumps(sorted(expected), separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    return {
        "release_id": release,
        "repo_head": head,
        "registered_names_sha256": names_sha,
        "agent_instructions_sha256": agent_sha,
    }


def reconcile(manifest_path: Path, selector_path: Path, ingress: object) -> dict[str, str]:
    desired = _binding(manifest_path)
    # Fresh deployments may have no ChatGPT tunnel. Do not provision another
    # service, token or selector on their behalf.
    if not selector_path.exists() and not selector_path.is_symlink():
        return {"status": "ingress_not_configured"}
    current = ingress.read_routing_selector(selector_path)
    if current["selected_slot"] != "canonical":
        # A separately coordinated blue/green cutover owns the green route.
        return {"status": "noncanonical_route"}
    if current["runtime_binding"] == desired:
        return {"status": "already_bound"}
    result = ingress.publish_routing_selector(
        path=selector_path,
        expected_selector_sha256=current["selector_sha256"],
        selected_slot="canonical",
        runtime_binding=desired,
        cutover_id="nixos-native-" + desired["repo_head"][:12],
    )
    if result["selected_slot"] != "canonical" or result["runtime_binding"] != desired:
        raise RuntimeError("NixOS Grabowski ingress selector readback did not match")
    return {"status": "rebound", "selector_sha256": result["selector_sha256"]}


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: grabowski-ingress-rebind.py <immutable-manifest>")
    # Built from the same pinned GitHub tarball as the operator; the
    # existing ingress publisher retains the single atomic CAS authority.
    import grabowski_transport_ingress as ingress

    result = reconcile(
        Path(sys.argv[1]),
        ingress.DEFAULT_SELECTOR_FILE,
        ingress,
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
