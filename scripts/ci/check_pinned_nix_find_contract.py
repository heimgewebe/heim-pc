#!/usr/bin/env python3
"""Verify the live-store ENOENT parser against the pinned GNU find binary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import managed_build  # noqa: E402
from scripts import nixos_production_install as installer  # noqa: E402

PULL_TIMEOUT_SECONDS = 300
COMMAND_TIMEOUT_SECONDS = 60
MISSING_DESCENDANT = "/subject/heim-pc-pinned-find-contract-missing"
TRUST_CONTRACT_PATH = ROOT / "nixos" / "production" / "trust-contract-v1.json"


def _run(argv: Sequence[str], *, timeout_seconds: int) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        list(argv),
        env=managed_build._docker_client_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout_seconds,
    )


def _detail(result: subprocess.CompletedProcess[bytes]) -> str:
    stderr = result.stderr.decode("utf-8", errors="replace").strip()
    stdout = result.stdout.decode("utf-8", errors="replace").strip()
    detail = stderr or stdout or "no output"
    return detail[:2000]


def _require_success(result: subprocess.CompletedProcess[bytes], operation: str) -> None:
    if result.returncode != 0:
        raise RuntimeError(f"{operation} failed with exit {result.returncode}: {_detail(result)}")


def verify_managed_nix_verifier_contract(path: Path = TRUST_CONTRACT_PATH) -> dict[str, str]:
    try:
        contract = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("managed Nix verifier trust contract cannot be read") from exc
    if (
        not isinstance(contract, dict)
        or contract.get("schema_version") != 1
        or contract.get("kind") != "heim_pc.nixos_supply_chain_trust_contract"
    ):
        raise RuntimeError("managed Nix verifier trust contract identity mismatch")
    verifier = contract.get("managed_nix_verifier")
    if not isinstance(verifier, dict):
        raise RuntimeError("managed Nix verifier trust contract section is missing")

    runtime = {
        "image_id": installer.PINNED_NIX_IMAGE,
        "image_tag": installer.PINNED_NIX_IMAGE_TAG,
        "image_ref": installer.PINNED_NIX_IMAGE_REF,
    }
    for field, value in runtime.items():
        contract_value = verifier.get(field)
        if not isinstance(contract_value, str) or contract_value != value:
            raise RuntimeError(
                f"managed Nix verifier {field} diverged from trust contract: "
                f"runtime={value!r}, contract={contract_value!r}"
            )
    if managed_build.PINNED_NIX_IMAGE != runtime["image_id"]:
        raise RuntimeError("managed-build Nix image ID diverged from trust contract")
    return runtime


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--trust-contract",
        type=Path,
        default=TRUST_CONTRACT_PATH,
        help="canonical managed-Nix verifier trust contract",
    )
    parser.add_argument(
        "--trust-contract-only",
        action="store_true",
        help="verify only the semantic trust-contract binding; do not invoke Docker",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    verifier = verify_managed_nix_verifier_contract(args.trust_contract)
    if args.trust_contract_only:
        print(
            json.dumps(
                {
                    "kind": "heim_pc.managed_nix_verifier_contract_binding",
                    "managed_nix_verifier": verifier,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0

    docker = managed_build._docker_executable()
    pull = _run(
        [docker, "pull", installer.PINNED_NIX_IMAGE_REF],
        timeout_seconds=PULL_TIMEOUT_SECONDS,
    )
    _require_success(pull, "pulling pinned Nix image")

    inspect = _run(
        [docker, "image", "inspect", "--format", "{{.Id}}", installer.PINNED_NIX_IMAGE_REF],
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
    )
    _require_success(inspect, "inspecting pinned Nix image")
    image_id = inspect.stdout.decode("ascii", errors="strict").strip()
    if image_id != managed_build.PINNED_NIX_IMAGE:
        raise RuntimeError(
            "pinned Nix image reference resolved to an unexpected image ID: "
            f"expected {managed_build.PINNED_NIX_IMAGE}, got {image_id}"
        )

    find_result = _run(
        [
            docker,
            "run",
            "--rm",
            "--network",
            "none",
            "-e",
            "LC_ALL=C",
            "-e",
            "LANG=C",
            "--entrypoint",
            managed_build.NIX_LIVE_SCAN_FIND,
            managed_build.PINNED_NIX_IMAGE,
            MISSING_DESCENDANT,
            "-xdev",
            "-ignore_readdir_race",
            "-printf",
            "%D %i %b\\n",
        ],
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
    )
    if find_result.returncode != 1:
        raise RuntimeError(
            "pinned GNU find missing-path contract changed: "
            f"expected exit 1, got {find_result.returncode}: {_detail(find_result)}"
        )
    if find_result.stdout:
        raise RuntimeError("pinned GNU find emitted filesystem rows for a missing path")

    expected_stderr = (
        os.fsencode(managed_build.NIX_LIVE_SCAN_FIND)
        + b": '"
        + os.fsencode(MISSING_DESCENDANT)
        + b"': No such file or directory\n"
    )
    if find_result.stderr != expected_stderr:
        raise RuntimeError(
            "pinned GNU find diagnostic contract changed: "
            f"expected {expected_stderr!r}, got {find_result.stderr!r}"
        )

    accepted = managed_build._live_store_scan_vanished_descendant_count(
        find_result.returncode, find_result.stderr
    )
    if accepted != 1:
        raise RuntimeError(
            "live-store ENOENT parser rejected the diagnostic emitted by the pinned GNU find"
        )

    print(
        json.dumps(
            {
                "kind": "heim_pc.pinned_nix_find_contract",
                "image_id": image_id,
                "image_ref": installer.PINNED_NIX_IMAGE_REF,
                "find": managed_build.NIX_LIVE_SCAN_FIND,
                "returncode": find_result.returncode,
                "stderr_sha256": hashlib.sha256(find_result.stderr).hexdigest(),
                "accepted_vanished_descendants": accepted,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())