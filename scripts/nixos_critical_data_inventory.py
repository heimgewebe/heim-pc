#!/usr/bin/env python3
"""Aggregate, fail-closed inventory for every non-reproducible Heim-PC data root."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCOPE_CONTRACT = ROOT / "nixos" / "production" / "critical-user-data-contract-v1.json"
ROOT_INVENTORY_SCRIPT = Path(__file__).with_name("nixos_critical_user_data_inventory.py")
SCOPE_KIND = "heim_pc.critical_user_data_scope_contract"
AGGREGATE_KIND = "heim_pc.critical_user_data_aggregate_inventory.v1"
AGGREGATE_ALGORITHM = "member-inventory-sha256-v1"
MAX_CONTRACT_BYTES = 256 * 1024


class AggregateInventoryError(ValueError):
    pass


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _require_sha(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise AggregateInventoryError(f"{label} must be a lowercase SHA-256")
    return value


def _load_regular_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise AggregateInventoryError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise AggregateInventoryError(f"{label} must be a regular file")
    if info.st_size <= 0 or info.st_size > MAX_CONTRACT_BYTES:
        raise AggregateInventoryError(f"{label} size is invalid")
    try:
        payload = path.read_bytes()
        value = json.loads(payload.decode("utf-8", "strict"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AggregateInventoryError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise AggregateInventoryError(f"{label} must be an object")
    return value, payload


def _load_root_inventory_module():
    spec = importlib.util.spec_from_file_location(
        "nixos_critical_user_data_inventory", ROOT_INVENTORY_SCRIPT
    )
    if spec is None or spec.loader is None:
        raise AggregateInventoryError("root inventory implementation is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _docker_quiesced() -> None:
    docker = Path("/usr/bin/docker")
    if not docker.is_file():
        raise AggregateInventoryError("Docker quiescence cannot be verified")
    try:
        result = subprocess.run(
            [str(docker), "ps", "-q"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            env={"PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AggregateInventoryError("Docker quiescence cannot be verified") from exc
    if result.returncode != 0:
        raise AggregateInventoryError("Docker quiescence cannot be verified")
    if result.stdout.strip():
        raise AggregateInventoryError(
            "authoritative Docker-volume inventory requires all containers stopped"
        )


def _canonical_line(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def collect_inventory(
    contract_path: Path,
    *,
    classification_only: bool = False,
    max_exclusion_samples: int = 0,
) -> dict[str, Any]:
    contract_path = Path(contract_path)
    contract, contract_bytes = _load_regular_json(contract_path, "aggregate contract")
    if (
        contract.get("schema_version") != 1
        or contract.get("kind") != SCOPE_KIND
        or contract.get("scope") != "critical-user-data"
        or contract.get("scope_semantics") != "explicit-positive-selection"
    ):
        raise AggregateInventoryError("aggregate contract identity is invalid")

    members = contract.get("members")
    if not isinstance(members, list) or not members:
        raise AggregateInventoryError("aggregate contract members are missing")
    expected_ids = {"home"}
    observed_ids = {item.get("id") for item in members if isinstance(item, dict)}
    if observed_ids != expected_ids or len(members) != len(expected_ids):
        raise AggregateInventoryError("aggregate contract member set is invalid")

    implementation = contract.get("inventory_implementation")
    if not isinstance(implementation, dict):
        raise AggregateInventoryError("aggregate inventory implementation binding is missing")
    expected_root_script = _require_sha(
        implementation.get("root_inventory_script_sha256"),
        "root inventory implementation digest",
    )
    expected_aggregate_script = _require_sha(
        implementation.get("aggregate_inventory_script_sha256"),
        "aggregate inventory implementation digest",
    )
    try:
        root_script_bytes = ROOT_INVENTORY_SCRIPT.read_bytes()
        aggregate_script_bytes = Path(__file__).read_bytes()
    except OSError as exc:
        raise AggregateInventoryError("inventory implementation cannot be read") from exc
    if _sha256_bytes(root_script_bytes) != expected_root_script:
        raise AggregateInventoryError("root inventory implementation digest mismatch")
    if _sha256_bytes(aggregate_script_bytes) != expected_aggregate_script:
        raise AggregateInventoryError("aggregate inventory implementation digest mismatch")

    root_inventory = _load_root_inventory_module()
    aggregate_digest = hashlib.sha256() if not classification_only else None
    member_results: list[dict[str, Any]] = []
    total_records = 0
    total_regular_bytes = 0
    total_exclusion_boundaries = 0

    for member in sorted(members, key=lambda item: str(item.get("id"))):
        if not isinstance(member, dict) or set(member) != {
            "id",
            "contract_file",
            "contract_sha256",
            "destination",
            "restore_mode",
        }:
            raise AggregateInventoryError("aggregate contract member is malformed")
        member_id = member["id"]
        contract_file = member["contract_file"]
        if (
            not isinstance(member_id, str)
            or member_id not in expected_ids
            or not isinstance(contract_file, str)
            or not contract_file
            or "/" in contract_file
            or contract_file in {".", ".."}
        ):
            raise AggregateInventoryError("aggregate contract member identity is invalid")
        member_path = contract_path.parent / contract_file
        member_contract, member_bytes = _load_regular_json(
            member_path, f"{member_id} member contract"
        )
        expected_member_sha = _require_sha(
            member["contract_sha256"], f"{member_id} member contract digest"
        )
        if _sha256_bytes(member_bytes) != expected_member_sha:
            raise AggregateInventoryError(f"{member_id} member contract digest mismatch")
        if member_contract.get("kind") != SCOPE_KIND:
            raise AggregateInventoryError(f"{member_id} member contract kind mismatch")
        if (
            member_id != "home"
            or member_contract.get("scope") != "critical-user-data-home"
            or member_contract.get("scope_semantics") != "explicit-path-set"
            or member_contract.get("root") != "/home/alex"
        ):
            raise AggregateInventoryError("home member contract identity mismatch")

        try:
            result = root_inventory.collect_inventory(
                member_path,
                classification_only=classification_only,
                max_exclusion_samples=max_exclusion_samples,
            )
        except root_inventory.InventoryError as exc:
            raise AggregateInventoryError(
                f"{member_id} member inventory failed closed"
            ) from exc

        if result.get("scope") != member_contract.get("scope"):
            raise AggregateInventoryError(f"{member_id} member inventory scope mismatch")
        if not classification_only:
            member_digest = _require_sha(
                result.get("inventory_sha256"), f"{member_id} member inventory digest"
            )
            assert aggregate_digest is not None
            aggregate_digest.update(
                _canonical_line(
                    {
                        "id": member_id,
                        "contract_sha256": expected_member_sha,
                        "inventory_sha256": member_digest,
                    }
                )
            )

        total_records += int(result.get("record_count", 0))
        total_regular_bytes += int(result.get("regular_file_bytes", 0))
        total_exclusion_boundaries += int(result.get("exclusion_boundary_count", 0))
        member_results.append(
            {
                "id": member_id,
                "scope": result.get("scope"),
                "contract_sha256": expected_member_sha,
                "inventory_sha256": result.get("inventory_sha256"),
                "record_count": result.get("record_count"),
                "regular_file_bytes": result.get("regular_file_bytes"),
                "exclusion_boundary_count": result.get("exclusion_boundary_count"),
            }
        )

    scope_sha = _sha256_bytes(contract_bytes)
    return {
        "schema_version": 1,
        "kind": AGGREGATE_KIND,
        "scope": "critical-user-data",
        "scope_semantics": "explicit-positive-selection",
        "algorithm": AGGREGATE_ALGORITHM,
        "critical_scope_sha256": scope_sha,
        "contract_sha256": scope_sha,
        "authoritative_inventory": not classification_only,
        "inventory_sha256": (
            aggregate_digest.hexdigest() if aggregate_digest is not None else None
        ),
        "member_count": len(member_results),
        "members": member_results,
        "record_count": total_records,
        "regular_file_bytes": total_regular_bytes,
        "exclusion_boundary_count": total_exclusion_boundaries,
        "production_effects_authorized": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, default=DEFAULT_SCOPE_CONTRACT)
    parser.add_argument("--classification-only", action="store_true")
    parser.add_argument("--expected-script-sha256")
    parser.add_argument("--expected-contract-sha256")
    parser.add_argument("--max-exclusion-samples", type=int, default=0)
    args = parser.parse_args(argv)
    try:
        if bool(args.expected_script_sha256) != bool(args.expected_contract_sha256):
            raise AggregateInventoryError(
                "source pinning requires both expected SHA-256 values"
            )
        if args.expected_script_sha256:
            expected_script = _require_sha(
                args.expected_script_sha256, "expected script digest"
            )
            expected_contract = _require_sha(
                args.expected_contract_sha256, "expected contract digest"
            )
            if _sha256_bytes(Path(__file__).read_bytes()) != expected_script:
                raise AggregateInventoryError("aggregate inventory script digest mismatch")
            if _sha256_bytes(args.contract.read_bytes()) != expected_contract:
                raise AggregateInventoryError("aggregate contract digest mismatch")
        result = collect_inventory(
            args.contract,
            classification_only=args.classification_only,
            max_exclusion_samples=args.max_exclusion_samples,
        )
    except (AggregateInventoryError, OSError):
        print("critical aggregate inventory blocked by a safety check", file=os.sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
