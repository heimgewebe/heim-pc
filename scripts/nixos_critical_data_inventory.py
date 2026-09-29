#!/usr/bin/env python3
"""Aggregate, fail-closed inventory for every non-reproducible Heim-PC data root."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import types
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCOPE_CONTRACT = ROOT / "nixos" / "production" / "critical-user-data-contract-v1.json"
ROOT_INVENTORY_SCRIPT = Path(__file__).resolve().with_name("nixos_critical_user_data_inventory.py")
SCOPE_KIND = "heim_pc.critical_user_data_scope_contract"
AGGREGATE_KIND = "heim_pc.critical_user_data_aggregate_inventory.v1"
AGGREGATE_ALGORITHM = "member-inventory-sha256-v1"
AGGREGATE_EXECUTION_MODE = "external-verified-payload-exec-v1"
_VERIFIED_EXECUTION = False
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


def _load_root_inventory_module(payload: bytes):
    try:
        code = compile(payload, str(ROOT_INVENTORY_SCRIPT), "exec")
    except (SyntaxError, ValueError) as exc:
        raise AggregateInventoryError("root inventory implementation is invalid") from exc
    module = types.ModuleType("nixos_critical_user_data_inventory")
    module.__file__ = str(ROOT_INVENTORY_SCRIPT)
    exec(code, module.__dict__)
    module._VERIFIED_EXECUTION = True
    return module


def _load_aggregate_inventory_module(payload: bytes):
    path = Path(__file__).resolve()
    try:
        code = compile(payload, str(path), "exec")
    except (SyntaxError, ValueError) as exc:
        raise AggregateInventoryError("aggregate inventory implementation is invalid") from exc
    module = types.ModuleType("nixos_critical_data_inventory_verified")
    module.__file__ = str(path)
    exec(code, module.__dict__)
    module._VERIFIED_EXECUTION = True
    return module



def _canonical_line(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")



def _validate_home_materialization_policy(contract: dict[str, Any]) -> None:
    policy = contract.get("materialization_policy")
    cold_root = "/var/lib/heim-pc-data/import/legacy-2026"
    authority_classes = {
        "grabowski-authority-state",
        "grabowski-audit-chain",
        "grabowski-durable-outbox",
        "bureau-authority-state",
        "chronik-history-state",
        "observer-findings",
    }
    if (
        not isinstance(policy, dict)
        or policy.get("schema_version") != 1
        or policy.get("kind") != "heim_pc.critical_user_data_materialization_policy"
        or policy.get("source_scope_and_nixos_target_layout_are_separate") is not True
        or policy.get("source_equivalent_disposable_restore_required") is not True
        or policy.get("cold_import_root") != cold_root
        or policy.get("first_productive_boot_requires_cold_import_completion") is not False
    ):
        raise AggregateInventoryError("home materialization policy identity is invalid")

    roles = policy.get("roles")
    if not isinstance(roles, dict) or set(roles) != {
        "bootstrap-direct",
        "authority-reconcile",
        "cold-preservation",
    }:
        raise AggregateInventoryError("home materialization roles are invalid")
    bootstrap = roles["bootstrap-direct"]
    authority = roles["authority-reconcile"]
    cold = roles["cold-preservation"]
    if (
        bootstrap.get("classes") != ["credentials-and-identity"]
        or bootstrap.get("nixos_storage_domain") != "@home"
        or bootstrap.get("target_mapping") != "same-absolute-path"
        or bootstrap.get("source_path_is_live_target_path") is not True
        or bootstrap.get("activation") != "direct-after-verified-restore"
    ):
        raise AggregateInventoryError("bootstrap materialization policy is invalid")
    if (
        set(authority.get("classes", [])) != authority_classes
        or authority.get("nixos_storage_domain") != "@data"
        or authority.get("staging_root") != cold_root + "/authority"
        or authority.get("target_mapping") != "source-path-relative-to-/home/alex"
        or authority.get("source_path_is_live_target_path") is not False
        or authority.get("activation") != "service-specific-restore-reconcile-only"
        or authority.get("direct_activation_forbidden") is not True
    ):
        raise AggregateInventoryError("authority materialization policy is invalid")
    if (
        set(cold.get("classes", []))
        != {"legacy-library-preservation", "local-only-repository"}
        or cold.get("nixos_storage_domain") != "@data"
        or cold.get("staging_root") != cold_root
        or cold.get("source_path_is_live_target_path") is not False
        or cold.get("activation") != "future-explicit-import-only"
        or cold.get("required_before_first_productive_boot") is not False
    ):
        raise AggregateInventoryError("cold-preservation materialization policy is invalid")

    entries = policy.get("cold_entries")
    if not isinstance(entries, list) or len(entries) != 3:
        raise AggregateInventoryError("cold-preservation entry set is invalid")
    by_source = {
        item.get("source_path"): item
        for item in entries
        if isinstance(item, dict) and isinstance(item.get("source_path"), str)
    }
    if set(by_source) != {
        "/home/alex/collections/bibliothek",
        "/home/alex/repos/schotter",
        "/home/alex/repos/fotoatelier",
    }:
        raise AggregateInventoryError("cold-preservation source set is invalid")
    library = by_source["/home/alex/collections/bibliothek"]
    if (
        library.get("capsule_kind") != "tree-snapshot"
        or library.get("target_path") != cold_root + "/bibliothek"
        or library.get("manifest_path") != cold_root + "/bibliothek.manifest.json"
        or library.get("old_source_path_becomes_active_path") is not False
        or library.get("future_importer_required") is not True
    ):
        raise AggregateInventoryError("library preservation policy is invalid")
    for name in ("schotter", "fotoatelier"):
        item = by_source[f"/home/alex/repos/{name}"]
        if (
            item.get("capsule_kind") != "git-bundle-plus-working-tree-overlay"
            or item.get("bundle_path") != f"{cold_root}/repos/{name}.gitbundle"
            or item.get("working_tree_overlay_path")
            != f"{cold_root}/repos/{name}-working-tree.tar.zst"
            or item.get("manifest_path") != f"{cold_root}/repos/{name}.manifest.json"
            or item.get("bundle_mode") != "--all"
            or item.get("working_tree_overlay_policy")
            != "required-iff-tracked-dirty-or-untracked"
            or item.get("active_checkout_created_automatically") is not False
        ):
            raise AggregateInventoryError(f"{name} preservation policy is invalid")

    manifest_requirements = policy.get("capsule_manifest_requirements")
    expected_manifest_requirements = {
        "sha256_bound": True,
        "source_path_bound": True,
        "source_inventory_sha256_bound": True,
        "git_ref_tips_bound_for_git_capsules": True,
        "git_head_bound_for_git_capsules": True,
        "working_tree_status_bound_for_git_capsules": True,
    }
    if manifest_requirements != expected_manifest_requirements:
        raise AggregateInventoryError("capsule manifest requirements are invalid")

    includes = contract.get("includes")
    if not isinstance(includes, list):
        raise AggregateInventoryError("home include set is invalid")
    by_path = {
        item.get("path"): item
        for item in includes
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    if by_path.get("/home/alex/collections/bibliothek", {}).get("class") != "legacy-library-preservation":
        raise AggregateInventoryError("library source classification is invalid")
    if by_path.get("/home/alex/collections/bibliothek", {}).get("restore_mode") != "cold-preservation-tree":
        raise AggregateInventoryError("library source restore mode is invalid")
    for name in ("schotter", "fotoatelier"):
        repo = by_path.get(f"/home/alex/repos/{name}", {})
        if (
            repo.get("class") != "local-only-repository"
            or repo.get("restore_mode") != "cold-preservation-git-capsule"
        ):
            raise AggregateInventoryError(f"{name} source restore mode is invalid")


def collect_inventory(
    contract_path: Path,
    *,
    classification_only: bool = False,
    max_exclusion_samples: int = 0,
    _contract_snapshot: tuple[dict[str, Any], bytes] | None = None,
    _aggregate_script_bytes: bytes | None = None,
) -> dict[str, Any]:
    contract_path = Path(contract_path)
    if not classification_only and not _VERIFIED_EXECUTION:
        raise AggregateInventoryError(
            "authoritative aggregate inventory requires verified payload execution"
        )
    if _contract_snapshot is None:
        contract, contract_bytes = _load_regular_json(
            contract_path, "aggregate contract"
        )
    else:
        contract, contract_bytes = _contract_snapshot
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
    expected_implementation_keys = {
        "algorithm",
        "root_inventory_script",
        "root_inventory_script_sha256",
        "aggregate_inventory_script",
        "aggregate_inventory_script_sha256",
        "aggregate_execution_mode",
        "member_contract_digest_bound",
        "source_and_restored_aggregate_inventory_sha256_must_match",
        "authoritative_member_source_stability",
    }
    if (
        not isinstance(implementation, dict)
        or set(implementation) != expected_implementation_keys
        or implementation.get("algorithm") != AGGREGATE_ALGORITHM
        or implementation.get("root_inventory_script")
        != "scripts/nixos_critical_user_data_inventory.py"
        or implementation.get("aggregate_inventory_script")
        != "scripts/nixos_critical_data_inventory.py"
        or implementation.get("aggregate_execution_mode")
        != AGGREGATE_EXECUTION_MODE
        or implementation.get("member_contract_digest_bound") is not True
        or implementation.get(
            "source_and_restored_aggregate_inventory_sha256_must_match"
        )
        is not True
        or implementation.get("authoritative_member_source_stability")
        != "kernel-local-pci-nvme-readonly-mountinfo-v3"
    ):
        raise AggregateInventoryError(
            "aggregate inventory implementation binding is invalid"
        )
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
        aggregate_script_bytes = (
            Path(__file__).resolve().read_bytes()
            if _aggregate_script_bytes is None
            else _aggregate_script_bytes
        )
    except OSError as exc:
        raise AggregateInventoryError("inventory implementation cannot be read") from exc
    if _sha256_bytes(root_script_bytes) != expected_root_script:
        raise AggregateInventoryError("root inventory implementation digest mismatch")
    if _sha256_bytes(aggregate_script_bytes) != expected_aggregate_script:
        raise AggregateInventoryError("aggregate inventory implementation digest mismatch")

    root_inventory = _load_root_inventory_module(root_script_bytes)
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
        _validate_home_materialization_policy(member_contract)

        try:
            result = root_inventory.collect_inventory(
                member_path,
                classification_only=classification_only,
                max_exclusion_samples=max_exclusion_samples,
                _contract_payload=member_bytes,
            )
        except root_inventory.InventoryError as exc:
            raise AggregateInventoryError(
                f"{member_id} member inventory failed closed"
            ) from exc

        if result.get("scope") != member_contract.get("scope"):
            raise AggregateInventoryError(f"{member_id} member inventory scope mismatch")
        result_contract_sha = _require_sha(
            result.get("contract_sha256"),
            f"{member_id} member inventory contract digest",
        )
        if result_contract_sha != expected_member_sha:
            raise AggregateInventoryError(
                f"{member_id} member inventory contract digest mismatch"
            )
        if not classification_only:
            if result.get("authoritative_inventory") is not True:
                raise AggregateInventoryError(
                    f"{member_id} member did not establish authoritative inventory"
                )
            if (
                result.get("source_stability_verified") is not True
                or result.get("source_stability_proof")
                != implementation["authoritative_member_source_stability"]
                or result.get("stability_pass_count") != 2
                or result.get("stability_proof")
                != "two-consecutive-identical-full-captures"
            ):
                raise AggregateInventoryError(
                    f"{member_id} member source stability proof is invalid"
                )
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
        if not args.classification_only:
            raise AggregateInventoryError(
                "authoritative aggregate inventory requires external verified payload executor"
            )
        pin_values = (
            args.expected_script_sha256,
            args.expected_contract_sha256,
        )
        if any(pin_values) and not all(pin_values):
            raise AggregateInventoryError(
                "source pinning requires both expected SHA-256 values"
            )
        if all(pin_values):
            expected_script = _require_sha(
                args.expected_script_sha256, "expected script digest"
            )
            expected_contract = _require_sha(
                args.expected_contract_sha256, "expected contract digest"
            )
            try:
                script_payload = Path(__file__).resolve().read_bytes()
            except OSError as exc:
                raise AggregateInventoryError(
                    "aggregate inventory implementation cannot be read"
                ) from exc
            if _sha256_bytes(script_payload) != expected_script:
                raise AggregateInventoryError(
                    "aggregate inventory script digest mismatch"
                )
            pinned_contract = _load_regular_json(
                args.contract, "aggregate contract"
            )
            if _sha256_bytes(pinned_contract[1]) != expected_contract:
                raise AggregateInventoryError("aggregate contract digest mismatch")

            verified_module = _load_aggregate_inventory_module(script_payload)
            try:
                result = verified_module.collect_inventory(
                    args.contract,
                    classification_only=True,
                    max_exclusion_samples=args.max_exclusion_samples,
                    _contract_snapshot=pinned_contract,
                    _aggregate_script_bytes=script_payload,
                )
            except verified_module.AggregateInventoryError as exc:
                raise AggregateInventoryError(str(exc)) from exc
        else:
            result = collect_inventory(
                args.contract,
                classification_only=True,
                max_exclusion_samples=args.max_exclusion_samples,
            )
    except (AggregateInventoryError, OSError):
        print("critical aggregate inventory blocked by a safety check", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
