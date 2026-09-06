#!/usr/bin/env python3
"""Effect-free storage/recovery rehearsal planner for the Heim-PC NixOS migration.

This module validates fresh disposable-target evidence, compiles a *non-authorized*
argv plan for the later T003 sandbox executor, validates independent topology
readback, and validates offline recovery evidence. It deliberately contains no
process-execution primitive and no live block-device discovery. T005 may build
and test this contract; it cannot cross into a block-device effect.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "nixos" / "rehearsal" / "contract-v1.json"
CONTRACT_SHA256 = "3510e57aebb9bb98f410c7908f0e737a473488f4a3f9b15c2748f31089d52f94"
TARGET_KIND = "heim_pc.storage_target_observation"
AUTHORITY_KIND = "heim_pc.nixos_storage_sandbox_authority"
READBACK_KIND = "heim_pc.storage_rehearsal_readback"
RECOVERY_KIND = "heim_pc.offline_recovery_evidence"
EXECUTOR_TASK = "HEIM-PC-NIXOS-MIGRATION-V1-T003"
SANDBOX_RESOURCE = "service.heim-pc-nixos-storage-rehearsal-sandbox"
MOUNT_ROOT = "/mnt/nixos-rehearsal"
BTRFS_STAGE_ROOT = f"{MOUNT_ROOT}/.btrfs-root"
EFI_MOUNT = f"{MOUNT_ROOT}/efi"
RECOVERY_MOUNT = f"{MOUNT_ROOT}/recovery"
FUTURE_SKEW_SECONDS = 5


class RehearsalError(ValueError):
    pass


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def _copy_json(value: Any) -> Any:
    return json.loads(canonical_json(value))


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise RehearsalError(f"{label} must contain exactly: {', '.join(sorted(expected))}")
    return value


def _nonempty_text(value: Any, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise RehearsalError(f"{label} must be text")
    normalized = value.strip()
    if not normalized or "\x00" in normalized or len(normalized.encode("utf-8")) > maximum:
        raise RehearsalError(f"{label} is empty, too large or contains NUL")
    return normalized


def _sha256(value: Any, label: str) -> str:
    text = _nonempty_text(value, label, 64)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise RehearsalError(f"{label} must be lowercase SHA-256")
    return text


def _positive_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise RehearsalError(f"{label} must be a positive integer")
    return value


def _bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise RehearsalError(f"{label} must be boolean")
    return value


def _parse_utc(value: Any, label: str) -> datetime:
    text = _nonempty_text(value, label, 80)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RehearsalError(f"{label} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise RehearsalError(f"{label} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_device(value: Any, label: str) -> str:
    text = _nonempty_text(value, label, 256)
    if not text.startswith("/dev/") or os.path.normpath(text) != text:
        raise RehearsalError(f"{label} must be a canonical /dev path")
    if any(part in {".", ".."} for part in PurePosixPath(text).parts):
        raise RehearsalError(f"{label} contains a non-canonical path component")
    return text


def _canonical_absolute_nondevice(value: Any, label: str) -> str:
    text = _nonempty_text(value, label, 1024)
    path = PurePosixPath(text)
    if not path.is_absolute() or text.startswith("/dev/") or os.path.normpath(text) != text:
        raise RehearsalError(f"{label} must be a canonical absolute non-device path")
    if any(part in {".", ".."} for part in path.parts):
        raise RehearsalError(f"{label} contains a non-canonical path component")
    return text


def _string_list(value: Any, label: str, *, devices: bool = False) -> list[str]:
    if not isinstance(value, list):
        raise RehearsalError(f"{label} must be a list")
    result: list[str] = []
    for index, item in enumerate(value):
        parsed = _canonical_device(item, f"{label}[{index}]") if devices else _nonempty_text(
            item, f"{label}[{index}]", 512
        )
        if parsed in result:
            raise RehearsalError(f"{label} contains duplicates")
        result.append(parsed)
    return sorted(result)


def load_contract() -> dict[str, Any]:
    try:
        value = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RehearsalError(f"cannot read storage rehearsal contract: {exc}") from exc
    if sha256_json(value) != CONTRACT_SHA256:
        raise RehearsalError("storage rehearsal contract digest mismatch")
    _exact_keys(
        value,
        {
            "schema_version",
            "kind",
            "profile",
            "target",
            "topology",
            "runtime_effect_boundary",
            "recovery_evidence_domains",
            "recovery_max_evidence_age_seconds",
            "offline_reconstruction",
        },
        "contract",
    )
    if value["schema_version"] != 1 or value["kind"] != "heim_pc.nixos_storage_rehearsal_contract":
        raise RehearsalError("storage rehearsal contract identity mismatch")
    target = _exact_keys(
        value["target"],
        {
            "allowed_device_kinds", "minimum_size_bytes", "max_evidence_age_seconds",
            "requires_blank", "requires_unmounted", "requires_no_partition_table",
            "requires_no_filesystem_signatures", "production_identity_match_forbidden",
            "production_backing_match_forbidden", "production_mount_match_forbidden",
        },
        "contract.target",
    )
    allowed_kinds = _string_list(target["allowed_device_kinds"], "contract.target.allowed_device_kinds")
    if allowed_kinds != ["loop", "nbd"]:
        raise RehearsalError("contract target kinds must remain loop and nbd")
    _positive_int(target["minimum_size_bytes"], "contract.target.minimum_size_bytes")
    _positive_int(target["max_evidence_age_seconds"], "contract.target.max_evidence_age_seconds")
    for key in (
        "requires_blank", "requires_unmounted", "requires_no_partition_table",
        "requires_no_filesystem_signatures", "production_identity_match_forbidden",
        "production_backing_match_forbidden", "production_mount_match_forbidden",
    ):
        _bool(target[key], f"contract.target.{key}")

    topology = _exact_keys(
        value["topology"], {"partition_table", "partitions", "luks", "btrfs"}, "contract.topology"
    )
    if topology["partition_table"] != "gpt" or not isinstance(topology["partitions"], list):
        raise RehearsalError("contract topology must define a GPT partition list")
    numbers: set[int] = set()
    roles: set[str] = set()
    for index, item in enumerate(topology["partitions"]):
        allowed = {"number", "role", "label", "type_guid", "size", "filesystem"}
        if isinstance(item, dict) and "encryption" in item:
            allowed.add("encryption")
        partition = _exact_keys(item, allowed, f"contract.topology.partitions[{index}]")
        number = _positive_int(partition["number"], f"contract partition {index}.number")
        role = _nonempty_text(partition["role"], f"contract partition {index}.role", 64)
        if number in numbers or role in roles:
            raise RehearsalError("contract partition numbers and roles must be unique")
        numbers.add(number)
        roles.add(role)
        _nonempty_text(partition["label"], f"contract partition {index}.label", 64)
        _nonempty_text(partition["type_guid"], f"contract partition {index}.type_guid", 64)
        _nonempty_text(partition["filesystem"], f"contract partition {index}.filesystem", 32)
        size = partition["size"]
        if not isinstance(size, dict) or size.get("kind") not in {"fixed_mib", "remainder"}:
            raise RehearsalError("contract partition size must be fixed_mib or remainder")
        if size["kind"] == "fixed_mib":
            _exact_keys(size, {"kind", "value"}, f"contract partition {index}.size")
            _positive_int(size["value"], f"contract partition {index}.size.value")
        else:
            _exact_keys(size, {"kind"}, f"contract partition {index}.size")
    if roles != {"efi-system-partition", "recovery-surface", "encrypted-system"}:
        raise RehearsalError("contract partition roles are unsupported")
    luks = _exact_keys(topology["luks"], {"version", "mapper_name"}, "contract.topology.luks")
    if _positive_int(luks["version"], "contract.topology.luks.version") != 2:
        raise RehearsalError("contract LUKS version must remain 2")
    mapper_name = _nonempty_text(luks["mapper_name"], "contract.topology.luks.mapper_name", 64)
    if re.fullmatch(r"[A-Za-z0-9._-]+", mapper_name) is None:
        raise RehearsalError("contract mapper_name is not canonical")
    btrfs = _exact_keys(topology["btrfs"], {"label", "subvolumes"}, "contract.topology.btrfs")
    _nonempty_text(btrfs["label"], "contract.topology.btrfs.label", 64)
    if not isinstance(btrfs["subvolumes"], list) or not btrfs["subvolumes"]:
        raise RehearsalError("contract Btrfs subvolumes must be a non-empty list")
    seen_subvolumes: set[str] = set()
    for index, item in enumerate(btrfs["subvolumes"]):
        subvolume = _exact_keys(item, {"name", "mountpoint"}, f"contract btrfs subvolume {index}")
        name = _nonempty_text(subvolume["name"], f"contract btrfs subvolume {index}.name", 64)
        _canonical_absolute_nondevice(subvolume["mountpoint"], f"contract btrfs subvolume {index}.mountpoint")
        if name in seen_subvolumes:
            raise RehearsalError("contract Btrfs subvolume names must be unique")
        seen_subvolumes.add(name)

    boundary = value["runtime_effect_boundary"]
    if not isinstance(boundary, dict) or _bool(boundary.get("teardown_required"), "contract.runtime_effect_boundary.teardown_required") is not True:
        raise RehearsalError("contract must require rehearsal teardown")
    _positive_int(value["recovery_max_evidence_age_seconds"], "contract.recovery_max_evidence_age_seconds")
    return value


def _partition_by_role(contract: dict[str, Any], role: str) -> dict[str, Any]:
    matches = [item for item in contract["topology"]["partitions"] if item["role"] == role]
    if len(matches) != 1:
        raise RehearsalError(f"contract must contain exactly one {role} partition")
    return matches[0]


def _mapper_path(contract: dict[str, Any]) -> str:
    return f"/dev/mapper/{contract['topology']['luks']['mapper_name']}"


def _sandbox_mounts(contract: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in contract["topology"]["btrfs"]["subvolumes"]:
        name = item["name"]
        suffix = name[1:] if name.startswith("@") else name
        if re.fullmatch(r"[A-Za-z0-9._-]+", suffix) is None:
            raise RehearsalError(f"subvolume name cannot form a sandbox mount: {name}")
        result[name] = f"{MOUNT_ROOT}/mounts/{suffix}"
    return result


def _partition_new_arg(partition: dict[str, Any]) -> str:
    number = partition["number"]
    size = partition["size"]
    end = f"+{size['value']}MiB" if size["kind"] == "fixed_mib" else "0"
    return f"--new={number}:0:{end}"


def _validate_self_digest(value: dict[str, Any], digest_field: str, label: str) -> str:
    claimed = _sha256(value.get(digest_field), f"{label}.{digest_field}")
    material = {key: item for key, item in value.items() if key != digest_field}
    observed = sha256_json(material)
    if claimed != observed:
        raise RehearsalError(f"{label} digest mismatch")
    return claimed


def validate_target_evidence(
    value: Any, *, now: datetime | None = None
) -> dict[str, Any]:
    contract = load_contract()
    target_contract = contract["target"]
    evidence = _exact_keys(
        value,
        {
            "schema_version",
            "kind",
            "source",
            "observed_at",
            "target",
            "production",
            "evidence_sha256",
        },
        "target evidence",
    )
    if evidence["schema_version"] != 1 or evidence["kind"] != TARGET_KIND:
        raise RehearsalError("target evidence identity mismatch")
    if evidence["source"] != "fresh-block-device-readback":
        raise RehearsalError("target evidence must come from fresh-block-device-readback")
    evidence_sha = _validate_self_digest(evidence, "evidence_sha256", "target evidence")
    observed_at = _parse_utc(evidence["observed_at"], "target evidence.observed_at")
    current = (now or _now_utc()).astimezone(timezone.utc)
    age = (current - observed_at).total_seconds()
    if age < -FUTURE_SKEW_SECONDS:
        raise RehearsalError("target evidence is from the future")
    if age > int(target_contract["max_evidence_age_seconds"]):
        raise RehearsalError("target evidence is stale")

    target = _exact_keys(
        evidence["target"],
        {
            "path",
            "device_kind",
            "device_identity",
            "size_bytes",
            "backing_file",
            "blank",
            "mounted",
            "has_partition_table",
            "has_filesystem_signatures",
        },
        "target evidence.target",
    )
    target_path = _canonical_device(target["path"], "target.path")
    device_kind = _nonempty_text(target["device_kind"], "target.device_kind", 32)
    allowed_kinds = list(target_contract["allowed_device_kinds"])
    if device_kind not in allowed_kinds:
        raise RehearsalError("target must be an explicitly disposable loop or nbd device")
    device_pattern = r"/dev/loop[0-9]+" if device_kind == "loop" else r"/dev/nbd[0-9]+"
    if re.fullmatch(device_pattern, target_path) is None:
        raise RehearsalError("target path does not match disposable whole-device kind")
    identity = _nonempty_text(target["device_identity"], "target.device_identity", 512)
    size_bytes = _positive_int(target["size_bytes"], "target.size_bytes")
    if size_bytes < int(target_contract["minimum_size_bytes"]):
        raise RehearsalError("target is too small for the rehearsal topology")
    backing_file = _canonical_absolute_nondevice(target["backing_file"], "target.backing_file")
    blank = _bool(target["blank"], "target.blank")
    mounted = _bool(target["mounted"], "target.mounted")
    has_partition_table = _bool(target["has_partition_table"], "target.has_partition_table")
    has_filesystem_signatures = _bool(
        target["has_filesystem_signatures"], "target.has_filesystem_signatures"
    )
    if target_contract["requires_blank"] and not blank:
        raise RehearsalError("target is not explicitly blank")
    if target_contract["requires_unmounted"] and mounted:
        raise RehearsalError("target or descendant is mounted")
    if target_contract["requires_no_partition_table"] and has_partition_table:
        raise RehearsalError("blank target already has a partition table")
    if target_contract["requires_no_filesystem_signatures"] and has_filesystem_signatures:
        raise RehearsalError("blank target already has filesystem signatures")

    production = _exact_keys(
        evidence["production"],
        {"root_backing_devices", "mounted_devices", "device_identities"},
        "target evidence.production",
    )
    root_backing = _string_list(production["root_backing_devices"], "production.root_backing_devices", devices=True)
    mounted_devices = _string_list(production["mounted_devices"], "production.mounted_devices", devices=True)
    production_identities = _string_list(production["device_identities"], "production.device_identities")
    if target_contract["production_backing_match_forbidden"] and not root_backing:
        raise RehearsalError("production root backing evidence must not be empty")
    if target_contract["production_backing_match_forbidden"] and target_path in root_backing:
        raise RehearsalError("target matches productive root backing")
    if target_contract["production_mount_match_forbidden"] and target_path in mounted_devices:
        raise RehearsalError("target matches a mounted production device")
    if target_contract["production_identity_match_forbidden"] and identity in production_identities:
        raise RehearsalError("target identity matches a production device identity")

    exclusion_material = {
        "schema_version": 1,
        "target_path": target_path,
        "target_identity": identity,
        "target_backing_file": backing_file,
        "production_root_backing_devices": root_backing,
        "production_mounted_devices": mounted_devices,
        "production_device_identities": production_identities,
        "target_evidence_sha256": evidence_sha,
    }
    return {
        "schema_version": 1,
        "kind": "heim_pc.storage_target_preflight",
        "status": "admitted-disposable-blank-target",
        "target_path": target_path,
        "device_kind": device_kind,
        "device_identity": identity,
        "size_bytes": size_bytes,
        "backing_file": backing_file,
        "target_evidence_sha256": evidence_sha,
        "production_exclusion_sha256": sha256_json(exclusion_material),
        "observed_at": evidence["observed_at"],
        "age_seconds": max(0, int(age)),
        "production_effects_authorized": False,
    }


def validate_sandbox_authority(
    value: Any, preflight: dict[str, Any], *, now: datetime | None = None
) -> dict[str, Any]:
    authority = _exact_keys(
        value,
        {
            "schema_version",
            "kind",
            "source_task",
            "run_id",
            "resource",
            "exclusive",
            "target_path",
            "target_identity",
            "production_exclusion_sha256",
            "observed_at",
            "expires_at",
            "receipt_sha256",
        },
        "sandbox authority",
    )
    if authority["schema_version"] != 1 or authority["kind"] != AUTHORITY_KIND:
        raise RehearsalError("sandbox authority identity mismatch")
    if authority["source_task"] != EXECUTOR_TASK:
        raise RehearsalError("sandbox authority must be produced for T003")
    if authority["resource"] != SANDBOX_RESOURCE or authority["exclusive"] is not True:
        raise RehearsalError("sandbox authority is not exclusive for the canonical resource")
    if _canonical_device(authority["target_path"], "sandbox authority.target_path") != preflight["target_path"]:
        raise RehearsalError("sandbox authority target path mismatch")
    if _nonempty_text(authority["target_identity"], "sandbox authority.target_identity") != preflight["device_identity"]:
        raise RehearsalError("sandbox authority target identity mismatch")
    if _sha256(authority["production_exclusion_sha256"], "sandbox authority.production_exclusion_sha256") != preflight["production_exclusion_sha256"]:
        raise RehearsalError("sandbox authority production exclusion mismatch")
    _nonempty_text(authority["run_id"], "sandbox authority.run_id", 128)
    receipt_sha = _validate_self_digest(authority, "receipt_sha256", "sandbox authority")
    observed = _parse_utc(authority["observed_at"], "sandbox authority.observed_at")
    expires = _parse_utc(authority["expires_at"], "sandbox authority.expires_at")
    current = (now or _now_utc()).astimezone(timezone.utc)
    if (observed - current).total_seconds() > FUTURE_SKEW_SECONDS:
        raise RehearsalError("sandbox authority is from the future")
    if expires <= current:
        raise RehearsalError("sandbox authority is expired")
    if expires <= observed:
        raise RehearsalError("sandbox authority expiry is invalid")
    return {
        "schema_version": 1,
        "kind": AUTHORITY_KIND,
        "receipt_sha256": receipt_sha,
        "run_id": authority["run_id"],
        "target_path": preflight["target_path"],
        "target_identity": preflight["device_identity"],
        "production_exclusion_sha256": preflight["production_exclusion_sha256"],
        "expires_at": authority["expires_at"],
    }


def _partition_path(target_path: str, number: int) -> str:
    suffix = f"p{number}" if target_path[-1].isdigit() else str(number)
    return f"{target_path}{suffix}"


def _effect_plan_sha256(material: dict[str, Any]) -> str:
    # ``age_seconds`` is a diagnostic derived from the validation clock, not
    # part of the target-evidence identity.  Excluding only that derived value
    # keeps a plan stable while the same still-fresh evidence and authority are
    # revalidated at a later instant; observed_at and the evidence/authority
    # digests remain bound into the plan.
    digest_material = _copy_json(material)
    digest_material["target_preflight"].pop("age_seconds", None)
    return sha256_json(digest_material)


def compile_effect_plan(
    target_evidence: Any,
    sandbox_authority: Any,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    contract = load_contract()
    preflight = validate_target_evidence(target_evidence, now=now)
    authority = validate_sandbox_authority(sandbox_authority, preflight, now=now)
    target = preflight["target_path"]
    partitions = sorted(contract["topology"]["partitions"], key=lambda item: item["number"])
    efi = _partition_by_role(contract, "efi-system-partition")
    recovery = _partition_by_role(contract, "recovery-surface")
    encrypted = _partition_by_role(contract, "encrypted-system")
    efi_device = _partition_path(target, efi["number"])
    recovery_device = _partition_path(target, recovery["number"])
    encrypted_device = _partition_path(target, encrypted["number"])
    luks = contract["topology"]["luks"]
    luks_type = f"luks{luks['version']}"
    mapper_name = luks["mapper_name"]
    mapper = _mapper_path(contract)
    btrfs = contract["topology"]["btrfs"]
    sandbox_mounts = _sandbox_mounts(contract)
    subvolumes = [item["name"] for item in btrfs["subvolumes"]]

    mount_targets = [EFI_MOUNT, RECOVERY_MOUNT, BTRFS_STAGE_ROOT, *sandbox_mounts.values()]
    commands: list[dict[str, Any]] = [
        {"effect": "partition-table", "argv": ["sgdisk", "--clear", target]},
    ]
    for partition in partitions:
        number = partition["number"]
        commands.append(
            {
                "effect": f"partition-{partition['role']}",
                "argv": [
                    "sgdisk",
                    _partition_new_arg(partition),
                    f"--typecode={number}:{partition['type_guid']}",
                    f"--change-name={number}:{partition['label']}",
                    target,
                ],
                "partition_role": partition["role"],
            }
        )
    commands.extend([
        {"effect": "partition-table-reread", "argv": ["partprobe", target]},
        {"effect": "udev-settle", "argv": ["udevadm", "settle"]},
        {"effect": "sandbox-mountpoint-create", "argv": ["mkdir", "-p", *mount_targets]},
        {
            "effect": "efi-filesystem",
            "argv": ["mkfs.fat", "-F", "32", "-n", efi["label"], efi_device],
        },
        {
            "effect": "recovery-filesystem",
            "argv": ["mkfs.ext4", "-F", "-L", recovery["label"], recovery_device],
        },
        {
            "effect": "luks-format",
            "argv": ["cryptsetup", "luksFormat", "--type", luks_type, "--key-file", "-", encrypted_device],
            "secret_input": "stdin",
            "secret_binding": "luks-key-v1",
        },
        {
            "effect": "luks-open",
            "argv": [
                "cryptsetup", "open", "--type", luks_type, "--key-file", "-",
                encrypted_device, mapper_name,
            ],
            "secret_input": "stdin",
            "secret_binding": "luks-key-v1",
        },
        {"effect": "btrfs-filesystem", "argv": ["mkfs.btrfs", "-f", "-L", btrfs["label"], mapper]},
        {"effect": "efi-surface-mount", "argv": ["mount", efi_device, EFI_MOUNT]},
        {"effect": "recovery-surface-mount", "argv": ["mount", recovery_device, RECOVERY_MOUNT]},
        {"effect": "btrfs-stage-mount", "argv": ["mount", mapper, BTRFS_STAGE_ROOT]},
    ])
    for name in subvolumes:
        commands.append(
            {
                "effect": "btrfs-subvolume-create",
                "argv": ["btrfs", "subvolume", "create", f"{BTRFS_STAGE_ROOT}/{name}"],
                "subvolume": name,
            }
        )
    commands.append({"effect": "btrfs-stage-unmount", "argv": ["umount", BTRFS_STAGE_ROOT]})
    logical_mounts = {item["name"]: item["mountpoint"] for item in btrfs["subvolumes"]}
    for name in subvolumes:
        commands.append(
            {
                "effect": "btrfs-subvolume-mount",
                "argv": ["mount", "-o", f"subvol={name}", mapper, sandbox_mounts[name]],
                "subvolume": name,
                "logical_mountpoint": logical_mounts[name],
            }
        )

    teardown_commands = [
        {"effect": "btrfs-subvolume-unmount", "argv": ["umount", sandbox_mounts[name]], "subvolume": name}
        for name in reversed(subvolumes)
    ]
    teardown_commands.extend([
        {"effect": "efi-surface-unmount", "argv": ["umount", EFI_MOUNT]},
        {"effect": "recovery-surface-unmount", "argv": ["umount", RECOVERY_MOUNT]},
        {"effect": "luks-close", "argv": ["cryptsetup", "close", mapper_name]},
    ])

    material = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_storage_effect_plan",
        "contract_sha256": CONTRACT_SHA256,
        "target_preflight": preflight,
        "sandbox_authority_receipt_sha256": authority["receipt_sha256"],
        "runtime_executor_task": EXECUTOR_TASK,
        "exclusive_resource": SANDBOX_RESOURCE,
        "commands": commands,
        "teardown_commands": teardown_commands,
        "teardown_required": contract["runtime_effect_boundary"]["teardown_required"],
        "expected_readback": {
            "partition_table": contract["topology"]["partition_table"],
            "partitions": _copy_json(partitions),
            "luks": _copy_json(luks),
            "btrfs": {**_copy_json(btrfs), "sandbox_mounts": dict(sandbox_mounts)},
            "efi": {
                "device": efi_device,
                "filesystem": efi["filesystem"],
                "sandbox_mountpoint": EFI_MOUNT,
            },
            "recovery": {
                "device": recovery_device,
                "filesystem": recovery["filesystem"],
                "sandbox_mountpoint": RECOVERY_MOUNT,
            },
        },
        "execution_authorized": False,
        "production_effects_authorized": False,
        "requires_runtime_executor_reauthentication": True,
    }
    return {**material, "plan_sha256": _effect_plan_sha256(material)}


def validate_topology_readback(
    value: Any,
    target_evidence: Any,
    sandbox_authority: Any,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    plan = compile_effect_plan(target_evidence, sandbox_authority, now=now)
    readback = _exact_keys(
        value,
        {
            "schema_version",
            "kind",
            "source",
            "observed_at",
            "target_path",
            "plan_sha256",
            "gpt",
            "luks",
            "btrfs",
            "efi",
            "recovery",
            "readback_sha256",
        },
        "topology readback",
    )
    if readback["schema_version"] != 1 or readback["kind"] != READBACK_KIND:
        raise RehearsalError("topology readback identity mismatch")
    if readback["source"] != "independent-runtime-readback":
        raise RehearsalError("topology readback source is not independent")
    readback_sha = _validate_self_digest(readback, "readback_sha256", "topology readback")
    observed = _parse_utc(readback["observed_at"], "topology readback.observed_at")
    current = (now or _now_utc()).astimezone(timezone.utc)
    age = (current - observed).total_seconds()
    if age < -FUTURE_SKEW_SECONDS or age > load_contract()["target"]["max_evidence_age_seconds"]:
        raise RehearsalError("topology readback is stale or from the future")
    if _canonical_device(readback["target_path"], "topology readback.target_path") != plan["target_preflight"]["target_path"]:
        raise RehearsalError("topology readback target mismatch")
    if _sha256(readback["plan_sha256"], "topology readback.plan_sha256") != plan["plan_sha256"]:
        raise RehearsalError("topology readback plan mismatch")

    contract = load_contract()
    expected_partitions = contract["topology"]["partitions"]
    gpt = _exact_keys(readback["gpt"], {"partition_table", "partitions"}, "topology readback.gpt")
    if gpt["partition_table"] != "gpt" or not isinstance(gpt["partitions"], list):
        raise RehearsalError("GPT readback is invalid")
    normalized_partitions: list[dict[str, Any]] = []
    for index, item in enumerate(gpt["partitions"]):
        partition = _exact_keys(
            item,
            {"number", "role", "label", "type_guid", "device", "size_bytes"},
            f"topology readback.gpt.partitions[{index}]",
        )
        normalized_partitions.append(
            {
                "number": _positive_int(partition["number"], f"partition[{index}].number"),
                "role": _nonempty_text(partition["role"], f"partition[{index}].role"),
                "label": _nonempty_text(partition["label"], f"partition[{index}].label"),
                "type_guid": _nonempty_text(partition["type_guid"], f"partition[{index}].type_guid", 64).upper(),
                "device": _canonical_device(partition["device"], f"partition[{index}].device"),
                "size_bytes": _positive_int(partition["size_bytes"], f"partition[{index}].size_bytes"),
            }
        )
    normalized_partitions.sort(key=lambda item: item["number"])
    expected_summary = [
        {
            "number": item["number"],
            "role": item["role"],
            "label": item["label"],
            "type_guid": item["type_guid"].upper(),
            "device": _partition_path(plan["target_preflight"]["target_path"], item["number"]),
        }
        for item in expected_partitions
    ]
    observed_metadata = [{key: item[key] for key in ("number", "role", "label", "type_guid", "device")} for item in normalized_partitions]
    if observed_metadata != expected_summary:
        raise RehearsalError("partition topology readback differs from contract")
    for observed_partition, expected_partition in zip(normalized_partitions, expected_partitions):
        size = expected_partition["size"]
        if size["kind"] == "fixed_mib" and observed_partition["size_bytes"] != size["value"] * 1024**2:
            raise RehearsalError("partition size readback differs from contract")

    expected_luks = contract["topology"]["luks"]
    encrypted_partition = _partition_by_role(contract, "encrypted-system")
    encrypted_device = _partition_path(
        plan["target_preflight"]["target_path"], encrypted_partition["number"]
    )
    luks = _exact_keys(readback["luks"], {"version", "container_device", "mapper_name", "unlocked"}, "topology readback.luks")
    if (
        luks["version"] != expected_luks["version"]
        or luks["mapper_name"] != expected_luks["mapper_name"]
        or luks["unlocked"] is not True
    ):
        raise RehearsalError(f"LUKS{expected_luks['version']} readback is not unlocked as expected")
    if _canonical_device(luks["container_device"], "luks.container_device") != encrypted_device:
        raise RehearsalError("LUKS container device mismatch")

    btrfs = _exact_keys(
        readback["btrfs"],
        {"label", "device", "subvolumes", "mounts", "sandbox_mounts"},
        "topology readback.btrfs",
    )
    expected_btrfs = contract["topology"]["btrfs"]
    sandbox_mounts = _sandbox_mounts(contract)
    if (
        btrfs["label"] != expected_btrfs["label"]
        or _canonical_device(btrfs["device"], "btrfs.device") != _mapper_path(contract)
    ):
        raise RehearsalError("Btrfs readback identity mismatch")
    expected_subvolumes = [item["name"] for item in expected_btrfs["subvolumes"]]
    if _string_list(btrfs["subvolumes"], "btrfs.subvolumes") != sorted(expected_subvolumes):
        raise RehearsalError("Btrfs subvolume readback mismatch")
    if not isinstance(btrfs["mounts"], dict):
        raise RehearsalError("Btrfs mounts must be an object")
    expected_mounts = {item["mountpoint"]: item["name"] for item in contract["topology"]["btrfs"]["subvolumes"]}
    if btrfs["mounts"] != expected_mounts:
        raise RehearsalError("Btrfs mount readback mismatch")
    if btrfs["sandbox_mounts"] != sandbox_mounts:
        raise RehearsalError("Btrfs sandbox mount readback mismatch")

    efi = _exact_keys(
        readback["efi"],
        {"device", "filesystem", "sandbox_mountpoint"},
        "topology readback.efi",
    )
    expected_efi = _partition_by_role(contract, "efi-system-partition")
    expected_efi_device = _partition_path(
        plan["target_preflight"]["target_path"], expected_efi["number"]
    )
    if _canonical_device(efi["device"], "efi.device") != expected_efi_device:
        raise RehearsalError("EFI partition device mismatch")
    if efi["filesystem"] != expected_efi["filesystem"] or efi["sandbox_mountpoint"] != EFI_MOUNT:
        raise RehearsalError("EFI surface readback mismatch")

    recovery = _exact_keys(
        readback["recovery"],
        {"device", "filesystem", "surface_present", "sandbox_mountpoint"},
        "topology readback.recovery",
    )
    expected_recovery = _partition_by_role(contract, "recovery-surface")
    expected_recovery_device = _partition_path(
        plan["target_preflight"]["target_path"], expected_recovery["number"]
    )
    if _canonical_device(recovery["device"], "recovery.device") != expected_recovery_device:
        raise RehearsalError("recovery partition device mismatch")
    if (
        recovery["filesystem"] != expected_recovery["filesystem"]
        or recovery["surface_present"] is not True
        or recovery["sandbox_mountpoint"] != RECOVERY_MOUNT
    ):
        raise RehearsalError("recovery surface readback mismatch")

    return {
        "schema_version": 1,
        "kind": "heim_pc.storage_rehearsal_topology_acceptance",
        "status": "passed",
        "target_path": plan["target_preflight"]["target_path"],
        "plan_sha256": plan["plan_sha256"],
        "readback_sha256": readback_sha,
        "independent_readback": True,
        "production_effects_authorized": False,
    }


def validate_recovery_evidence(value: Any, *, now: datetime | None = None) -> dict[str, Any]:
    contract = load_contract()
    evidence = _exact_keys(
        value,
        {"schema_version", "kind", "observed_at", "domains", "evidence_sha256"},
        "recovery evidence",
    )
    if evidence["schema_version"] != 1 or evidence["kind"] != RECOVERY_KIND:
        raise RehearsalError("recovery evidence identity mismatch")
    evidence_sha = _validate_self_digest(evidence, "evidence_sha256", "recovery evidence")
    observed = _parse_utc(evidence["observed_at"], "recovery evidence.observed_at")
    current = (now or _now_utc()).astimezone(timezone.utc)
    recovery_age = (current - observed).total_seconds()
    if recovery_age < -FUTURE_SKEW_SECONDS:
        raise RehearsalError("recovery evidence is from the future")
    if recovery_age > contract["recovery_max_evidence_age_seconds"]:
        raise RehearsalError("recovery evidence is stale")
    domains = evidence["domains"]
    required = list(contract["recovery_evidence_domains"])
    if not isinstance(domains, dict) or set(domains) != set(required):
        raise RehearsalError("recovery evidence domains are incomplete")
    normalized: dict[str, Any] = {}
    for name in required:
        item = _exact_keys(
            domains[name],
            {"status", "source", "observed_at", "evidence_sha256", "independence"},
            f"recovery evidence.domains.{name}",
        )
        if item["status"] != "verified" or item["source"] != "off-host":
            raise RehearsalError(f"recovery domain {name} is not verified off-host")
        domain_observed = _parse_utc(item["observed_at"], f"recovery domain {name}.observed_at")
        domain_age = (current - domain_observed).total_seconds()
        if domain_age < -FUTURE_SKEW_SECONDS or domain_age > contract["recovery_max_evidence_age_seconds"]:
            raise RehearsalError(f"recovery domain {name} is stale or from the future")
        if (domain_observed - observed).total_seconds() > FUTURE_SKEW_SECONDS:
            raise RehearsalError(f"recovery domain {name} is newer than the containing observation")
        domain_sha = _sha256(item["evidence_sha256"], f"recovery domain {name}.evidence_sha256")
        independence = _exact_keys(
            item["independence"],
            {"network_required", "production_system_ssd_required", "grabowski_required", "bureau_required"},
            f"recovery domain {name}.independence",
        )
        normalized_independence = {
            key: _bool(value, f"recovery domain {name}.independence.{key}")
            for key, value in independence.items()
        }
        if any(normalized_independence.values()):
            raise RehearsalError(f"recovery domain {name} is not offline/host-independent")
        normalized[name] = {"evidence_sha256": domain_sha, "observed_at": item["observed_at"]}
    return {
        "schema_version": 1,
        "kind": "heim_pc.offline_recovery_acceptance",
        "status": "passed",
        "evidence_sha256": evidence_sha,
        "domains": normalized,
        "reconstruction": _copy_json(contract["offline_reconstruction"]),
        "production_effects_authorized": False,
    }


def _read_json(path: str) -> Any:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("contract")
    preflight = subparsers.add_parser("preflight")
    preflight.add_argument("--target-evidence", required=True)
    plan = subparsers.add_parser("plan")
    plan.add_argument("--target-evidence", required=True)
    plan.add_argument("--sandbox-authority", required=True)
    readback = subparsers.add_parser("validate-readback")
    readback.add_argument("--target-evidence", required=True)
    readback.add_argument("--sandbox-authority", required=True)
    readback.add_argument("--readback", required=True)
    recovery = subparsers.add_parser("validate-recovery")
    recovery.add_argument("--evidence", required=True)
    args = parser.parse_args()

    try:
        if args.command == "contract":
            result = {
                "schema_version": 1,
                "kind": "heim_pc.nixos_storage_rehearsal_contract_projection",
                "contract_sha256": CONTRACT_SHA256,
                "contract": load_contract(),
                "effect_performed": False,
            }
        elif args.command == "preflight":
            result = validate_target_evidence(_read_json(args.target_evidence))
        elif args.command == "plan":
            result = compile_effect_plan(
                _read_json(args.target_evidence), _read_json(args.sandbox_authority)
            )
        elif args.command == "validate-readback":
            result = validate_topology_readback(
                _read_json(args.readback),
                _read_json(args.target_evidence),
                _read_json(args.sandbox_authority),
            )
        else:
            result = validate_recovery_evidence(_read_json(args.evidence))
    except (OSError, json.JSONDecodeError, RehearsalError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "heim_pc.nixos_storage_rehearsal_error",
                    "status": "rejected",
                    "error": str(exc),
                    "effect_performed": False,
                },
                sort_keys=True,
                indent=2,
            )
        )
        return 2

    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
