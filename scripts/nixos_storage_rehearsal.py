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
CONTRACT_SHA256 = "40fda917530ee0a78426bb6c4f1ce53f48f2108c5cc5b12afed314340d9cc263"
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
MAPPER_PATH = "/dev/mapper/nixos-rehearsal-crypt"
SANDBOX_MOUNT_BY_SUBVOLUME = {
    "@root": f"{MOUNT_ROOT}/mounts/root",
    "@nix": f"{MOUNT_ROOT}/mounts/nix",
    "@persist": f"{MOUNT_ROOT}/mounts/persist",
    "@home": f"{MOUNT_ROOT}/mounts/home",
    "@data": f"{MOUNT_ROOT}/mounts/data",
    "@containers": f"{MOUNT_ROOT}/mounts/containers",
}
FUTURE_SKEW_SECONDS = 5


class RehearsalError(ValueError):
    pass


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _copy_json(value: Any) -> Any:
    return json.loads(json.dumps(value))


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
    raw = CONTRACT_PATH.read_bytes()
    observed = sha256_bytes(raw)
    if observed != CONTRACT_SHA256:
        raise RehearsalError("storage rehearsal contract digest mismatch")
    value = json.loads(raw)
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
            "offline_reconstruction",
        },
        "contract",
    )
    if value["schema_version"] != 1 or value["kind"] != "heim_pc.nixos_storage_rehearsal_contract":
        raise RehearsalError("storage rehearsal contract identity mismatch")
    return value


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
    if _bool(target["blank"], "target.blank") is not True:
        raise RehearsalError("target is not explicitly blank")
    if _bool(target["mounted"], "target.mounted") is not False:
        raise RehearsalError("target or descendant is mounted")
    if _bool(target["has_partition_table"], "target.has_partition_table") is not False:
        raise RehearsalError("blank target already has a partition table")
    if _bool(target["has_filesystem_signatures"], "target.has_filesystem_signatures") is not False:
        raise RehearsalError("blank target already has filesystem signatures")

    production = _exact_keys(
        evidence["production"],
        {"root_backing_devices", "mounted_devices", "device_identities"},
        "target evidence.production",
    )
    root_backing = _string_list(production["root_backing_devices"], "production.root_backing_devices", devices=True)
    mounted_devices = _string_list(production["mounted_devices"], "production.mounted_devices", devices=True)
    production_identities = _string_list(production["device_identities"], "production.device_identities")
    if not root_backing:
        raise RehearsalError("production root backing evidence must not be empty")
    if target_path in root_backing:
        raise RehearsalError("target matches productive root backing")
    if target_path in mounted_devices:
        raise RehearsalError("target matches a mounted production device")
    if identity in production_identities:
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
    p1, p2, p3 = (_partition_path(target, number) for number in (1, 2, 3))
    mapper = MAPPER_PATH
    subvolumes = [item["name"] for item in contract["topology"]["btrfs"]["subvolumes"]]

    mount_targets = [
        EFI_MOUNT,
        RECOVERY_MOUNT,
        BTRFS_STAGE_ROOT,
        *SANDBOX_MOUNT_BY_SUBVOLUME.values(),
    ]
    commands: list[dict[str, Any]] = [
        {"effect": "partition-table", "argv": ["sgdisk", "--clear", target]},
        {
            "effect": "partition-efi",
            "argv": [
                "sgdisk", "--new=1:1MiB:+1024MiB", "--typecode=1:EF00", "--change-name=1:EFI", target,
            ],
        },
        {
            "effect": "partition-recovery",
            "argv": [
                "sgdisk", "--new=2:0:+4096MiB", "--typecode=2:8300", "--change-name=2:RECOVERY", target,
            ],
        },
        {
            "effect": "partition-luks",
            "argv": [
                "sgdisk", "--new=3:0:0", "--typecode=3:8309", "--change-name=3:NIXOS_CRYPT", target,
            ],
        },
        {"effect": "partition-table-reread", "argv": ["partprobe", target]},
        {"effect": "udev-settle", "argv": ["udevadm", "settle"]},
        {"effect": "sandbox-mountpoint-create", "argv": ["mkdir", "-p", *mount_targets]},
        {"effect": "efi-filesystem", "argv": ["mkfs.fat", "-F", "32", "-n", "EFI", p1]},
        {"effect": "recovery-filesystem", "argv": ["mkfs.ext4", "-F", "-L", "RECOVERY", p2]},
        {
            "effect": "luks-format",
            "argv": ["cryptsetup", "luksFormat", "--type", "luks2", "--key-file", "-", p3],
            "secret_input": "stdin",
        },
        {
            "effect": "luks-open",
            "argv": [
                "cryptsetup", "open", "--type", "luks2", "--key-file", "-", p3, "nixos-rehearsal-crypt",
            ],
            "secret_input": "stdin",
        },
        {"effect": "btrfs-filesystem", "argv": ["mkfs.btrfs", "-f", "-L", "NIXOS_SYSTEM", mapper]},
        {"effect": "efi-surface-mount", "argv": ["mount", p1, EFI_MOUNT]},
        {"effect": "recovery-surface-mount", "argv": ["mount", p2, RECOVERY_MOUNT]},
        {"effect": "btrfs-stage-mount", "argv": ["mount", mapper, BTRFS_STAGE_ROOT]},
    ]
    for name in subvolumes:
        commands.append(
            {
                "effect": "btrfs-subvolume-create",
                "argv": ["btrfs", "subvolume", "create", f"{BTRFS_STAGE_ROOT}/{name}"],
                "subvolume": name,
            }
        )
    commands.append(
        {"effect": "btrfs-stage-unmount", "argv": ["umount", BTRFS_STAGE_ROOT]}
    )
    logical_mounts = {
        item["name"]: item["mountpoint"]
        for item in contract["topology"]["btrfs"]["subvolumes"]
    }
    for name in subvolumes:
        commands.append(
            {
                "effect": "btrfs-subvolume-mount",
                "argv": [
                    "mount",
                    "-o",
                    f"subvol={name}",
                    mapper,
                    SANDBOX_MOUNT_BY_SUBVOLUME[name],
                ],
                "subvolume": name,
                "logical_mountpoint": logical_mounts[name],
            }
        )

    material = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_storage_effect_plan",
        "contract_sha256": CONTRACT_SHA256,
        "target_preflight": preflight,
        "sandbox_authority_receipt_sha256": authority["receipt_sha256"],
        "runtime_executor_task": EXECUTOR_TASK,
        "exclusive_resource": SANDBOX_RESOURCE,
        "commands": commands,
        "expected_readback": {
            "partition_table": "gpt",
            "partitions": _copy_json(contract["topology"]["partitions"]),
            "luks": _copy_json(contract["topology"]["luks"]),
            "btrfs": {
                **_copy_json(contract["topology"]["btrfs"]),
                "sandbox_mounts": dict(SANDBOX_MOUNT_BY_SUBVOLUME),
            },
            "efi": {
                "device": p1,
                "filesystem": "vfat",
                "sandbox_mountpoint": EFI_MOUNT,
            },
            "recovery": {
                "device": p2,
                "filesystem": "ext4",
                "sandbox_mountpoint": RECOVERY_MOUNT,
            },
        },
        "execution_authorized": False,
        "production_effects_authorized": False,
        "requires_runtime_executor_reauthentication": True,
    }
    return {**material, "plan_sha256": sha256_json(material)}


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
            {"number", "role", "label", "type_guid", "device"},
            f"topology readback.gpt.partitions[{index}]",
        )
        normalized_partitions.append(
            {
                "number": _positive_int(partition["number"], f"partition[{index}].number"),
                "role": _nonempty_text(partition["role"], f"partition[{index}].role"),
                "label": _nonempty_text(partition["label"], f"partition[{index}].label"),
                "type_guid": _nonempty_text(partition["type_guid"], f"partition[{index}].type_guid", 64).upper(),
                "device": _canonical_device(partition["device"], f"partition[{index}].device"),
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
    if normalized_partitions != expected_summary:
        raise RehearsalError("partition topology readback differs from contract")

    luks = _exact_keys(readback["luks"], {"version", "container_device", "mapper_name", "unlocked"}, "topology readback.luks")
    if luks["version"] != 2 or luks["mapper_name"] != "nixos-rehearsal-crypt" or luks["unlocked"] is not True:
        raise RehearsalError("LUKS2 readback is not unlocked as expected")
    if _canonical_device(luks["container_device"], "luks.container_device") != expected_summary[2]["device"]:
        raise RehearsalError("LUKS container device mismatch")

    btrfs = _exact_keys(
        readback["btrfs"],
        {"label", "device", "subvolumes", "mounts", "sandbox_mounts"},
        "topology readback.btrfs",
    )
    if btrfs["label"] != "NIXOS_SYSTEM" or _canonical_device(btrfs["device"], "btrfs.device") != MAPPER_PATH:
        raise RehearsalError("Btrfs readback identity mismatch")
    expected_subvolumes = [item["name"] for item in contract["topology"]["btrfs"]["subvolumes"]]
    if _string_list(btrfs["subvolumes"], "btrfs.subvolumes") != sorted(expected_subvolumes):
        raise RehearsalError("Btrfs subvolume readback mismatch")
    if not isinstance(btrfs["mounts"], dict):
        raise RehearsalError("Btrfs mounts must be an object")
    expected_mounts = {item["mountpoint"]: item["name"] for item in contract["topology"]["btrfs"]["subvolumes"]}
    if btrfs["mounts"] != expected_mounts:
        raise RehearsalError("Btrfs mount readback mismatch")
    if btrfs["sandbox_mounts"] != SANDBOX_MOUNT_BY_SUBVOLUME:
        raise RehearsalError("Btrfs sandbox mount readback mismatch")

    efi = _exact_keys(
        readback["efi"],
        {"device", "filesystem", "sandbox_mountpoint"},
        "topology readback.efi",
    )
    if _canonical_device(efi["device"], "efi.device") != expected_summary[0]["device"]:
        raise RehearsalError("EFI partition device mismatch")
    if efi["filesystem"] != "vfat" or efi["sandbox_mountpoint"] != EFI_MOUNT:
        raise RehearsalError("EFI surface readback mismatch")

    recovery = _exact_keys(
        readback["recovery"],
        {"device", "filesystem", "surface_present", "sandbox_mountpoint"},
        "topology readback.recovery",
    )
    if _canonical_device(recovery["device"], "recovery.device") != expected_summary[1]["device"]:
        raise RehearsalError("recovery partition device mismatch")
    if (
        recovery["filesystem"] != "ext4"
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
    if (current - observed).total_seconds() < -FUTURE_SKEW_SECONDS:
        raise RehearsalError("recovery evidence is from the future")
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
        _parse_utc(item["observed_at"], f"recovery domain {name}.observed_at")
        domain_sha = _sha256(item["evidence_sha256"], f"recovery domain {name}.evidence_sha256")
        independence = _exact_keys(
            item["independence"],
            {"network_required", "production_system_ssd_required", "grabowski_required", "bureau_required"},
            f"recovery domain {name}.independence",
        )
        if any(independence.values()):
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
