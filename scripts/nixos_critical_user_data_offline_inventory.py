#!/usr/bin/env python3
"""Offline authoritative Critical-User-Data inventory for the Heim-PC recovery live image.

The tool is fail-closed. Without --apply it only observes the evidence/source
identities and prints a plan. With --apply it requires a removable ext4 evidence
volume, validates the revision-bound private storage identity, makes the protected
Pop!_OS fallback NVMe kernel-read-only, mounts its root read-only in the service's
private mount namespace, executes the contract-pinned inventory payload, and writes
a create-only result back to the evidence volume.

It never makes the source disk writable again and never authorizes production
storage or cutover effects.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any

EXPECTED_CRITICAL_SCOPE_SHA256 = "d979b42a8a030ca37b5a3c57ac192c81324d72bf3ac292adbda427eeec2c8097"
EXPECTED_HOME_CONTRACT_SHA256 = "385cf944e6a28c94a4593eeb1e6e5c87141cb26a4dc8a6cc96b783e21a623347"
EXPECTED_ROOT_SCANNER_SHA256 = "5f3b9aa1e2ad49da932ac699023f7f020e562d1d6ec0584a8c9dafb6ffaef572"
EXPECTED_AGGREGATE_SCANNER_SHA256 = "f71996ac1b3722a0785465e9504c2cfd23878d1b85597ddaff7a5bebf0a49d84"
SOURCE_STABILITY_MODE = "kernel-local-pci-nvme-readonly-mountinfo-v3"
EVIDENCE_LABEL = "HEIMPC_EVIDENCE"
EVIDENCE_AUTHORITY = Path("/dev/disk/by-label") / EVIDENCE_LABEL
IDENTITY_FILENAME = "private-storage-identity.json"
AUTHORITY_FILENAME = "authority.json"
AUTHORITY_KIND = "heim_pc.offline_critical_user_data_inventory_authority.v1"
FAILURE_FILENAME = "failure.json"
RESULT_DIRNAME = "critical-user-data-inventory"
SOURCE_MOUNT_NAME = "source"
RESULT_FILENAME = "source-inventory.json"
RESULT_SHA_FILENAME = "source-inventory.sha256"
RECEIPT_FILENAME = "source-inventory-receipt.json"
SOURCE_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class OfflineInventoryError(RuntimeError):
    pass


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def _canonical_line(value: Any) -> bytes:
    return _canonical_json(value) + b"\n"


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _run(argv: list[str], *, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OfflineInventoryError(f"command failed to execute: {argv[0]}") from exc
    if completed.returncode != 0:
        raise OfflineInventoryError(
            f"command failed: {argv[0]} rc={completed.returncode}"
        )
    return completed


def _read_regular(path: Path, label: str, *, max_bytes: int = 512 * 1024) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise OfflineInventoryError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise OfflineInventoryError(f"{label} must be a single-link regular file")
    if before.st_size <= 0 or before.st_size > max_bytes:
        raise OfflineInventoryError(f"{label} size is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise OfflineInventoryError(f"{label} cannot be opened safely") from exc
    try:
        opened = os.fstat(fd)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_nlink,
            item.st_uid,
            item.st_gid,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if identity(opened) != identity(before):
            raise OfflineInventoryError(f"{label} changed while opening")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            total += len(block)
            if total > max_bytes:
                raise OfflineInventoryError(f"{label} grew beyond its size bound")
            chunks.append(block)
        after = os.fstat(fd)
        if identity(after) != identity(opened):
            raise OfflineInventoryError(f"{label} changed while reading")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _read_json_regular(path: Path, label: str) -> dict[str, Any]:
    payload = _read_regular(path, label)
    try:
        value = json.loads(payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OfflineInventoryError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise OfflineInventoryError(f"{label} must be a JSON object")
    return value


def _validate_authority(value: dict[str, Any], expected_revision: str) -> dict[str, Any]:
    expected_keys = {
        "schema_version",
        "kind",
        "operation",
        "live_source_revision",
        "critical_user_data_contract_sha256",
        "allow_source_read_only_transition",
        "allow_inventory_result_write",
        "production_cutover_authorized",
    }
    if (
        set(value) != expected_keys
        or value.get("schema_version") != 1
        or value.get("kind") != AUTHORITY_KIND
        or value.get("operation") != "source-inventory"
        or value.get("live_source_revision") != expected_revision
        or value.get("critical_user_data_contract_sha256") != EXPECTED_CRITICAL_SCOPE_SHA256
        or value.get("allow_source_read_only_transition") is not True
        or value.get("allow_inventory_result_write") is not True
        or value.get("production_cutover_authorized") is not False
    ):
        raise OfflineInventoryError("offline inventory authority is invalid")
    return dict(value)


def _load_identity_module(path: Path):
    spec = importlib.util.spec_from_file_location("heim_pc_nixos_production_identity", path)
    if spec is None or spec.loader is None:
        raise OfflineInventoryError("storage identity helper cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_bound_contract(
    payload_root: Path, identity_path: Path, expected_revision: str
) -> dict[str, Any]:
    if SOURCE_REVISION_RE.fullmatch(expected_revision) is None:
        raise OfflineInventoryError("expected source revision must be exact 40-hex")
    public_path = payload_root / "nixos/production/contract-v1.json"
    helper_path = payload_root / "scripts/nixos_production_identity.py"
    module = _load_identity_module(helper_path)
    try:
        contract = module.load_contract(
            public_path, identity_path, expected_revision=expected_revision
        )
    except Exception as exc:
        raise OfflineInventoryError("private storage identity contract rejected") from exc

    protected = contract.get("protected_disks")
    target = contract.get("target_identity")
    if (
        not isinstance(protected, list)
        or len(protected) != 1
        or not isinstance(protected[0], dict)
        or protected[0].get("role") != "popos-fallback"
        or not isinstance(target, dict)
    ):
        raise OfflineInventoryError("bound production storage identity is incomplete")
    source_by_id = protected[0].get("by_id")
    target_by_id = target.get("exact_by_id")
    if (
        not isinstance(source_by_id, str)
        or not source_by_id.startswith("/dev/disk/by-id/")
        or not isinstance(target_by_id, str)
        or not target_by_id.startswith("/dev/disk/by-id/")
        or source_by_id == target_by_id
    ):
        raise OfflineInventoryError("source/target stable storage authorities are invalid")
    return contract


def _mountpoints(item: dict[str, Any]) -> list[str]:
    values = item.get("mountpoints")
    if values is None:
        one = item.get("mountpoint")
        return [] if not one else [str(one)]
    if not isinstance(values, list):
        raise OfflineInventoryError("lsblk mountpoints shape is invalid")
    return [str(value) for value in values if value]


def _resolve_block_authority(path: Path, label: str) -> Path:
    if not path.is_absolute() or not path.is_symlink():
        raise OfflineInventoryError(f"{label} stable authority is unavailable")
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError as exc:
        raise OfflineInventoryError(f"{label} stable authority cannot be resolved") from exc
    if not stat.S_ISBLK(info.st_mode):
        raise OfflineInventoryError(f"{label} authority does not resolve to a block device")
    return resolved


def _require_local_pci_nvme(path: Path, label: str) -> None:
    info = path.stat()
    dev = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
    try:
        sysfs = (Path("/sys/dev/block") / dev).resolve(strict=True)
    except OSError as exc:
        raise OfflineInventoryError(f"{label} sysfs identity is unavailable") from exc
    parts = sysfs.parts
    if (
        "virtual" in parts
        or not any(part.startswith("pci") for part in parts)
        or not any(part == "nvme" or part.startswith("nvme") for part in parts)
    ):
        raise OfflineInventoryError(f"{label} is not a local PCI NVMe device")


def _lsblk_tree(path: Path) -> dict[str, Any]:
    fields = (
        "PATH,TYPE,SIZE,MODEL,SERIAL,WWN,TRAN,FSTYPE,PARTN,PARTUUID,UUID,"
        "LABEL,RO,RM,MOUNTPOINTS"
    )
    completed = _run(
        ["lsblk", "--json", "--bytes", "--paths", "-o", fields, str(path)]
    )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise OfflineInventoryError("lsblk returned invalid JSON") from exc
    devices = value.get("blockdevices")
    if not isinstance(devices, list) or len(devices) != 1 or not isinstance(devices[0], dict):
        raise OfflineInventoryError("lsblk returned an ambiguous block-device tree")
    return devices[0]


def _protected_root_partition(contract: dict[str, Any]) -> dict[str, Any]:
    protected = contract["protected_disks"][0]
    parts = protected.get("partition_table_fingerprint")
    if not isinstance(parts, list) or len(parts) != 4:
        raise OfflineInventoryError("protected fallback partition fingerprint is invalid")
    roots = [
        item
        for item in parts
        if isinstance(item, dict) and item.get("role") == "popos-root"
    ]
    if len(roots) != 1:
        raise OfflineInventoryError("protected fallback root partition is ambiguous")
    root = roots[0]
    if (
        root.get("fstype") != "ext4"
        or not isinstance(root.get("partuuid"), str)
        or not isinstance(root.get("uuid"), str)
    ):
        raise OfflineInventoryError("protected fallback root identity is incomplete")
    return root


def _validate_source_tree(
    contract: dict[str, Any], resolved_disk: Path, tree: dict[str, Any]
) -> dict[str, Any]:
    protected = contract["protected_disks"][0]
    if (
        tree.get("type") != "disk"
        or Path(str(tree.get("path"))) != resolved_disk
        or (tree.get("model") or "").strip() != protected.get("model")
        or str(tree.get("serial") or "") != str(protected.get("serial") or "")
        or str(tree.get("wwn") or "") != str(protected.get("wwn") or "")
        or int(tree.get("size") or -1) != int(protected.get("size_bytes") or -2)
        or tree.get("tran") != "nvme"
        or _mountpoints(tree)
    ):
        raise OfflineInventoryError("protected fallback live disk identity mismatch")

    expected_parts = protected.get("partition_table_fingerprint")
    expected = {
        int(item["number"]): item
        for item in expected_parts
        if isinstance(item, dict) and isinstance(item.get("number"), int)
    }
    children = tree.get("children")
    if not isinstance(children, list) or len(children) != 4 or set(expected) != {1, 2, 3, 4}:
        raise OfflineInventoryError("protected fallback live partition set is invalid")

    observed: dict[int, dict[str, Any]] = {}
    for item in children:
        if not isinstance(item, dict) or item.get("type") != "part":
            raise OfflineInventoryError("protected fallback contains a non-partition child")
        try:
            number = int(item.get("partn"))
        except (TypeError, ValueError) as exc:
            raise OfflineInventoryError("protected fallback partition number is invalid") from exc
        if number in observed or _mountpoints(item):
            raise OfflineInventoryError("protected fallback partition is mounted or duplicated")
        observed[number] = item
    if set(observed) != set(expected):
        raise OfflineInventoryError("protected fallback partition numbers do not match contract")

    for number, expected_item in expected.items():
        item = observed[number]
        if (
            int(item.get("size") or -1) != int(expected_item.get("size_bytes") or -2)
            or (item.get("fstype") or "") != expected_item.get("fstype")
            or str(item.get("partuuid") or "").lower()
            != str(expected_item.get("partuuid") or "").lower()
            or str(item.get("uuid") or "") != str(expected_item.get("uuid") or "")
        ):
            raise OfflineInventoryError(
                f"protected fallback partition {number} identity mismatch"
            )

    root_contract = _protected_root_partition(contract)
    root_number = int(root_contract["number"])
    root = observed[root_number]
    root_path = Path(str(root.get("path") or ""))
    if not root_path.is_absolute():
        raise OfflineInventoryError("protected fallback root path is invalid")
    return {
        "disk": str(resolved_disk),
        "root_partition": str(root_path),
        "devices": [str(observed[n]["path"]) for n in sorted(observed)] + [str(resolved_disk)],
        "source_by_id": protected["by_id"],
        "root_partuuid": root_contract["partuuid"],
    }


def observe_source(contract: dict[str, Any]) -> dict[str, Any]:
    protected = contract["protected_disks"][0]
    source_by_id = Path(protected["by_id"])
    resolved_disk = _resolve_block_authority(source_by_id, "protected fallback")
    _require_local_pci_nvme(resolved_disk, "protected fallback")
    result = _validate_source_tree(contract, resolved_disk, _lsblk_tree(resolved_disk))

    root_by_partuuid = Path("/dev/disk/by-partuuid") / result["root_partuuid"]
    root_authority = _resolve_block_authority(root_by_partuuid, "protected fallback root")
    if root_authority != Path(result["root_partition"]):
        raise OfflineInventoryError("protected fallback root PARTUUID resolution mismatch")
    _require_local_pci_nvme(root_authority, "protected fallback root")
    return result


def _validate_target_tree(
    contract: dict[str, Any], resolved_disk: Path, tree: dict[str, Any]
) -> dict[str, Any]:
    target = contract.get("target_identity")
    if not isinstance(target, dict):
        raise OfflineInventoryError("NixOS target identity is incomplete")
    if (
        tree.get("type") != "disk"
        or Path(str(tree.get("path"))) != resolved_disk
        or (tree.get("model") or "").strip() != target.get("exact_model")
        or str(tree.get("serial") or "") != str(target.get("exact_serial") or "")
        or str(tree.get("wwn") or "") != str(target.get("exact_wwn") or "")
        or int(tree.get("size") or -1) != int(target.get("exact_size_bytes") or -2)
        or tree.get("tran") != "nvme"
        or _mountpoints(tree)
    ):
        raise OfflineInventoryError("NixOS target live disk identity mismatch")
    children = tree.get("children", [])
    if not isinstance(children, list):
        raise OfflineInventoryError("NixOS target partition inventory is invalid")
    for child in children:
        if not isinstance(child, dict) or _mountpoints(child):
            raise OfflineInventoryError("NixOS target has an unsafe mounted child")
    return {"disk": str(resolved_disk), "target_by_id": target["exact_by_id"]}


def observe_target(contract: dict[str, Any]) -> dict[str, Any]:
    target = contract.get("target_identity")
    if not isinstance(target, dict):
        raise OfflineInventoryError("NixOS target identity is missing")
    target_by_id = target.get("exact_by_id")
    if not isinstance(target_by_id, str) or not target_by_id.startswith("/dev/disk/by-id/"):
        raise OfflineInventoryError("NixOS target by-id authority is invalid")
    resolved_disk = _resolve_block_authority(Path(target_by_id), "NixOS target")
    _require_local_pci_nvme(resolved_disk, "NixOS target")
    return _validate_target_tree(contract, resolved_disk, _lsblk_tree(resolved_disk))


def _validate_evidence_independence(
    evidence: dict[str, Any], source: dict[str, Any], target: dict[str, Any]
) -> None:
    evidence_parent = Path(evidence["parent_disk"]).resolve()
    source_disk = Path(source["disk"]).resolve()
    target_disk = Path(target["disk"]).resolve()
    if source_disk == target_disk:
        raise OfflineInventoryError("protected fallback resolves to the NixOS target")
    if evidence_parent == source_disk:
        raise OfflineInventoryError("evidence medium aliases the protected source disk")
    if evidence_parent == target_disk:
        raise OfflineInventoryError("evidence medium aliases the NixOS target disk")


def _parent_device(path: Path) -> Path:
    completed = _run(
        ["lsblk", "--noheadings", "--paths", "--output", "PKNAME", str(path)]
    )
    values = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    if len(values) != 1:
        raise OfflineInventoryError("evidence parent disk is ambiguous")
    parent = Path(values[0])
    if not parent.is_absolute():
        raise OfflineInventoryError("evidence parent disk path is invalid")
    return parent


def _validate_evidence_trees(
    partition: Path,
    partition_tree: dict[str, Any],
    parent: Path,
    parent_tree: dict[str, Any],
) -> dict[str, Any]:
    if (
        partition_tree.get("type") != "part"
        or Path(str(partition_tree.get("path"))) != partition
        or partition_tree.get("fstype") != "ext4"
        or partition_tree.get("label") != EVIDENCE_LABEL
        or _mountpoints(partition_tree)
    ):
        raise OfflineInventoryError("recovery evidence partition identity is invalid")
    if (
        parent_tree.get("type") != "disk"
        or Path(str(parent_tree.get("path"))) != parent
        or parent_tree.get("tran") != "usb"
        or int(parent_tree.get("rm") or 0) != 1
        or _mountpoints(parent_tree)
    ):
        raise OfflineInventoryError(
            "recovery evidence must be an unmounted removable USB disk"
        )
    return {"partition": str(partition), "parent_disk": str(parent)}


def observe_evidence() -> dict[str, Any]:
    partition = _resolve_block_authority(EVIDENCE_AUTHORITY, "recovery evidence")
    parent = _parent_device(partition)
    return _validate_evidence_trees(
        partition, _lsblk_tree(partition), parent, _lsblk_tree(parent)
    )


def _mount_ro(device: Path, mountpoint: Path, *, fstype: str, options: str) -> None:
    mountpoint.mkdir(parents=True, exist_ok=True)
    _run(["mount", "-t", fstype, "-o", options, str(device), str(mountpoint)])


def _umount(mountpoint: Path) -> None:
    _run(["umount", str(mountpoint)])


def _create_start_fence(state_dir: Path, expected_revision: str) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    path = state_dir / "start-attempt.json"
    payload = _canonical_line(
        {
            "schema_version": 1,
            "kind": "heim_pc.offline_critical_user_data_inventory_start_attempt.v1",
            "source_revision": expected_revision,
            "critical_user_data_contract_sha256": EXPECTED_CRITICAL_SCOPE_SHA256,
        }
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise OfflineInventoryError(
            "offline inventory was already attempted during this boot"
        ) from exc
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)


def _set_source_readonly(source: dict[str, Any]) -> None:
    devices = [Path(item) for item in source["devices"]]
    disk = Path(source["disk"])
    ordered = [disk] + [item for item in devices if item != disk]
    for device in ordered:
        _run(["blockdev", "--setro", str(device)])
    for device in ordered:
        value = _run(["blockdev", "--getro", str(device)]).stdout.strip()
        if value != "1":
            raise OfflineInventoryError("kernel read-only source state was not established")


def _verified_inventory(payload_root: Path) -> dict[str, Any]:
    contract_path = payload_root / "nixos/production/critical-user-data-contract-v1.json"
    home_path = payload_root / "nixos/production/critical-user-home-data-contract-v1.json"
    aggregate_path = payload_root / "scripts/nixos_critical_data_inventory.py"
    root_path = payload_root / "scripts/nixos_critical_user_data_inventory.py"

    contract_payload = _read_regular(contract_path, "critical-user-data contract")
    if _sha256(contract_payload) != EXPECTED_CRITICAL_SCOPE_SHA256:
        raise OfflineInventoryError("critical-user-data contract digest mismatch")
    try:
        contract = json.loads(contract_payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OfflineInventoryError("critical-user-data contract JSON is invalid") from exc

    implementation = contract.get("inventory_implementation")
    members = contract.get("members")
    if not isinstance(implementation, dict) or not isinstance(members, list) or len(members) != 1:
        raise OfflineInventoryError("critical-user-data inventory binding is invalid")
    aggregate_payload = _read_regular(aggregate_path, "aggregate inventory implementation")
    root_payload = _read_regular(root_path, "root inventory implementation")
    home_payload = _read_regular(home_path, "home inventory contract")
    if implementation.get("aggregate_inventory_script_sha256") != EXPECTED_AGGREGATE_SCANNER_SHA256:
        raise OfflineInventoryError("aggregate inventory contract pin mismatch")
    if implementation.get("root_inventory_script_sha256") != EXPECTED_ROOT_SCANNER_SHA256:
        raise OfflineInventoryError("root inventory contract pin mismatch")
    if members[0].get("contract_sha256") != EXPECTED_HOME_CONTRACT_SHA256:
        raise OfflineInventoryError("home inventory contract pin mismatch")
    if _sha256(aggregate_payload) != EXPECTED_AGGREGATE_SCANNER_SHA256:
        raise OfflineInventoryError("aggregate inventory implementation digest mismatch")
    if _sha256(root_payload) != EXPECTED_ROOT_SCANNER_SHA256:
        raise OfflineInventoryError("root inventory implementation digest mismatch")
    if _sha256(home_payload) != EXPECTED_HOME_CONTRACT_SHA256:
        raise OfflineInventoryError("home inventory contract digest mismatch")

    spec = importlib.util.spec_from_file_location(
        "heim_pc_verified_offline_aggregate_inventory", aggregate_path
    )
    if spec is None or spec.loader is None:
        raise OfflineInventoryError("aggregate inventory implementation cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module._VERIFIED_EXECUTION = True
    try:
        result = module.collect_inventory(
            contract_path,
            classification_only=False,
            max_exclusion_samples=0,
            _contract_snapshot=(contract, contract_payload),
            _aggregate_script_bytes=aggregate_payload,
        )
    except Exception as exc:
        raise OfflineInventoryError("authoritative aggregate inventory failed closed") from exc

    if (
        result.get("kind") != "heim_pc.critical_user_data_aggregate_inventory.v1"
        or result.get("scope") != "critical-user-data"
        or result.get("authoritative_inventory") is not True
        or result.get("production_effects_authorized") is not False
        or result.get("member_count") != 1
        or not isinstance(result.get("inventory_sha256"), str)
        or SHA256_RE.fullmatch(result["inventory_sha256"]) is None
    ):
        raise OfflineInventoryError("authoritative aggregate inventory result identity is invalid")
    return result


def _create_file(path: Path, payload: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                raise OfflineInventoryError("result write was incomplete")
            offset += written
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_success(
    evidence_mount: Path,
    result: dict[str, Any],
    *,
    source_revision: str,
    source: dict[str, Any],
) -> dict[str, Any]:
    output = evidence_mount / RESULT_DIRNAME
    if output.exists() or output.is_symlink():
        raise OfflineInventoryError("evidence output directory already exists")
    _run(["mount", "-o", "remount,rw,nodev,nosuid,noexec", str(evidence_mount)])
    try:
        output.mkdir(mode=0o700)
        result_payload = _canonical_line(result)
        result_sha = _sha256(result_payload)
        receipt = {
            "schema_version": 1,
            "kind": "heim_pc.offline_critical_user_data_inventory_receipt.v1",
            "status": "passed",
            "source_revision": source_revision,
            "critical_user_data_contract_sha256": EXPECTED_CRITICAL_SCOPE_SHA256,
            "source_stability_proof": SOURCE_STABILITY_MODE,
            "source_authority": source["source_by_id"],
            "source_root_partuuid": source["root_partuuid"],
            "aggregate_inventory_sha256": result["inventory_sha256"],
            "result_file_sha256": result_sha,
            "evidence_write_mode": "create-only-fsync",
            "authoritative_inventory": True,
            "production_effects_authorized": False,
        }
        _create_file(output / RESULT_FILENAME, result_payload, 0o600)
        _create_file(output / RESULT_SHA_FILENAME, (result_sha + "\n").encode("ascii"), 0o600)
        _create_file(output / RECEIPT_FILENAME, _canonical_line(receipt), 0o600)
        directory_fd = os.open(output, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        mount_fd = os.open(evidence_mount, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(mount_fd)
        finally:
            os.close(mount_fd)
    finally:
        _run(["mount", "-o", "remount,ro,nodev,nosuid,noexec", str(evidence_mount)])
    return receipt


def _plan(
    *,
    expected_revision: str,
    evidence: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "heim_pc.offline_critical_user_data_inventory_plan.v1",
        "source_revision": expected_revision,
        "critical_user_data_contract_sha256": EXPECTED_CRITICAL_SCOPE_SHA256,
        "evidence_partition": evidence["partition"],
        "evidence_parent_disk": evidence["parent_disk"],
        "source_authority": source["source_by_id"],
        "source_disk": source["disk"],
        "source_root_partition": source["root_partition"],
        "source_root_partuuid": source["root_partuuid"],
        "effects": [
            "source-block-devices-set-read-only",
            "source-root-mounted-ro-noload-in-private-namespace",
            "authoritative-critical-user-data-inventory",
            "create-only-result-on-removable-evidence-volume",
        ],
        "production_effects_authorized": False,
    }


def run(args: argparse.Namespace) -> int:
    payload_root = args.payload_root.resolve()
    state_dir = args.state_dir.resolve()
    evidence_mount = args.evidence_mount.resolve()
    if SOURCE_REVISION_RE.fullmatch(args.expected_source_revision) is None:
        raise OfflineInventoryError("runtime source revision is not clean 40-hex")
    if os.geteuid() != 0 and args.apply:
        raise OfflineInventoryError("--apply requires the dedicated root service")

    if args.apply:
        _create_start_fence(state_dir, args.expected_source_revision)

    evidence = observe_evidence()
    evidence_partition = Path(evidence["partition"])
    evidence_parent = Path(evidence["parent_disk"])
    evidence_mounted = False
    source_mount = state_dir / SOURCE_MOUNT_NAME
    home_bound = False
    source_mounted = False
    try:
        _mount_ro(
            evidence_partition,
            evidence_mount,
            fstype="ext4",
            options="ro,nodev,nosuid,noexec",
        )
        evidence_mounted = True
        _validate_authority(
            _read_json_regular(evidence_mount / AUTHORITY_FILENAME, "offline inventory authority"),
            args.expected_source_revision,
        )
        identity_path = evidence_mount / IDENTITY_FILENAME
        contract = load_bound_contract(
            payload_root, identity_path, args.expected_source_revision
        )
        source = observe_source(contract)
        target = observe_target(contract)
        _validate_evidence_independence(evidence, source, target)

        plan = _plan(
            expected_revision=args.expected_source_revision,
            evidence=evidence,
            source=source,
        )
        if not args.apply:
            sys.stdout.buffer.write(_canonical_line(plan))
            return 0

        if (evidence_mount / RESULT_DIRNAME).exists():
            raise OfflineInventoryError("evidence medium already contains an inventory result")

        _set_source_readonly(source)
        _mount_ro(
            Path(source["root_partition"]),
            source_mount,
            fstype="ext4",
            options="ro,noload,nodev,nosuid,noexec",
        )
        source_mounted = True
        source_home = source_mount / "home/alex"
        if not source_home.is_dir():
            raise OfflineInventoryError("protected fallback root does not contain /home/alex")
        _run(["mount", "--bind", str(source_home), "/home/alex"])
        home_bound = True
        _run(["mount", "-o", "remount,bind,ro,nodev,nosuid,noexec", "/home/alex"])

        result = _verified_inventory(payload_root)

        _umount(Path("/home/alex"))
        home_bound = False
        _umount(source_mount)
        source_mounted = False

        receipt = _write_success(
            evidence_mount,
            result,
            source_revision=args.expected_source_revision,
            source=source,
        )
        sys.stdout.buffer.write(_canonical_line(result))
        print(
            f"offline inventory passed inventory_sha256={receipt['aggregate_inventory_sha256']}",
            file=sys.stderr,
        )
        return 0
    finally:
        if home_bound:
            try:
                _umount(Path("/home/alex"))
            except Exception:
                pass
        if source_mounted:
            try:
                _umount(source_mount)
            except Exception:
                pass
        if evidence_mounted:
            try:
                _run(["mount", "-o", "remount,ro,nodev,nosuid,noexec", str(evidence_mount)])
            except Exception:
                pass
            try:
                _umount(evidence_mount)
            except Exception:
                pass


def _record_failure_fence(
    state_dir: Path, expected_revision: str, reason: str
) -> None:
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        _create_file(
            state_dir / FAILURE_FILENAME,
            _canonical_line(
                {
                    "schema_version": 1,
                    "kind": "heim_pc.offline_critical_user_data_inventory_failure.v1",
                    "source_revision": expected_revision,
                    "status": "failed",
                    "reason": reason,
                    "automatic_retry_authorized": False,
                    "production_effects_authorized": False,
                }
            ),
            0o600,
        )
        directory_fd = os.open(state_dir, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except (OSError, OfflineInventoryError, FileExistsError):
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload-root", type=Path, required=True)
    parser.add_argument("--expected-source-revision", required=True)
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path("/run/heim-pc-offline-inventory"),
    )
    parser.add_argument(
        "--evidence-mount",
        type=Path,
        default=Path("/run/heim-pc-recovery-evidence"),
    )
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        return run(args)
    except OfflineInventoryError as exc:
        _record_failure_fence(
            args.state_dir, args.expected_source_revision, str(exc)
        )
        print(f"offline critical-user-data inventory blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
