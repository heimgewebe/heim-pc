#!/usr/bin/env python3
"""Bind public NixOS storage shape to private, revision-bound host identity."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

PRIVATE_IDENTITY_KIND = "heim_pc.nixos_production_storage_identity"
SOURCE_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
PARTLABEL_RE = re.compile(r"^[A-Z0-9_]{1,36}$")
FAT_LABEL_RE = re.compile(r"^[A-Z0-9_]{1,11}$")
EXT4_LABEL_RE = re.compile(r"^[A-Z0-9_]{1,16}$")
GPT_GUID_RE = re.compile(r"^[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$")
FORBIDDEN_PUBLIC_IDENTITY_KEYS = frozenset({
    "exact_by_id", "exact_serial", "exact_wwn", "by_id", "serial", "wwn",
    "verified_by_id_aliases", "partuuid", "uuid",
})


class IdentityContractError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _read_json(path: Path, *, private: bool) -> dict[str, Any]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise IdentityContractError("storage identity input is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise IdentityContractError("storage identity input must be a single-link regular file")
    if info.st_size > 64 * 1024:
        raise IdentityContractError("storage identity input exceeds the bounded size")
    if private and stat.S_IMODE(info.st_mode) & 0o077:
        raise IdentityContractError("private storage identity contract must be mode 0600 or stricter")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise IdentityContractError("cannot open storage identity input safely") from exc
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink) != (
            info.st_dev, info.st_ino, info.st_mode, info.st_nlink
        ):
            raise IdentityContractError("storage identity input changed while opening")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(fd, 8192)
            if not block:
                break
            total += len(block)
            if total > 64 * 1024:
                raise IdentityContractError("storage identity input grew beyond the bounded size")
            chunks.append(block)
    finally:
        os.close(fd)
    try:
        value = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IdentityContractError("storage identity input is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise IdentityContractError("storage identity input must be a JSON object")
    return value


def _reject_public_unique_identifiers(value: Any, path: str = "contract") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_PUBLIC_IDENTITY_KEYS:
                raise IdentityContractError(
                    f"public production contract contains private identity key: {path}.{key}"
                )
            _reject_public_unique_identifiers(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_public_unique_identifiers(child, f"{path}[{index}]")


def validate_public_contract(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IdentityContractError("public production contract must be a JSON object")
    if value.get("schema_version") != 1 or value.get("kind") != "heim_pc.nixos_production_storage_contract":
        raise IdentityContractError("public production contract identity mismatch")
    _reject_public_unique_identifiers(value)
    policy = value.get("identity_policy")
    if (
        not isinstance(policy, dict)
        or policy.get("source") != "local-private-contract"
        or policy.get("schema_version") != 1
        or policy.get("source_revision_bound") is not True
        or policy.get("public_contract_sha256_bound") is not True
        or policy.get("unique_identifiers_forbidden_in_public_contract") is not True
    ):
        raise IdentityContractError("public production identity policy is incomplete")
    target = value.get("target_identity")
    protected = value.get("protected_disks")
    topology = value.get("topology")
    if (
        not isinstance(target, dict)
        or target.get("exact_model") in (None, "")
        or target.get("exact_size_bytes") in (None, "")
        or target.get("transport") != "nvme"
        or target.get("kernel_name_authoritative") is not False
        or target.get("requires_blank") is not True
        or target.get("requires_unmounted") is not True
    ):
        raise IdentityContractError("public target structure/policy is incomplete")
    if (
        not isinstance(protected, list)
        or len(protected) != 1
        or not isinstance(protected[0], dict)
        or not isinstance(protected[0].get("partition_table_fingerprint"), list)
        or len(protected[0]["partition_table_fingerprint"]) != 4
    ):
        raise IdentityContractError("public protected-disk structure is incomplete")
    if (
        not isinstance(topology, dict)
        or topology.get("partition_table") != "gpt"
        or topology.get("partition_identity_policy") != "private-identity-contract-assigned-partuuid"
        or not isinstance(topology.get("partitions"), list)
        or len(topology["partitions"]) != 3
    ):
        raise IdentityContractError("public production topology is incomplete")
    labels = [item.get("label") for item in topology["partitions"] if isinstance(item, dict)]
    if (
        len(labels) != 3
        or any(not isinstance(label, str) or PARTLABEL_RE.fullmatch(label) is None for label in labels)
        or len(set(labels)) != 3
    ):
        raise IdentityContractError("public production partition labels must be canonical, unique and complete")
    for partition in topology["partitions"]:
        filesystem = partition.get("filesystem")
        filesystem_label = partition.get("filesystem_label")
        if filesystem == "vfat" and (
            not isinstance(filesystem_label, str)
            or FAT_LABEL_RE.fullmatch(filesystem_label) is None
        ):
            raise IdentityContractError(
                "public vfat filesystem label must fit the FAT 11-character limit"
            )
        if filesystem == "ext4" and (
            not isinstance(filesystem_label, str)
            or EXT4_LABEL_RE.fullmatch(filesystem_label) is None
        ):
            raise IdentityContractError(
                "public ext4 filesystem label must fit the ext4 16-character limit"
            )
    return json.loads(json.dumps(value))


def _require_private_by_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("/dev/disk/by-id/") or os.path.normpath(value) != value:
        raise IdentityContractError(f"{label} must be a canonical /dev/disk/by-id path")
    return value


def _canonical_gpt_guid(value: Any, label: str) -> str:
    if not isinstance(value, str) or GPT_GUID_RE.fullmatch(value) is None:
        raise IdentityContractError(f"{label} must be a canonical GPT GUID")
    return value.lower()


def bind_contract(public: dict[str, Any], identity: dict[str, Any], *, expected_revision: str) -> dict[str, Any]:
    public = validate_public_contract(public)
    if SOURCE_REVISION_RE.fullmatch(expected_revision) is None:
        raise IdentityContractError("expected source revision must be exact 40-hex")
    if (
        identity.get("schema_version") != 1
        or identity.get("kind") != PRIVATE_IDENTITY_KIND
        or identity.get("source_revision") != expected_revision
    ):
        raise IdentityContractError("private storage identity source binding mismatch")
    public_sha256 = sha256_json(public)
    if identity.get("public_contract_sha256") != public_sha256:
        raise IdentityContractError("private storage identity public-contract digest mismatch")

    target_private = identity.get("target_identity")
    protected_private = identity.get("protected_disks")
    topology_private = identity.get("topology")
    if (
        not isinstance(target_private, dict)
        or not isinstance(protected_private, list)
        or len(protected_private) != 1
        or not isinstance(protected_private[0], dict)
        or not isinstance(topology_private, dict)
    ):
        raise IdentityContractError("private storage identity structure is incomplete")
    for key in ("exact_by_id", "exact_serial", "exact_wwn"):
        if target_private.get(key) in (None, ""):
            raise IdentityContractError(f"private target identity is incomplete: {key}")
    _require_private_by_id(target_private["exact_by_id"], "private target authority")

    protected_identity = protected_private[0]
    if protected_identity.get("role") != public["protected_disks"][0].get("role"):
        raise IdentityContractError("private protected-disk role mismatch")
    for key in ("by_id", "serial", "wwn"):
        if protected_identity.get(key) in (None, ""):
            raise IdentityContractError(f"private protected identity is incomplete: {key}")
    _require_private_by_id(protected_identity["by_id"], "private protected authority")
    aliases = protected_identity.get("verified_by_id_aliases", [])
    if not isinstance(aliases, list):
        raise IdentityContractError("private protected by-id aliases are invalid")
    for alias in aliases:
        _require_private_by_id(alias, "private protected by-id alias")

    protected_parts = protected_identity.get("partition_table_fingerprint")
    target_parts = topology_private.get("partitions")
    if not isinstance(protected_parts, list) or len(protected_parts) != 4:
        raise IdentityContractError("private protected partition identity structure is incomplete")
    if not isinstance(target_parts, list) or len(target_parts) != 3:
        raise IdentityContractError("private target partition identity structure is incomplete")
    protected_by_number = {item.get("number"): item for item in protected_parts if isinstance(item, dict)}
    target_by_number = {item.get("number"): item for item in target_parts if isinstance(item, dict)}
    if len(protected_by_number) != 4 or len(target_by_number) != 3:
        raise IdentityContractError("private partition numbers must be unique and complete")

    merged = json.loads(json.dumps(public))
    merged["target_identity"].update(
        {key: target_private[key] for key in ("exact_by_id", "exact_serial", "exact_wwn")}
    )
    merged_protected = merged["protected_disks"][0]
    merged_protected.update({key: protected_identity[key] for key in ("by_id", "serial", "wwn")})
    merged_protected["verified_by_id_aliases"] = list(aliases)
    for item in merged_protected["partition_table_fingerprint"]:
        private_item = protected_by_number.get(item.get("number"))
        if (
            not isinstance(private_item, dict)
            or private_item.get("partuuid") in (None, "")
            or private_item.get("uuid") in (None, "")
        ):
            raise IdentityContractError("private protected partition identity is incomplete")
        item["partuuid"] = _canonical_gpt_guid(
            private_item["partuuid"], "private protected PARTUUID"
        )
        item["uuid"] = str(private_item["uuid"])
    for item in merged["topology"]["partitions"]:
        private_item = target_by_number.get(item.get("number"))
        if not isinstance(private_item, dict) or private_item.get("partuuid") in (None, ""):
            raise IdentityContractError("private target PARTUUID identity is incomplete")
        item["partuuid"] = _canonical_gpt_guid(
            private_item["partuuid"], "private target PARTUUID"
        )
    partuuids = [item["partuuid"] for item in merged["topology"]["partitions"]]
    if len(set(partuuids)) != len(partuuids):
        raise IdentityContractError("private target PARTUUIDs must be unique")
    merged["identity_binding"] = {
        "schema_version": 1,
        "source_revision": expected_revision,
        "public_contract_sha256": public_sha256,
        "identity_contract_sha256": sha256_json(identity),
    }
    return merged


def load_contract(public_path: Path, identity_path: Path, *, expected_revision: str) -> dict[str, Any]:
    public = validate_public_contract(_read_json(public_path, private=False))
    identity = _read_json(identity_path, private=True)
    return bind_contract(public, identity, expected_revision=expected_revision)
