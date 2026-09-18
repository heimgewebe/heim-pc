#!/usr/bin/env python3
"""Fail-closed private pre-cutover readiness validation for the NixOS installer."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

READINESS_KIND = "heim_pc.nixos_pre_cutover_readiness"
VERIFICATION_KIND = "heim_pc.nixos_pre_cutover_readiness_verification"
RECOVERY_RECEIPT_KIND = "heim_pc.nixos_recovery_evidence_receipt"
RECOVERY_EVIDENCE_PROVENANCE_KIND = "heim_pc.nixos_recovery_evidence_provenance"
RECOVERY_RESTORE_TEST_PROVENANCE_KIND = "heim_pc.nixos_recovery_restore_test_provenance"
RECOVERY_CONTRACT_KIND = "heim_pc.nixos_recovery_readiness_contract"
LIFECYCLE_CONTRACT_KIND = "heim_pc.nixos_store_lifecycle_contract"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MAX_BUNDLE_BYTES = 256 * 1024
MAX_RECEIPT_BYTES = 256 * 1024
MAX_PROVENANCE_BYTES = 256 * 1024
MAX_CONTRACT_BYTES = 256 * 1024


class ReadinessError(ValueError):
    pass


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _copy_json(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _canonical_absolute(path: Path, label: str) -> Path:
    path = Path(path)
    text = str(path)
    if not path.is_absolute() or os.path.normpath(text) != text or not path.name:
        raise ReadinessError(f"{label} path must be canonical and absolute")
    return path


def _open_parent_without_symlinks(path: Path, label: str) -> tuple[int, str]:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ReadinessError(f"{label} cannot be opened safely on this platform")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    current_fd = -1
    try:
        current_fd = os.open("/", directory_flags)
        for component in path.parts[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            info = os.fstat(next_fd)
            if not stat.S_ISDIR(info.st_mode):
                os.close(next_fd)
                raise ReadinessError(f"{label} path component is not a directory")
            os.close(current_fd)
            current_fd = next_fd
        return current_fd, path.name
    except (OSError, ValueError) as exc:
        if current_fd >= 0:
            os.close(current_fd)
        if isinstance(exc, ReadinessError):
            raise
        raise ReadinessError(f"{label} path must not traverse symlinks") from exc


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_regular(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    private: bool,
    expected_owner_uid: int | None = None,
) -> tuple[bytes, dict[str, Any]]:
    path = _canonical_absolute(path, label)
    parent_fd, leaf = _open_parent_without_symlinks(path, label)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = -1
    try:
        try:
            linked_before = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(linked_before.st_mode):
                raise ReadinessError(f"{label} path must not traverse symlinks")
            fd = os.open(leaf, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise ReadinessError(f"{label} cannot be opened safely") from exc
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _identity(opened) != _identity(linked_before)
        ):
            raise ReadinessError(f"{label} must be a stable single-link regular file")
        mode = stat.S_IMODE(opened.st_mode)
        if private:
            if mode & ~0o600:
                raise ReadinessError(f"{label} mode must be 0600 or more restrictive")
            owner_uid = os.geteuid() if expected_owner_uid is None else expected_owner_uid
            if opened.st_uid != owner_uid:
                raise ReadinessError(f"{label} owner is not the reviewed private owner")
        elif mode & 0o022:
            raise ReadinessError(f"{label} must not be group/world writable")
        if opened.st_size <= 0 or opened.st_size > max_bytes:
            raise ReadinessError(f"{label} size is outside the bounded contract")
        remaining = opened.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                raise ReadinessError(f"{label} changed while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise ReadinessError(f"{label} grew while being read")
        opened_after = os.fstat(fd)
        try:
            linked_after = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise ReadinessError(f"{label} path disappeared during readback") from exc
        if (
            _identity(opened_after) != _identity(opened)
            or _identity(linked_after) != _identity(opened)
        ):
            raise ReadinessError(f"{label} identity changed during readback")
        payload = b"".join(chunks)
        return payload, {
            "path": str(path),
            "sha256": _sha256(payload),
            "device": opened.st_dev,
            "inode": opened.st_ino,
            "owner_uid": opened.st_uid,
            "group_gid": opened.st_gid,
            "mode": mode,
            "nlink": opened.st_nlink,
            "size": opened.st_size,
            "mtime_ns": opened.st_mtime_ns,
            "ctime_ns": opened.st_ctime_ns,
        }
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent_fd)


def _identity_binding(meta: dict[str, Any]) -> dict[str, Any]:
    return {
        key: meta[key]
        for key in (
            "device",
            "inode",
            "owner_uid",
            "group_gid",
            "mode",
            "nlink",
            "size",
            "mtime_ns",
            "ctime_ns",
        )
    }


def _json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReadinessError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ReadinessError(f"{label} must be a JSON object")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ReadinessError(f"{label} must be lowercase sha256")
    return value


def _revision(value: Any, label: str) -> str:
    if not isinstance(value, str) or REVISION_RE.fullmatch(value) is None:
        raise ReadinessError(f"{label} must be exact 40-hex")
    return value


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise ReadinessError(f"{label} must be canonical UTC seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ReadinessError(f"{label} is not a valid UTC timestamp") from exc


def _fresh(
    observed_at: Any,
    *,
    now: datetime,
    max_age_seconds: int,
    future_skew_seconds: int,
    label: str,
) -> datetime:
    observed = _utc(observed_at, label)
    age = (now - observed).total_seconds()
    if age < -future_skew_seconds:
        raise ReadinessError(f"{label} is from the future")
    if age > max_age_seconds:
        raise ReadinessError(f"{label} is stale")
    return observed


def _load_contract(path: Path, *, label: str) -> tuple[dict[str, Any], dict[str, Any]]:
    payload, meta = _read_regular(
        path,
        label=label,
        max_bytes=MAX_CONTRACT_BYTES,
        private=False,
    )
    return _json(payload, label), meta


def _recovery_policy(
    contract: dict[str, Any],
) -> tuple[list[dict[str, Any]], int, int]:
    if (
        contract.get("schema_version") != 1
        or contract.get("kind") != RECOVERY_CONTRACT_KIND
    ):
        raise ReadinessError("recovery contract identity mismatch")
    required = contract.get("required_evidence")
    if not isinstance(required, list) or not required:
        raise ReadinessError("recovery contract required_evidence is invalid")
    requirements: list[dict[str, Any]] = []
    ids: set[str] = set()
    for item in required:
        if not isinstance(item, dict) or set(item) != {
            "id",
            "scope",
            "requires_restore_test",
        }:
            raise ReadinessError("recovery contract evidence item is invalid")
        evidence_id = item.get("id")
        scope = item.get("scope")
        requires_restore_test = item.get("requires_restore_test")
        if (
            not isinstance(evidence_id, str)
            or not evidence_id
            or evidence_id in ids
            or not isinstance(scope, str)
            or not scope
            or type(requires_restore_test) is not bool
        ):
            raise ReadinessError("recovery contract evidence requirement is invalid")
        ids.add(evidence_id)
        requirements.append({
            "id": evidence_id,
            "scope": scope,
            "requires_restore_test": requires_restore_test,
        })

    receipt_contract = contract.get("evidence_receipt")
    if (
        not isinstance(receipt_contract, dict)
        or receipt_contract.get("schema_version") != 1
        or receipt_contract.get("kind") != RECOVERY_RECEIPT_KIND
        or receipt_contract.get("source_revision_bound") is not True
        or receipt_contract.get("recovery_contract_sha256_bound") is not True
        or receipt_contract.get("evidence_scope_bound") is not True
        or receipt_contract.get("evidence_provenance_path_bound") is not True
        or receipt_contract.get("evidence_provenance_sha256_bound") is not True
        or receipt_contract.get("evidence_provenance_object_bound") is not True
        or receipt_contract.get("evidence_provenance_contract_bound") is not True
        or receipt_contract.get("restore_test_requirement_bound") is not True
        or receipt_contract.get("required_restore_test_status") != "passed"
        or receipt_contract.get("required_restore_test_freshness_bound") is not True
        or receipt_contract.get("required_restore_test_provenance_path_bound") is not True
        or receipt_contract.get("required_restore_test_provenance_sha256_bound") is not True
        or receipt_contract.get("required_restore_test_provenance_object_bound") is not True
        or receipt_contract.get("required_restore_test_provenance_contract_bound") is not True
        or receipt_contract.get("status") != "passed"
        or receipt_contract.get("production_effects_authorized") is not False
    ):
        raise ReadinessError("recovery contract receipt policy is not fail-closed")

    freshness = contract.get("evidence_freshness")
    if not isinstance(freshness, dict):
        raise ReadinessError("recovery contract evidence freshness is missing")
    max_age = freshness.get("maximum_age_seconds")
    skew = freshness.get("future_skew_seconds")
    if (
        isinstance(max_age, bool)
        or not isinstance(max_age, int)
        or max_age <= 0
        or isinstance(skew, bool)
        or not isinstance(skew, int)
        or skew < 0
        or skew > 300
    ):
        raise ReadinessError("recovery contract evidence freshness is invalid")
    admission = contract.get("admission")
    if (
        not isinstance(admission, dict)
        or admission.get("all_required_evidence_must_be_fresh") is not True
        or admission.get("point_of_no_return_blocked_without_complete_evidence") is not True
        or admission.get("production_storage_mutation_blocked_without_complete_evidence") is not True
    ):
        raise ReadinessError("recovery contract admission is not fail-closed")
    return requirements, max_age, skew


def _validate_lifecycle_contract(contract: dict[str, Any]) -> None:
    if (
        contract.get("schema_version") != 1
        or contract.get("kind") != LIFECYCLE_CONTRACT_KIND
        or contract.get("automatic_gc") is not False
    ):
        raise ReadinessError("Nix lifecycle contract identity or GC policy mismatch")
    admission = contract.get("admission")
    if (
        not isinstance(admission, dict)
        or admission.get("initial_cutover_requires_contract") is not True
        or admission.get("initial_cutover_requires_live_audit") is not False
        or admission.get("automatic_gc_requires_fresh_audit") is not True
        or admission.get("automatic_gc_requires_separate_reviewed_enablement") is not True
    ):
        raise ReadinessError("Nix lifecycle initial-cutover/GC admission mismatch")


def _validate_provenance_object(
    *,
    path_value: Any,
    digest_value: Any,
    label: str,
    expected_kind: str,
    evidence_id: str,
    evidence_scope: str,
    source_revision: str,
    recovery_contract_sha256: str,
    observed_at: str,
    expected_owner_uid: int,
) -> dict[str, Any]:
    if not isinstance(path_value, str):
        raise ReadinessError(f"{label} path must be canonical and absolute")
    path = _canonical_absolute(Path(path_value), label)
    expected_digest = _sha(digest_value, f"{label} digest")
    payload, meta = _read_regular(
        path,
        label=label,
        max_bytes=MAX_PROVENANCE_BYTES,
        private=True,
        expected_owner_uid=expected_owner_uid,
    )
    if meta["sha256"] != expected_digest:
        raise ReadinessError(f"{label} digest mismatch")
    value = _json(payload, label)
    expected_keys = {
        "schema_version",
        "kind",
        "evidence_id",
        "evidence_scope",
        "source_revision",
        "recovery_contract_sha256",
        "status",
        "observed_at",
        "producer",
        "evidence",
        "production_effects_authorized",
    }
    actual_keys = set(value)
    missing_keys = expected_keys - actual_keys
    if "producer" in missing_keys:
        raise ReadinessError(f"{label} producer is missing")
    if "evidence" in missing_keys:
        raise ReadinessError(f"{label} evidence payload is missing")
    if actual_keys != expected_keys:
        raise ReadinessError(f"{label} object is malformed")
    if value.get("schema_version") != 1 or value.get("kind") != expected_kind:
        raise ReadinessError(f"{label} identity mismatch")
    if value.get("evidence_id") != evidence_id:
        raise ReadinessError(f"{label} evidence id mismatch")
    if value.get("evidence_scope") != evidence_scope:
        raise ReadinessError(f"{label} evidence scope mismatch")
    if value.get("source_revision") != source_revision:
        raise ReadinessError(f"{label} source revision mismatch")
    if value.get("recovery_contract_sha256") != recovery_contract_sha256:
        raise ReadinessError(f"{label} recovery contract digest mismatch")
    if value.get("status") != "passed":
        raise ReadinessError(f"{label} did not pass")
    producer = value.get("producer")
    if not isinstance(producer, str) or not producer.strip():
        raise ReadinessError(f"{label} producer is missing")
    evidence = value.get("evidence")
    if not isinstance(evidence, dict) or not evidence:
        raise ReadinessError(f"{label} evidence payload is missing")
    if value.get("observed_at") != observed_at:
        raise ReadinessError(f"{label} observation mismatch")
    _utc(value.get("observed_at"), f"{label}.observed_at")
    if value.get("production_effects_authorized") is not False:
        raise ReadinessError(f"{label} must not authorize production effects")
    return {
        "path": meta["path"],
        "sha256": meta["sha256"],
        "owner_uid": meta["owner_uid"],
        "file_identity": _identity_binding(meta),
    }

def _validate_receipt(
    value: dict[str, Any],
    *,
    requirement: dict[str, Any],
    source_revision: str,
    recovery_contract_sha256: str,
    observed_bundle: datetime,
    now: datetime,
    max_age_seconds: int,
    future_skew_seconds: int,
    expected_owner_uid: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    evidence_id = requirement["id"]
    if value.get("schema_version") != 1 or value.get("kind") != RECOVERY_RECEIPT_KIND:
        raise ReadinessError(f"recovery receipt {evidence_id} identity mismatch")
    if value.get("evidence_id") != evidence_id:
        raise ReadinessError(f"recovery receipt {evidence_id} evidence id mismatch")
    if value.get("evidence_scope") != requirement["scope"]:
        raise ReadinessError(f"recovery receipt {evidence_id} evidence scope mismatch")
    if value.get("requires_restore_test") is not requirement["requires_restore_test"]:
        raise ReadinessError(f"recovery receipt {evidence_id} restore-test requirement mismatch")
    if value.get("status") != "passed":
        raise ReadinessError(f"recovery receipt {evidence_id} did not pass")
    if value.get("source_revision") != source_revision:
        raise ReadinessError(f"recovery receipt {evidence_id} source revision mismatch")
    if value.get("recovery_contract_sha256") != recovery_contract_sha256:
        raise ReadinessError(f"recovery receipt {evidence_id} recovery contract digest mismatch")
    if value.get("production_effects_authorized") is not False:
        raise ReadinessError(f"recovery receipt {evidence_id} must not authorize production effects")
    observed = _fresh(
        value.get("observed_at"),
        now=now,
        max_age_seconds=max_age_seconds,
        future_skew_seconds=future_skew_seconds,
        label=f"recovery receipt {evidence_id}.observed_at",
    )
    if (observed - observed_bundle).total_seconds() > future_skew_seconds:
        raise ReadinessError(f"recovery receipt {evidence_id} is newer than its bundle observation")

    evidence_provenance = _validate_provenance_object(
        path_value=value.get("evidence_provenance_path"),
        digest_value=value.get("evidence_provenance_sha256"),
        label=f"recovery receipt {evidence_id} evidence provenance",
        expected_kind=RECOVERY_EVIDENCE_PROVENANCE_KIND,
        evidence_id=evidence_id,
        evidence_scope=requirement["scope"],
        source_revision=source_revision,
        recovery_contract_sha256=recovery_contract_sha256,
        observed_at=value["observed_at"],
        expected_owner_uid=expected_owner_uid,
    )

    restore_test = value.get("restore_test")
    restore_observed_at = None
    if requirement["requires_restore_test"]:
        if not isinstance(restore_test, dict) or set(restore_test) != {
            "status",
            "observed_at",
            "evidence_provenance_path",
            "evidence_provenance_sha256",
        }:
            raise ReadinessError(
                f"recovery receipt {evidence_id} required restore test is missing or malformed"
            )
        if restore_test.get("status") != "passed":
            raise ReadinessError(f"recovery receipt {evidence_id} restore test did not pass")
        restore_observed = _fresh(
            restore_test.get("observed_at"),
            now=now,
            max_age_seconds=max_age_seconds,
            future_skew_seconds=future_skew_seconds,
            label=f"recovery receipt {evidence_id}.restore_test.observed_at",
        )
        if (restore_observed - observed).total_seconds() > future_skew_seconds:
            raise ReadinessError(
                f"recovery receipt {evidence_id} restore test is newer than receipt observation"
            )
        restore_provenance = _validate_provenance_object(
            path_value=restore_test.get("evidence_provenance_path"),
            digest_value=restore_test.get("evidence_provenance_sha256"),
            label=f"recovery receipt {evidence_id} restore-test provenance",
            expected_kind=RECOVERY_RESTORE_TEST_PROVENANCE_KIND,
            evidence_id=evidence_id,
            evidence_scope=requirement["scope"],
            source_revision=source_revision,
            recovery_contract_sha256=recovery_contract_sha256,
            observed_at=restore_test["observed_at"],
            expected_owner_uid=expected_owner_uid,
        )
        restore_observed_at = restore_test["observed_at"]
        restore_status = "passed"
    else:
        if restore_test != {"status": "not-required"}:
            raise ReadinessError(
                f"recovery receipt {evidence_id} restore test must be exactly not-required"
            )
        restore_status = "not-required"
        restore_provenance = None

    return {
        "evidence_id": evidence_id,
        "evidence_scope": requirement["scope"],
        "status": "passed",
        "observed_at": value["observed_at"],
        "restore_test_required": requirement["requires_restore_test"],
        "restore_test_status": restore_status,
        "restore_test_observed_at": restore_observed_at,
    }, evidence_provenance, restore_provenance


def validate_readiness(
    readiness_path: Path,
    *,
    source_revision: str,
    recovery_contract_path: Path,
    lifecycle_contract_path: Path,
    now: datetime | None = None,
    expected_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    source_revision = _revision(source_revision, "source_revision")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    recovery_contract, recovery_meta = _load_contract(
        recovery_contract_path, label="recovery contract"
    )
    lifecycle_contract, lifecycle_meta = _load_contract(
        lifecycle_contract_path, label="Nix lifecycle contract"
    )
    requirements, max_age, skew = _recovery_policy(recovery_contract)
    required_ids = [item["id"] for item in requirements]
    _validate_lifecycle_contract(lifecycle_contract)

    expected_bundle_owner = None
    expected_receipt_owners: dict[str, int] = {}
    if expected_snapshot is not None:
        if not isinstance(expected_snapshot, dict):
            raise ReadinessError("reviewed readiness snapshot is invalid")
        expected_bundle_owner = expected_snapshot.get("bundle_owner_uid")
        if type(expected_bundle_owner) is not int:
            raise ReadinessError("reviewed readiness bundle owner is invalid")
        expected_receipts = expected_snapshot.get("receipts")
        if not isinstance(expected_receipts, list):
            raise ReadinessError("reviewed readiness receipt set is invalid")
        for item in expected_receipts:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("evidence_id"), str)
                or type(item.get("owner_uid")) is not int
            ):
                raise ReadinessError("reviewed readiness receipt owner binding is invalid")
            expected_receipt_owners[item["evidence_id"]] = item["owner_uid"]

    bundle_payload, bundle_meta = _read_regular(
        readiness_path,
        label="pre-cutover readiness bundle",
        max_bytes=MAX_BUNDLE_BYTES,
        private=True,
        expected_owner_uid=expected_bundle_owner,
    )
    bundle = _json(bundle_payload, "pre-cutover readiness bundle")
    if bundle.get("schema_version") != 1 or bundle.get("kind") != READINESS_KIND:
        raise ReadinessError("pre-cutover readiness bundle identity mismatch")
    if bundle.get("source_revision") != source_revision:
        raise ReadinessError("pre-cutover readiness source revision mismatch")
    if bundle.get("production_effects_authorized") is not False:
        raise ReadinessError("pre-cutover readiness bundle must not authorize production effects")
    if bundle.get("recovery_contract_sha256") != recovery_meta["sha256"]:
        raise ReadinessError("pre-cutover readiness recovery contract digest mismatch")
    if bundle.get("nix_lifecycle_contract_sha256") != lifecycle_meta["sha256"]:
        raise ReadinessError("pre-cutover readiness lifecycle contract digest mismatch")
    if bundle.get("freshness_seconds") != max_age:
        raise ReadinessError("pre-cutover readiness freshness policy mismatch")
    observed_bundle = _fresh(
        bundle.get("observed_at"),
        now=current,
        max_age_seconds=max_age,
        future_skew_seconds=skew,
        label="pre-cutover readiness observed_at",
    )

    entries = bundle.get("recovery_evidence_receipts")
    if not isinstance(entries, list):
        raise ReadinessError("pre-cutover readiness receipt set is invalid")
    by_id: dict[str, dict[str, Any]] = {}
    seen_paths: set[str] = {
        bundle_meta["path"],
        recovery_meta["path"],
        lifecycle_meta["path"],
    }
    for item in entries:
        if not isinstance(item, dict) or set(item) != {"evidence_id", "path", "sha256"}:
            raise ReadinessError("pre-cutover readiness receipt binding is invalid")
        evidence_id = item.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id:
            raise ReadinessError("pre-cutover readiness evidence id is invalid")
        if evidence_id in by_id:
            raise ReadinessError("pre-cutover readiness contains duplicate evidence id")
        _sha(item.get("sha256"), f"pre-cutover readiness {evidence_id} receipt digest")
        receipt_path = _canonical_absolute(Path(item.get("path", "")), f"recovery receipt {evidence_id}")
        if str(receipt_path) in seen_paths:
            raise ReadinessError("pre-cutover readiness reuses one receipt path")
        seen_paths.add(str(receipt_path))
        by_id[evidence_id] = {
            "evidence_id": evidence_id,
            "path": str(receipt_path),
            "sha256": item["sha256"],
        }
    if set(by_id) != set(required_ids):
        missing = sorted(set(required_ids) - set(by_id))
        foreign = sorted(set(by_id) - set(required_ids))
        detail = []
        if missing:
            detail.append("missing=" + ",".join(missing))
        if foreign:
            detail.append("foreign=" + ",".join(foreign))
        raise ReadinessError("pre-cutover readiness evidence set mismatch" + (": " + " ".join(detail) if detail else ""))

    normalized_receipts: list[dict[str, Any]] = []
    evidence_summary: list[dict[str, Any]] = []
    for requirement in requirements:
        evidence_id = requirement["id"]
        binding = by_id[evidence_id]
        payload, meta = _read_regular(
            Path(binding["path"]),
            label=f"recovery receipt {evidence_id}",
            max_bytes=MAX_RECEIPT_BYTES,
            private=True,
            expected_owner_uid=expected_receipt_owners.get(evidence_id, bundle_meta["owner_uid"]),
        )
        if meta["sha256"] != binding["sha256"]:
            raise ReadinessError(f"recovery receipt {evidence_id} digest mismatch")
        receipt = _json(payload, f"recovery receipt {evidence_id}")
        summary, evidence_provenance, restore_provenance = _validate_receipt(
            receipt,
            requirement=requirement,
            source_revision=source_revision,
            recovery_contract_sha256=recovery_meta["sha256"],
            observed_bundle=observed_bundle,
            now=current,
            max_age_seconds=max_age,
            future_skew_seconds=skew,
            expected_owner_uid=meta["owner_uid"],
        )
        for provenance in (evidence_provenance, restore_provenance):
            if provenance is None:
                continue
            provenance_path = provenance["path"]
            if provenance_path in seen_paths:
                raise ReadinessError(
                    f"recovery receipt {evidence_id} reuses a bound evidence path"
                )
            seen_paths.add(provenance_path)
        normalized_receipts.append({
            "evidence_id": evidence_id,
            "path": binding["path"],
            "sha256": meta["sha256"],
            "owner_uid": meta["owner_uid"],
            "file_identity": _identity_binding(meta),
            "evidence_provenance": evidence_provenance,
            "restore_test_provenance": restore_provenance,
        })
        evidence_summary.append(summary)

    snapshot = {
        "schema_version": 1,
        "kind": VERIFICATION_KIND,
        "source_revision": source_revision,
        "bundle_path": bundle_meta["path"],
        "bundle_sha256": bundle_meta["sha256"],
        "bundle_owner_uid": bundle_meta["owner_uid"],
        "bundle_file_identity": _identity_binding(bundle_meta),
        "recovery_contract_path": recovery_meta["path"],
        "recovery_contract_sha256": recovery_meta["sha256"],
        "recovery_contract_file_identity": _identity_binding(recovery_meta),
        "nix_lifecycle_contract_path": lifecycle_meta["path"],
        "nix_lifecycle_contract_sha256": lifecycle_meta["sha256"],
        "nix_lifecycle_contract_file_identity": _identity_binding(lifecycle_meta),
        "observed_at": bundle["observed_at"],
        "freshness_seconds": max_age,
        "receipts": normalized_receipts,
        "evidence_summary": evidence_summary,
        "production_effects_authorized": False,
    }
    if expected_snapshot is not None and snapshot != expected_snapshot:
        raise ReadinessError("pre-cutover readiness drifted after plan compilation")
    return _copy_json(snapshot)


def revalidate_readiness(
    snapshot: dict[str, Any],
    *,
    source_revision: str,
    recovery_contract_path: Path,
    lifecycle_contract_path: Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(snapshot, dict) or snapshot.get("kind") != VERIFICATION_KIND:
        raise ReadinessError("reviewed pre-cutover readiness snapshot is missing")
    return validate_readiness(
        Path(snapshot.get("bundle_path", "")),
        source_revision=source_revision,
        recovery_contract_path=recovery_contract_path,
        lifecycle_contract_path=lifecycle_contract_path,
        now=now,
        expected_snapshot=snapshot,
    )
