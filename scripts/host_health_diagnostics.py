#!/usr/bin/env python3
"""Bounded Heim-PC hardware diagnostics; never stress-tests, unmounts, or flashes."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any, BinaryIO, Callable, Iterable
import zipfile

DEFAULT_CONFIG = Path("/etc/heim-pc/host-health-remediation.v1.json")
DEFAULT_MCE_STATE = Path("/var/lib/heim-pc/host-health/mce-edac-state.v1.json")
DEFAULT_MCE_REPORT = Path("/var/lib/heim-pc/host-health/mce-edac-report.v1.json")
DEFAULT_BOARD_NAME = Path("/sys/class/dmi/id/board_name")
DEFAULT_BIOS_VERSION = Path("/sys/class/dmi/id/bios_version")
FSCK_OUTPUT_LIMIT_BYTES = 4096
MAX_BIOS_PACKAGE_BYTES = 64 * 1024 * 1024
MAX_BIOS_PACKAGE_MEMBERS = 8
Runner = Callable[..., subprocess.CompletedProcess[str]]


class DiagnosticError(RuntimeError):
    pass


def load_config(path: Path) -> dict[str, Any]:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DiagnosticError(f"cannot load diagnostics config: {exc}") from exc
    if (
        not isinstance(config, dict)
        or config.get("schema_version") != 1
        or config.get("kind") != "heim_pc_host_health_log_remediation"
    ):
        raise DiagnosticError("unsupported diagnostics config")
    return config


def _completed(
    runner: Runner,
    argv: list[str],
    *,
    timeout: int = 20,
) -> subprocess.CompletedProcess[str]:
    try:
        return runner(argv, text=True, capture_output=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DiagnosticError(f"cannot execute {argv[0]}: {exc}") from exc


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )
    current = Path(path.anchor) if path.is_absolute() else Path()
    for part in path.parent.parts:
        if part in {"", path.anchor}:
            continue
        current = current / part
        if current.is_symlink():
            raise DiagnosticError(f"unsafe state directory symlink: {current}")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise DiagnosticError(f"unsafe state directory: {path.parent}")
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise DiagnosticError(f"unsafe state file: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def _mce_config(config: dict[str, Any]) -> dict[str, int]:
    value = config.get("mce_edac")
    if not isinstance(value, dict):
        raise DiagnosticError("mce_edac config is missing")
    limits = {
        "lookback_hours": (1, 168),
        "max_journal_entries": (1, 10000),
        "occurrence_gap_seconds": (1, 60),
        "retained_occurrence_ids": (1, 10000),
        "sample_message_limit": (1, 20),
        "sample_message_bytes": (32, 1000),
    }
    result: dict[str, int] = {}
    for key, (minimum, maximum) in limits.items():
        candidate = value.get(key)
        if not isinstance(candidate, int) or not minimum <= candidate <= maximum:
            raise DiagnosticError(f"mce_edac.{key} must be between {minimum} and {maximum}")
        result[key] = candidate
    if result["retained_occurrence_ids"] < result["max_journal_entries"]:
        raise DiagnosticError(
            "mce_edac.retained_occurrence_ids must cover max_journal_entries"
        )
    if (
        value.get("state_schema_version") != 2
        or value.get("deduplication")
        != "bounded_constituent_overlap_and_boundary_span"
        or value.get("constituent_evidence_limit")
        != result["max_journal_entries"]
    ):
        raise DiagnosticError("mce_edac evidence contract is inconsistent")
    return result


def read_bounded_kernel_journal(
    policy: dict[str, int], *, runner: Runner = subprocess.run
) -> list[dict[str, Any]]:
    argv = [
        "journalctl",
        f"--since=-{policy['lookback_hours']}h",
        f"--lines={policy['max_journal_entries']}",
        "--no-pager",
        "--output=json",
        "_TRANSPORT=kernel",
    ]
    completed = _completed(runner, argv, timeout=25)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise DiagnosticError(f"bounded kernel journal read failed: {detail[:500]}")
    records: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def is_mce_edac_event(message: str) -> bool:
    normalized = message.casefold()
    if "[hardware error]" in normalized or "machine check events logged" in normalized:
        return True
    return bool(
        re.search(r"\bedac\b", normalized)
        and re.search(
            r"\b(error|errors|corrected|uncorrected|fatal|ce|ue)\b",
            normalized,
        )
    )


def _event_rows(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        message = record.get("MESSAGE")
        timestamp = record.get("__REALTIME_TIMESTAMP")
        if not isinstance(message, str) or not is_mce_edac_event(message):
            continue
        try:
            timestamp_us = int(timestamp)
        except (TypeError, ValueError):
            continue
        boot_id = record.get("_BOOT_ID")
        normalized_boot_id = boot_id if isinstance(boot_id, str) else "unknown"
        cursor = record.get("__CURSOR")
        if isinstance(cursor, str) and cursor:
            constituent_identity = f"cursor\0{cursor}".encode("utf-8")
        else:
            monotonic = record.get("__MONOTONIC_TIMESTAMP")
            constituent_identity = json.dumps(
                [
                    normalized_boot_id,
                    timestamp_us,
                    monotonic if isinstance(monotonic, str) else None,
                    message,
                ],
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        rows.append(
            {
                "boot_id": normalized_boot_id,
                "timestamp_us": timestamp_us,
                "message": message,
                "constituent_id": hashlib.sha256(constituent_identity).hexdigest(),
            }
        )
    return sorted(
        rows,
        key=lambda item: (
            item["boot_id"],
            item["timestamp_us"],
            item["constituent_id"],
        ),
    )


def group_occurrences(
    records: Iterable[dict[str, Any]], *, gap_seconds: int
) -> list[dict[str, Any]]:
    rows = _event_rows(records)
    groups: list[list[dict[str, Any]]] = []
    gap_us = gap_seconds * 1_000_000
    for row in rows:
        if (
            not groups
            or groups[-1][-1]["boot_id"] != row["boot_id"]
            or row["timestamp_us"] - groups[-1][-1]["timestamp_us"] > gap_us
        ):
            groups.append([row])
        else:
            groups[-1].append(row)
    occurrences: list[dict[str, Any]] = []
    for group in groups:
        identity = f"constituent\0{group[0]['constituent_id']}".encode("utf-8")
        occurrences.append(
            {
                "id": hashlib.sha256(identity).hexdigest(),
                "boot_id": group[0]["boot_id"],
                "first_timestamp_us": group[0]["timestamp_us"],
                "last_timestamp_us": group[-1]["timestamp_us"],
                "messages": [item["message"] for item in group],
                "constituents": [
                    {
                        "id": item["constituent_id"],
                        "timestamp_us": item["timestamp_us"],
                    }
                    for item in group
                ],
            }
        )
    return sorted(
        occurrences,
        key=lambda item: (
            item["first_timestamp_us"],
            item["boot_id"],
            item["id"],
        ),
    )


def _empty_mce_state() -> dict[str, Any]:
    return {
        "schema_version": 2,
        "kind": "heim_pc_mce_edac_state",
        "total_occurrences": 0,
        "occurrence_evidence": [],
        "legacy_seen_occurrence_ids": [],
    }


def _legacy_occurrence_id(occurrence: dict[str, Any]) -> str:
    identity = (
        f"{occurrence['boot_id']}:{occurrence['first_timestamp_us']}".encode("utf-8")
    )
    return hashlib.sha256(identity).hexdigest()


def _normalize_mce_state(state: dict[str, Any]) -> dict[str, Any]:
    if (
        isinstance(state, dict)
        and state.get("schema_version") == 1
        and state.get("kind") == "heim_pc_mce_edac_state"
        and isinstance(state.get("total_occurrences"), int)
        and state["total_occurrences"] >= 0
        and isinstance(state.get("seen_occurrence_ids"), list)
        and all(isinstance(item, str) for item in state["seen_occurrence_ids"])
    ):
        return {
            "schema_version": 2,
            "kind": "heim_pc_mce_edac_state",
            "total_occurrences": state["total_occurrences"],
            "occurrence_evidence": [],
            "legacy_seen_occurrence_ids": list(
                dict.fromkeys(state["seen_occurrence_ids"])
            ),
            "last_observed_event_utc": state.get("last_observed_event_utc"),
            "migrated_from_schema_version": 1,
        }
    if (
        not isinstance(state, dict)
        or state.get("schema_version") != 2
        or state.get("kind") != "heim_pc_mce_edac_state"
        or not isinstance(state.get("total_occurrences"), int)
        or state["total_occurrences"] < 0
        or not isinstance(state.get("occurrence_evidence"), list)
        or not isinstance(state.get("legacy_seen_occurrence_ids"), list)
        or not all(
            isinstance(item, str) for item in state["legacy_seen_occurrence_ids"]
        )
    ):
        raise DiagnosticError("invalid MCE/EDAC state")

    normalized_evidence: list[dict[str, Any]] = []
    evidence_ids: set[str] = set()
    constituent_ids: set[str] = set()
    for evidence in state["occurrence_evidence"]:
        if (
            not isinstance(evidence, dict)
            or not isinstance(evidence.get("id"), str)
            or not isinstance(evidence.get("boot_id"), str)
            or not isinstance(evidence.get("first_timestamp_us"), int)
            or not isinstance(evidence.get("last_timestamp_us"), int)
            or evidence["first_timestamp_us"] > evidence["last_timestamp_us"]
            or not isinstance(evidence.get("constituents"), list)
        ):
            raise DiagnosticError("invalid MCE/EDAC occurrence evidence")
        if evidence["id"] in evidence_ids:
            raise DiagnosticError("duplicate MCE/EDAC occurrence evidence")
        evidence_ids.add(evidence["id"])
        constituents: list[dict[str, Any]] = []
        for constituent in evidence["constituents"]:
            if (
                not isinstance(constituent, dict)
                or not isinstance(constituent.get("id"), str)
                or not isinstance(constituent.get("timestamp_us"), int)
            ):
                raise DiagnosticError("invalid MCE/EDAC constituent evidence")
            if constituent["id"] in constituent_ids:
                raise DiagnosticError("duplicate MCE/EDAC constituent evidence")
            constituent_ids.add(constituent["id"])
            constituents.append(
                {
                    "id": constituent["id"],
                    "timestamp_us": constituent["timestamp_us"],
                }
            )
        normalized_evidence.append(
            {
                "id": evidence["id"],
                "boot_id": evidence["boot_id"],
                "first_timestamp_us": evidence["first_timestamp_us"],
                "last_timestamp_us": evidence["last_timestamp_us"],
                "constituents": constituents,
            }
        )
    return {
        "schema_version": 2,
        "kind": "heim_pc_mce_edac_state",
        "total_occurrences": state["total_occurrences"],
        "occurrence_evidence": normalized_evidence,
        "legacy_seen_occurrence_ids": list(
            dict.fromkeys(state["legacy_seen_occurrence_ids"])
        ),
        "last_observed_event_utc": state.get("last_observed_event_utc"),
    }


def _load_mce_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return _empty_mce_state()
    if path.is_symlink() or not path.is_file():
        raise DiagnosticError(f"unsafe MCE/EDAC state path: {path}")
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DiagnosticError(f"cannot load MCE/EDAC state: {exc}") from exc
    return _normalize_mce_state(state)


def _utc(timestamp_us: int | None) -> str | None:
    if timestamp_us is None:
        return None
    return datetime.fromtimestamp(timestamp_us / 1_000_000, timezone.utc).isoformat()


def analyze_mce_edac(
    records: Iterable[dict[str, Any]],
    state: dict[str, Any],
    policy: dict[str, int],
) -> tuple[dict[str, Any], dict[str, Any]]:
    occurrences = group_occurrences(records, gap_seconds=policy["occurrence_gap_seconds"])
    normalized_state = _normalize_mce_state(state)
    evidence_by_id = {
        item["id"]: {
            **item,
            "constituents": list(item["constituents"]),
        }
        for item in normalized_state["occurrence_evidence"]
    }
    constituent_owners: dict[str, set[str]] = {}
    for evidence in evidence_by_id.values():
        for constituent in evidence["constituents"]:
            constituent_owners.setdefault(constituent["id"], set()).add(evidence["id"])

    legacy_seen = set(normalized_state["legacy_seen_occurrence_ids"])
    assigned_ids: set[str] = set()
    new_count = 0
    gap_us = policy["occurrence_gap_seconds"] * 1_000_000
    for occurrence in occurrences:
        constituent_ids = {
            constituent["id"] for constituent in occurrence["constituents"]
        }
        overlap_counts: dict[str, int] = {}
        for constituent_id in constituent_ids:
            for evidence_id in constituent_owners.get(constituent_id, set()):
                if evidence_id not in assigned_ids:
                    overlap_counts[evidence_id] = overlap_counts.get(evidence_id, 0) + 1

        matched_id: str | None = None
        if overlap_counts:
            if len(overlap_counts) != 1:
                raise DiagnosticError(
                    "ambiguous MCE/EDAC occurrence overlap; state was not advanced"
                )
            matched_id = next(iter(overlap_counts))
        else:
            boundary_candidates: list[tuple[int, str]] = []
            for evidence_id, evidence in evidence_by_id.items():
                if evidence_id in assigned_ids or evidence["boot_id"] != occurrence["boot_id"]:
                    continue
                if occurrence["first_timestamp_us"] > evidence["last_timestamp_us"]:
                    distance = (
                        occurrence["first_timestamp_us"] - evidence["last_timestamp_us"]
                    )
                elif evidence["first_timestamp_us"] > occurrence["last_timestamp_us"]:
                    distance = (
                        evidence["first_timestamp_us"] - occurrence["last_timestamp_us"]
                    )
                else:
                    distance = 0
                if distance <= gap_us:
                    boundary_candidates.append((distance, evidence_id))
            if boundary_candidates:
                if len(boundary_candidates) != 1:
                    raise DiagnosticError(
                        "ambiguous MCE/EDAC boundary continuation; "
                        "state was not advanced"
                    )
                matched_id = boundary_candidates[0][1]

        legacy_id = _legacy_occurrence_id(occurrence)
        if matched_id is None and legacy_id in legacy_seen:
            matched_id = legacy_id
        if matched_id is None:
            matched_id = occurrence["id"]
            new_count += 1

        assigned_ids.add(matched_id)
        previous = evidence_by_id.get(matched_id)
        merged_constituents: dict[str, dict[str, Any]] = {}
        if previous is not None:
            for constituent in previous["constituents"]:
                merged_constituents[constituent["id"]] = constituent
        for constituent in occurrence["constituents"]:
            merged_constituents[constituent["id"]] = constituent
        evidence = {
            "id": matched_id,
            "boot_id": occurrence["boot_id"],
            "first_timestamp_us": min(
                occurrence["first_timestamp_us"],
                (
                    previous["first_timestamp_us"]
                    if previous is not None
                    else occurrence["first_timestamp_us"]
                ),
            ),
            "last_timestamp_us": max(
                occurrence["last_timestamp_us"],
                (
                    previous["last_timestamp_us"]
                    if previous is not None
                    else occurrence["last_timestamp_us"]
                ),
            ),
            "constituents": sorted(
                merged_constituents.values(),
                key=lambda item: (item["timestamp_us"], item["id"]),
            ),
        }
        evidence_by_id[matched_id] = evidence

    retained_evidence = sorted(
        evidence_by_id.values(),
        key=lambda item: (item["last_timestamp_us"], item["id"]),
        reverse=True,
    )[: policy["retained_occurrence_ids"]]
    newest_constituents = sorted(
        (
            (constituent["timestamp_us"], constituent["id"])
            for evidence in retained_evidence
            for constituent in evidence["constituents"]
        ),
        reverse=True,
    )[: policy["max_journal_entries"]]
    retained_constituent_ids = {
        constituent_id for _timestamp, constituent_id in newest_constituents
    }
    for evidence in retained_evidence:
        evidence["constituents"] = [
            constituent
            for constituent in evidence["constituents"]
            if constituent["id"] in retained_constituent_ids
        ]
    retained_evidence.sort(
        key=lambda item: (item["last_timestamp_us"], item["id"])
    )

    total = normalized_state["total_occurrences"] + new_count
    if total == 0:
        status = "no_events"
    elif total == 1:
        status = "first_occurrence"
    else:
        status = "recurrent"

    messages: list[str] = []
    for occurrence in occurrences:
        for message in occurrence["messages"]:
            concise = " ".join(message.split())[: policy["sample_message_bytes"]]
            if concise not in messages:
                messages.append(concise)
            if len(messages) >= policy["sample_message_limit"]:
                break
        if len(messages) >= policy["sample_message_limit"]:
            break
    first_timestamp = min(
        (item["first_timestamp_us"] for item in occurrences), default=None
    )
    last_timestamp = max(
        (item["last_timestamp_us"] for item in occurrences), default=None
    )
    updated_state = {
        "schema_version": 2,
        "kind": "heim_pc_mce_edac_state",
        "total_occurrences": total,
        "occurrence_evidence": retained_evidence,
        "legacy_seen_occurrence_ids": list(
            dict.fromkeys(
                [
                    *normalized_state["legacy_seen_occurrence_ids"],
                    *(
                        _legacy_occurrence_id(occurrence)
                        for occurrence in occurrences
                    ),
                ]
            )
        )[-policy["retained_occurrence_ids"] :],
        "last_observed_event_utc": _utc(last_timestamp),
    }
    report = {
        "schema_version": 1,
        "kind": "heim_pc_mce_edac_report",
        "status": status,
        "recurrent": total > 1,
        "new_occurrences": new_count,
        "total_occurrences": total,
        "occurrences_in_bounded_window": len(occurrences),
        "matching_messages_in_bounded_window": sum(
            len(item["messages"]) for item in occurrences
        ),
        "first_event_utc_in_window": _utc(first_timestamp),
        "last_event_utc_in_window": _utc(last_timestamp),
        "sample_messages": messages,
        "bounds": {
            "lookback_hours": policy["lookback_hours"],
            "max_journal_entries": policy["max_journal_entries"],
            "retained_occurrence_ids": policy["retained_occurrence_ids"],
        },
        "does_not_establish": [
            "hardware_stability",
            "absence_of_events_outside_the_bounded_window",
            "a stress_test",
            "automatic_hardware_remediation",
        ],
    }
    return updated_state, report


def run_mce_edac(
    config: dict[str, Any],
    *,
    state_path: Path,
    report_path: Path,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    policy = _mce_config(config)
    records = read_bounded_kernel_journal(policy, runner=runner)
    state = _load_mce_state(state_path)
    updated_state, report = analyze_mce_edac(records, state, policy)
    _atomic_json(state_path, updated_state)
    _atomic_json(report_path, report)
    return report


def parse_cpuinfo(text: str) -> tuple[str, set[str]]:
    vendor = ""
    flags: set[str] = set()
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        normalized_key = key.strip().casefold()
        if normalized_key == "vendor_id" and not vendor:
            vendor = value.strip()
        elif normalized_key in {"flags", "features"} and not flags:
            flags = set(value.split())
        if vendor and flags:
            break
    return vendor, flags


def evaluate_kvm_svm(
    *,
    vendor: str,
    flags: set[str],
    kvm_module: bool,
    vendor_module: bool,
    dev_kvm: bool,
) -> dict[str, Any]:
    vendor_normalized = vendor.casefold()
    if "amd" in vendor_normalized:
        virtualization_flag = "svm"
        firmware_name = "SVM"
        module_name = "kvm_amd"
    elif "intel" in vendor_normalized:
        virtualization_flag = "vmx"
        firmware_name = "Intel virtualization"
        module_name = "kvm_intel"
    else:
        return {
            "status": "unsupported_cpu_vendor",
            "kernel_module_failure": False,
            "automatic_bios_fix": False,
            "vendor": vendor,
        }

    flag_present = virtualization_flag in flags
    if not flag_present:
        status = "bios_virtualization_disabled_or_hidden"
        kernel_module_failure = False
        action = (
            f"Enable {firmware_name} in UEFI setup and reboot; the running OS "
            "cannot make that firmware setting effective automatically."
        )
    elif not vendor_module:
        status = "kernel_vendor_module_missing"
        kernel_module_failure = True
        action = f"Inspect why {module_name} did not load; firmware exposes the CPU flag."
    elif not kvm_module:
        status = "kernel_kvm_core_missing"
        kernel_module_failure = True
        action = "Inspect the generic kvm module; firmware exposes the CPU flag."
    elif not dev_kvm:
        status = "kvm_device_missing"
        kernel_module_failure = True
        action = "Inspect KVM device creation and udev after confirming loaded modules."
    else:
        status = "ready"
        kernel_module_failure = False
        action = "No KVM/SVM remediation indicated."
    return {
        "schema_version": 1,
        "kind": "heim_pc_kvm_svm_truth",
        "status": status,
        "vendor": vendor,
        "virtualization_flag": virtualization_flag,
        "virtualization_flag_present": flag_present,
        "kvm_module_present": kvm_module,
        "vendor_module": module_name,
        "vendor_module_present": vendor_module,
        "dev_kvm_present": dev_kvm,
        "kernel_module_failure": kernel_module_failure,
        "recommended_action": action,
        "automatic_bios_fix": False,
        "does_not_establish": [
            "that a BIOS setting was changed",
            "that nested virtualization is available",
        ],
    }


def kvm_svm_truth(
    *,
    cpuinfo_path: Path = Path("/proc/cpuinfo"),
    sys_module_root: Path = Path("/sys/module"),
    dev_kvm_path: Path = Path("/dev/kvm"),
) -> dict[str, Any]:
    try:
        vendor, flags = parse_cpuinfo(cpuinfo_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise DiagnosticError(f"cannot read CPU flags: {exc}") from exc
    vendor_module = "kvm_amd" if "amd" in vendor.casefold() else "kvm_intel"
    return evaluate_kvm_svm(
        vendor=vendor,
        flags=flags,
        kvm_module=(sys_module_root / "kvm").is_dir(),
        vendor_module=(sys_module_root / vendor_module).is_dir(),
        dev_kvm=dev_kvm_path.exists(),
    )


def _mounts_for(
    device: Path, *, runner: Runner
) -> subprocess.CompletedProcess[str]:
    return _completed(
        runner,
        ["findmnt", "-rn", "-S", str(device), "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"],
    )


def fat_check_or_repair(
    device: Path,
    *,
    repair: bool,
    confirmed: bool,
    runner: Runner = subprocess.run,
    require_block_device: bool = True,
) -> tuple[int, dict[str, Any]]:
    if repair and not confirmed:
        raise DiagnosticError("repair requires --confirm-offline-repair")
    try:
        resolved = device.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise DiagnosticError(f"cannot resolve FAT device: {exc}") from exc
    if require_block_device and not stat.S_ISBLK(metadata.st_mode):
        raise DiagnosticError("FAT target must be a block device")

    first_mount_check = _mounts_for(resolved, runner=runner)
    if first_mount_check.returncode not in (0, 1):
        raise DiagnosticError("cannot determine FAT mount state")
    if first_mount_check.stdout.strip():
        raise DiagnosticError(f"refusing mounted filesystem: {resolved}")

    topology = _completed(
        runner, ["lsblk", "-ndo", "TYPE,FSTYPE", str(resolved)]
    )
    if topology.returncode != 0:
        raise DiagnosticError("cannot determine FAT device type")
    fields = topology.stdout.split()
    if len(fields) < 2 or fields[0] not in {"part", "disk"}:
        raise DiagnosticError("FAT target must be a disk or partition")
    filesystem = fields[1].casefold()
    if filesystem not in {"fat", "vfat", "msdos"}:
        raise DiagnosticError(f"refusing non-FAT filesystem: {filesystem or 'unknown'}")

    second_mount_check = _mounts_for(resolved, runner=runner)
    if second_mount_check.returncode not in (0, 1):
        raise DiagnosticError("cannot re-confirm FAT mount state")
    if second_mount_check.stdout.strip():
        raise DiagnosticError(f"refusing filesystem mounted during preflight: {resolved}")

    passes: list[dict[str, Any]] = []

    def run_fsck(mode: str, option: str) -> subprocess.CompletedProcess[str]:
        completed = _completed(
            runner, ["fsck.fat", option, str(resolved)], timeout=60
        )
        passes.append(_fsck_pass_report(mode, completed))
        return completed

    primary = run_fsck("repair" if repair else "check", "-a" if repair else "-n")
    verification: subprocess.CompletedProcess[str] | None = None
    if repair and primary.returncode in (0, 1):
        verification = run_fsck("verification", "-n")

    if not repair:
        success = primary.returncode == 0
        if primary.returncode == 0:
            status = "clean"
        elif primary.returncode == 1:
            status = "inconsistencies_detected"
        else:
            status = "check_failed"
    elif primary.returncode not in (0, 1):
        success = False
        status = "repair_failed"
    elif verification is None:
        raise DiagnosticError("repair verification pass was not executed")
    elif verification.returncode == 0:
        success = True
        status = "repair_verified_clean"
    elif verification.returncode == 1:
        success = False
        status = "repair_verification_inconsistencies_detected"
    else:
        success = False
        status = "repair_verification_failed"

    report = {
        "schema_version": 1,
        "kind": "heim_pc_offline_fat_result",
        "device": str(resolved),
        "filesystem": filesystem,
        "mode": "repair" if repair else "check",
        "status": status,
        "mounted": False,
        "fsck_returncode": primary.returncode,
        "check_returncode": primary.returncode if not repair else None,
        "repair_returncode": primary.returncode if repair else None,
        "verification_returncode": (
            verification.returncode if verification is not None else None
        ),
        "passes": passes,
        "success": success,
        "automatic_unmount": False,
        "online_modification_allowed": False,
        "does_not_establish": [
            "race_free_exclusion_against_a_concurrent_privileged_mount",
            "filesystem_backup",
            "successful firmware recovery",
        ],
    }
    return (0 if success else 1), report


def _bounded_process_text(value: str) -> tuple[str, bool, int]:
    encoded = value.encode("utf-8", errors="replace")
    bounded = encoded[:FSCK_OUTPUT_LIMIT_BYTES]
    return (
        bounded.decode("utf-8", errors="ignore"),
        len(encoded) > FSCK_OUTPUT_LIMIT_BYTES,
        len(encoded),
    )


def _fsck_pass_report(
    mode: str, completed: subprocess.CompletedProcess[str]
) -> dict[str, Any]:
    stdout, stdout_truncated, stdout_bytes = _bounded_process_text(
        completed.stdout or ""
    )
    stderr, stderr_truncated, stderr_bytes = _bounded_process_text(
        completed.stderr or ""
    )
    return {
        "mode": mode,
        "returncode": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "output_limit_bytes_per_stream": FSCK_OUTPUT_LIMIT_BYTES,
    }


def _sha256_stream(handle: BinaryIO) -> str:
    digest = hashlib.sha256()
    while chunk := handle.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest().upper()


def _open_bios_package(path: Path) -> BinaryIO:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise DiagnosticError("BIOS package must be a regular file")
        if metadata.st_size > MAX_BIOS_PACKAGE_BYTES:
            raise DiagnosticError("BIOS package exceeds the inspection size bound")
        handle = os.fdopen(descriptor, "rb")
        descriptor = None
        return handle
    except OSError as exc:
        raise DiagnosticError(f"cannot open BIOS package safely: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_zip_member_name(name: str) -> None:
    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or "\x00" in name
        or any(part in {"", ".", ".."} for part in name.split("/"))
    ):
        raise DiagnosticError(f"unsafe BIOS package member name: {name!r}")


def _inspect_bios_package(
    handle: BinaryIO,
    *,
    expected_members: list[str],
    cap_member: str,
    cap_size_bytes: int,
) -> tuple[list[str], str]:
    try:
        with zipfile.ZipFile(handle) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_BIOS_PACKAGE_MEMBERS:
                raise DiagnosticError("BIOS package contains too many members")
            names = [entry.filename for entry in entries]
            for name in names:
                _validate_zip_member_name(name)
            if len(names) != len(set(names)) or len(names) != len(
                {name.casefold() for name in names}
            ):
                raise DiagnosticError("BIOS package contains duplicate member names")
            if names.count(cap_member) != 1:
                raise DiagnosticError(
                    "BIOS package must contain exactly one expected CAP member"
                )
            if len(names) != len(expected_members) or set(names) != set(
                expected_members
            ):
                raise DiagnosticError("BIOS package contains unexpected member names")
            for entry in entries:
                unix_mode = entry.external_attr >> 16
                file_type = stat.S_IFMT(unix_mode)
                if entry.is_dir() or stat.S_ISLNK(unix_mode):
                    raise DiagnosticError(
                        f"unsafe BIOS package member type: {entry.filename!r}"
                    )
                if file_type not in (0, stat.S_IFREG):
                    raise DiagnosticError(
                        f"unsupported BIOS package member type: {entry.filename!r}"
                    )
                if entry.flag_bits & 0x1:
                    raise DiagnosticError("encrypted BIOS package members are unsupported")
            cap_entry = archive.getinfo(cap_member)
            if cap_entry.file_size != cap_size_bytes:
                raise DiagnosticError("BIOS CAP member size differs from metadata")
            if cap_entry.file_size > MAX_BIOS_PACKAGE_BYTES:
                raise DiagnosticError("BIOS CAP member exceeds the inspection size bound")
            with archive.open(cap_entry, "r") as cap_handle:
                cap_digest = _sha256_stream(cap_handle)
            return names, cap_digest
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise DiagnosticError(f"cannot inspect BIOS ZIP package: {exc}") from exc


def verify_bios_preparation(
    config: dict[str, Any],
    *,
    target_name: str,
    board_name: str,
    live_version: str,
    package_path: Path,
) -> tuple[int, dict[str, Any]]:
    bios = config.get("bios")
    if not isinstance(bios, dict) or not isinstance(bios.get("targets"), dict):
        raise DiagnosticError("bios config is missing")
    target = bios["targets"].get(target_name)
    if not isinstance(target, dict):
        raise DiagnosticError(f"unknown BIOS target: {target_name}")
    expected_package_hash = target.get("package_sha256")
    target_version = target.get("version")
    expected_members = target.get("package_members")
    cap_member = target.get("cap_member")
    cap_size_bytes = target.get("cap_size_bytes")
    if (
        not isinstance(expected_package_hash, str)
        or not re.fullmatch(r"[0-9A-F]{64}", expected_package_hash)
        or not isinstance(target_version, str)
        or not isinstance(expected_members, list)
        or not expected_members
        or not all(isinstance(item, str) for item in expected_members)
        or len(expected_members) != len(set(expected_members))
        or not isinstance(cap_member, str)
        or expected_members.count(cap_member) != 1
        or cap_member
        != f"ROG-STRIX-B550-F-GAMING-ASUS-{target_version}.CAP"
        or not isinstance(cap_size_bytes, int)
        or not 1 <= cap_size_bytes <= MAX_BIOS_PACKAGE_BYTES
    ):
        raise DiagnosticError("invalid BIOS target metadata")
    expected_board = bios.get("board_name")
    expected_source = bios.get("observed_source_version")
    board_matches = board_name.strip() == expected_board
    source_matches = live_version.strip() == expected_source
    with _open_bios_package(package_path) as package_handle:
        package_hash = _sha256_stream(package_handle)
        package_hash_matches = package_hash == expected_package_hash
        package_members: list[str] | None = None
        cap_hash: str | None = None
        if package_hash_matches:
            package_handle.seek(0)
            package_members, cap_hash = _inspect_bios_package(
                package_handle,
                expected_members=expected_members,
                cap_member=cap_member,
                cap_size_bytes=cap_size_bytes,
            )
    ready = board_matches and source_matches and package_hash_matches
    report = {
        "schema_version": 1,
        "kind": "heim_pc_bios_preparation_verification",
        "board_name": board_name.strip(),
        "expected_board_name": expected_board,
        "board_matches": board_matches,
        "live_bios_version": live_version.strip(),
        "expected_source_version": expected_source,
        "source_version_matches": source_matches,
        "target_channel": target_name,
        "target_version": target_version,
        "expected_package_sha256": expected_package_hash,
        "package_sha256": package_hash,
        "package_hash_matches": package_hash_matches,
        "expected_package_members": expected_members,
        "package_members": package_members,
        "expected_cap_member": cap_member,
        "cap_member": cap_member if package_members is not None else None,
        "cap_size_bytes": cap_size_bytes if package_members is not None else None,
        "cap_sha256": cap_hash,
        "cap_sha256_provenance": (
            "locally_derived_from_verified_package"
            if cap_hash is not None
            else None
        ),
        "ready_for_manual_uefi_flash": ready,
        "automatic_flash": False,
        "requires_reboot_and_uefi": True,
        "does_not_establish": [
            "vendor_signature_authenticity_beyond_the_pinned_package_digest",
            "a separately_vendor_pinned_CAP_digest",
            "firmware_flash_success",
            "permission_to_flash",
            "automatic_SVM_enablement",
        ],
    }
    return (0 if ready else 1), report


def _read_trimmed(path: Path, label: str) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise DiagnosticError(f"cannot read {label}: {exc}") from exc
    if not value:
        raise DiagnosticError(f"{label} is empty")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    subparsers = parser.add_subparsers(dest="command", required=True)

    mce = subparsers.add_parser("mce-edac", help="update the bounded recurrence report")
    mce.add_argument("--state", type=Path, default=DEFAULT_MCE_STATE)
    mce.add_argument("--report", type=Path, default=DEFAULT_MCE_REPORT)

    subparsers.add_parser("kvm-svm", help="report CPU-flag, module, and /dev/kvm truth")

    fat = subparsers.add_parser("fat", help="check or explicitly repair an offline FAT device")
    fat.add_argument("device", type=Path)
    fat.add_argument("--repair", action="store_true")
    fat.add_argument("--confirm-offline-repair", action="store_true")

    bios = subparsers.add_parser(
        "bios", help="verify board, live version, and a pinned ASUS ZIP package"
    )
    bios.add_argument("--target", choices=("stable", "beta"), default="stable")
    bios.add_argument("--package", type=Path, required=True)
    bios.add_argument("--board-name-path", type=Path, default=DEFAULT_BOARD_NAME)
    bios.add_argument("--bios-version-path", type=Path, default=DEFAULT_BIOS_VERSION)

    args = parser.parse_args()
    try:
        config = load_config(args.config)
        if args.command == "mce-edac":
            report = run_mce_edac(
                config,
                state_path=args.state,
                report_path=args.report,
            )
            returncode = 0
        elif args.command == "kvm-svm":
            report = kvm_svm_truth()
            returncode = 0
        elif args.command == "fat":
            returncode, report = fat_check_or_repair(
                args.device,
                repair=args.repair,
                confirmed=args.confirm_offline_repair,
            )
        else:
            returncode, report = verify_bios_preparation(
                config,
                target_name=args.target,
                board_name=_read_trimmed(args.board_name_path, "board name"),
                live_version=_read_trimmed(args.bios_version_path, "BIOS version"),
                package_path=args.package,
            )
    except DiagnosticError as exc:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "heim_pc_host_health_diagnostic_error",
                    "error": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
