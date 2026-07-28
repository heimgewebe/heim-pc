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
        rows.append(
            {
                "boot_id": boot_id if isinstance(boot_id, str) else "unknown",
                "timestamp_us": timestamp_us,
                "message": message,
            }
        )
    return sorted(rows, key=lambda item: (item["boot_id"], item["timestamp_us"]))


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
        identity = f"{group[0]['boot_id']}:{group[0]['timestamp_us']}".encode("utf-8")
        occurrences.append(
            {
                "id": hashlib.sha256(identity).hexdigest(),
                "boot_id": group[0]["boot_id"],
                "first_timestamp_us": group[0]["timestamp_us"],
                "last_timestamp_us": group[-1]["timestamp_us"],
                "messages": [item["message"] for item in group],
            }
        )
    return occurrences


def _load_mce_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "schema_version": 1,
            "kind": "heim_pc_mce_edac_state",
            "total_occurrences": 0,
            "seen_occurrence_ids": [],
        }
    if path.is_symlink() or not path.is_file():
        raise DiagnosticError(f"unsafe MCE/EDAC state path: {path}")
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DiagnosticError(f"cannot load MCE/EDAC state: {exc}") from exc
    if (
        not isinstance(state, dict)
        or state.get("schema_version") != 1
        or state.get("kind") != "heim_pc_mce_edac_state"
        or not isinstance(state.get("total_occurrences"), int)
        or not isinstance(state.get("seen_occurrence_ids"), list)
        or not all(isinstance(item, str) for item in state["seen_occurrence_ids"])
    ):
        raise DiagnosticError("invalid MCE/EDAC state")
    return state


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
    seen = list(dict.fromkeys(state["seen_occurrence_ids"]))
    seen_set = set(seen)
    new = [item for item in occurrences if item["id"] not in seen_set]
    updated_seen = (seen + [item["id"] for item in new])[
        -policy["retained_occurrence_ids"] :
    ]
    total = state["total_occurrences"] + len(new)
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
        "schema_version": 1,
        "kind": "heim_pc_mce_edac_state",
        "total_occurrences": total,
        "seen_occurrence_ids": updated_seen,
        "last_observed_event_utc": _utc(last_timestamp),
    }
    report = {
        "schema_version": 1,
        "kind": "heim_pc_mce_edac_report",
        "status": status,
        "recurrent": total > 1,
        "new_occurrences": len(new),
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
