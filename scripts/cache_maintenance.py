#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import contextmanager
import configparser
import fcntl
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Iterable
import urllib.parse

POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "cache-policy.v1.json"
PLAN_KIND = "heim_pc.cache_maintenance_plan"
RECEIPT_KIND = "heim_pc.cache_maintenance_receipt"
PIN_KIND = "heim_pc.cache_maintenance_pins"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{12,64}$")
BUILD_RECORD_ID_RE = re.compile(r"^[a-z0-9]{8,128}$")
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024 * 1024
CommandRunner = Callable[[list[str]], dict[str, Any]]


class PolicyError(ValueError):
    pass


class PlanError(RuntimeError):
    pass


class ScanDeadlineExceeded(PlanError):
    pass


class ApplyError(RuntimeError):
    pass


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _expand_path(value: str, home: Path) -> Path:
    if not isinstance(value, str) or not value:
        raise PolicyError("configured paths must be non-empty strings")
    expanded = value.replace("${HOME}", str(home)).replace("~", str(home), 1)
    path = Path(expanded)
    if not path.is_absolute():
        raise PolicyError(f"configured path must be absolute after expansion: {value}")
    return path.resolve(strict=False)


def _positive_int(value: Any, label: str, *, allow_zero: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise PolicyError(f"{label} must be an integer")
    minimum = 0 if allow_zero else 1
    if value < minimum:
        raise PolicyError(f"{label} must be >= {minimum}")
    return value


def _ensure_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ApplyError(f"state directory may not be a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise ApplyError(f"state directory is not owner controlled: {path}")
    os.chmod(path, 0o700)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    _ensure_private_directory(path.parent)
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def _exclusive_state_lock(path: Path) -> Iterable[None]:
    _ensure_private_directory(path.parent)
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ApplyError(f"cannot open exclusive state lock: {path}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise ApplyError("exclusive state lock is not owner controlled")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _read_json_file(path: Path, *, max_bytes: int = 4 * 1024 * 1024) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink():
        raise ValueError(f"JSON path may not be a symlink: {path}")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
        raise ValueError(f"JSON path is not a bounded regular file: {path}")
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON document must be an object: {path}")
    return value, raw


def load_policy(path: Path = POLICY_PATH, *, home: Path | None = None) -> dict[str, Any]:
    resolved_home = (home or Path.home()).resolve(strict=True)
    value, raw = _read_json_file(path)
    if value.get("schema_version") != 1 or value.get("kind") != "heim_pc.cache_maintenance_policy":
        raise PolicyError("cache policy schema or kind mismatch")
    if value.get("automatic_apply") is not False:
        raise PolicyError("automatic_apply must remain false")
    policy_id = value.get("policy_id")
    if not isinstance(policy_id, str) or not policy_id:
        raise PolicyError("policy_id must be non-empty")
    safety = value.get("safety")
    if not isinstance(safety, dict):
        raise PolicyError("safety must be an object")
    required_false = {
        "follow_symlinks",
        "cross_filesystems",
        "docker_volumes_authorized",
        "referenced_images_authorized",
        "active_build_cache_authorized",
        "unknown_owner_authorized",
    }
    for key in required_false:
        if safety.get(key) is not False:
            raise PolicyError(f"safety.{key} must remain false")
    for key in ("require_exact_plan_hash", "require_exact_candidate_set"):
        if safety.get(key) is not True:
            raise PolicyError(f"safety.{key} must be true")
    limits = value.get("limits")
    if not isinstance(limits, dict):
        raise PolicyError("limits must be an object")
    for key in (
        "max_entries_per_candidate",
        "max_processes",
        "max_open_file_descriptors",
        "max_plan_candidates",
        "receipt_retention_count",
        "max_scan_seconds_per_candidate",
        "max_plan_seconds",
        "max_docker_records",
    ):
        _positive_int(limits.get(key), f"limits.{key}")
    pins = value.get("pins")
    if not isinstance(pins, dict):
        raise PolicyError("pins must be an object")
    _expand_path(pins.get("path"), resolved_home)
    _positive_int(pins.get("max_ttl_hours"), "pins.max_ttl_hours")
    classes = value.get("classes")
    required_classes = {
        "filesystem_cache",
        "trash",
        "grabowski_releases",
        "maintenance_journal",
        "docker_build_cache",
        "docker_images",
        "user_journal",
    }
    if not isinstance(classes, dict) or set(classes) != required_classes:
        raise PolicyError(f"classes must be exactly {sorted(required_classes)}")
    for class_id, spec in classes.items():
        if not isinstance(spec, dict) or not isinstance(spec.get("apply_authorized"), bool):
            raise PolicyError(f"class {class_id} requires apply_authorized boolean")
    fs_targets = classes["filesystem_cache"].get("targets")
    if not isinstance(fs_targets, list) or not fs_targets:
        raise PolicyError("filesystem_cache.targets must be non-empty")
    target_ids: set[str] = set()
    target_paths: set[str] = set()
    for target in fs_targets:
        if not isinstance(target, dict):
            raise PolicyError("filesystem cache target must be an object")
        target_id = target.get("id")
        if not isinstance(target_id, str) or not target_id or target_id in target_ids:
            raise PolicyError("filesystem cache target ids must be unique non-empty strings")
        target_ids.add(target_id)
        resolved = str(_expand_path(target.get("path"), resolved_home))
        if resolved in target_paths:
            raise PolicyError("filesystem cache target paths must be unique")
        target_paths.add(resolved)
        _positive_int(target.get("minimum_unused_seconds"), f"filesystem target {target_id} age")
    trash = classes["trash"]
    _expand_path(trash.get("root"), resolved_home)
    _positive_int(trash.get("minimum_age_seconds"), "trash.minimum_age_seconds")
    releases = classes["grabowski_releases"]
    _expand_path(releases.get("root"), resolved_home)
    _expand_path(releases.get("deployment_manifest"), resolved_home)
    _positive_int(releases.get("keep_newest_fallbacks"), "grabowski_releases.keep_newest_fallbacks", allow_zero=True)
    _positive_int(releases.get("minimum_age_seconds"), "grabowski_releases.minimum_age_seconds")
    journals = classes["maintenance_journal"]
    roots = journals.get("roots")
    if not isinstance(roots, list) or not roots:
        raise PolicyError("maintenance_journal.roots must be non-empty")
    for root in roots:
        _expand_path(root, resolved_home)
    _positive_int(journals.get("keep_newest_per_root"), "maintenance_journal.keep_newest_per_root")
    _positive_int(journals.get("minimum_age_seconds"), "maintenance_journal.minimum_age_seconds")
    build = classes["docker_build_cache"]
    if not isinstance(build.get("builder"), str) or not build["builder"]:
        raise PolicyError("docker_build_cache.builder must be non-empty")
    for key in ("minimum_unused_seconds", "reserved_space_bytes", "max_used_space_bytes"):
        _positive_int(build.get(key), f"docker_build_cache.{key}")
    if build["reserved_space_bytes"] > build["max_used_space_bytes"]:
        raise PolicyError("docker build cache reserved space cannot exceed max used space")
    images = classes["docker_images"]
    if images.get("dangling_only") is not True:
        raise PolicyError("docker_images.dangling_only must remain true")
    _positive_int(images.get("minimum_age_seconds"), "docker_images.minimum_age_seconds")
    if classes["user_journal"].get("apply_authorized") is not False:
        raise PolicyError("user_journal must remain report-only")
    result = json.loads(json.dumps(value))
    result["policy_sha256"] = _sha256_bytes(raw)
    result["resolved_home"] = str(resolved_home)
    result["resolved_state_root"] = str(_expand_path(value["state_root"], resolved_home))
    return result


def _default_runner(argv: list[str]) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            argv,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            env={**os.environ, "LC_ALL": "C.UTF-8"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "returncode": 124 if isinstance(exc, subprocess.TimeoutExpired) else 127,
            "stdout": "",
            "stderr": str(exc),
            "duration_seconds": round(time.monotonic() - started, 3),
        }
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "duration_seconds": round(time.monotonic() - started, 3),
    }


def _run_checked(
    runner: CommandRunner, argv: list[str]
) -> dict[str, Any]:
    result = runner(argv)
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    if not isinstance(stdout, str) or not isinstance(stderr, str):
        raise PlanError("command runner output must be text")
    if (
        len(stdout.encode("utf-8", errors="replace"))
        > MAX_COMMAND_OUTPUT_BYTES
        or len(stderr.encode("utf-8", errors="replace"))
        > MAX_COMMAND_OUTPUT_BYTES
    ):
        raise PlanError("command output exceeds byte limit")
    if int(result.get("returncode", 1)) != 0:
        detail = str(stderr or stdout or "command failed")[:1000]
        raise PlanError(f"command failed ({argv[0]}): {detail}")
    return result


def _parse_size(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    if not isinstance(value, str):
        return 0
    text = value.strip().replace(" ", "")
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([kMGTPE]?i?B)", text, re.I)
    if match is None:
        return 0
    amount = float(match.group(1))
    unit = match.group(2).upper()
    powers = {"B": 0, "KB": 1, "KIB": 1, "MB": 2, "MIB": 2, "GB": 3, "GIB": 3, "TB": 4, "TIB": 4, "PB": 5, "PIB": 5, "EB": 6, "EIB": 6}
    base = 1024 if "I" in unit else 1000
    return int(amount * (base ** powers[unit]))


def _path_inside(path: Path, root: Path) -> bool:
    try:
        return path == root or root in path.parents
    except RuntimeError:
        return False


def _check_scan_deadline(deadline_monotonic: float | None) -> None:
    if deadline_monotonic is not None and time.monotonic() > deadline_monotonic:
        raise ScanDeadlineExceeded("scan-time-budget-exceeded")


def _candidate_deadline(
    policy: dict[str, Any], overall_deadline: float | None
) -> float:
    candidate_deadline = (
        time.monotonic() + policy["limits"]["max_scan_seconds_per_candidate"]
    )
    return min(candidate_deadline, overall_deadline) if overall_deadline is not None else candidate_deadline


def _tree_snapshot(
    path: Path,
    *,
    max_entries: int,
    cross_filesystems: bool = False,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    _check_scan_deadline(deadline_monotonic)
    if path.is_symlink():
        raise ValueError("symlink target is excluded")
    root_info = os.stat(path, follow_symlinks=False)
    if root_info.st_uid != os.geteuid():
        raise PermissionError("target is not owned by the current user")
    root_device = root_info.st_dev
    entries: list[tuple[str, int, int, int, int, int, int]] = []
    allocated = 0
    apparent = 0
    max_mtime_ns = root_info.st_mtime_ns

    def add_entry(entry_path: Path, relative: str) -> None:
        nonlocal allocated, apparent, max_mtime_ns
        _check_scan_deadline(deadline_monotonic)
        info = os.stat(entry_path, follow_symlinks=False)
        if info.st_uid != os.geteuid():
            raise PermissionError(f"entry is not owner controlled: {relative}")
        if not cross_filesystems and info.st_dev != root_device:
            raise ValueError(f"cross-filesystem entry is excluded: {relative}")
        entries.append(
            (
                relative,
                info.st_dev,
                info.st_ino,
                info.st_mode,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )
        )
        if len(entries) > max_entries:
            raise ValueError("candidate exceeds entry limit")
        allocated += info.st_blocks * 512
        apparent += info.st_size
        max_mtime_ns = max(max_mtime_ns, info.st_mtime_ns)

    add_entry(path, ".")
    if stat.S_ISDIR(root_info.st_mode):
        for directory, names, filenames in os.walk(
            path, topdown=True, followlinks=False
        ):
            _check_scan_deadline(deadline_monotonic)
            names.sort()
            filenames.sort()
            base = Path(directory)
            for name in names:
                child = base / name
                add_entry(child, child.relative_to(path).as_posix())
            for name in filenames:
                child = base / name
                add_entry(child, child.relative_to(path).as_posix())
    identity_material = {
        "entries": entries,
        "allocated_bytes": allocated,
        "apparent_bytes": apparent,
        "max_mtime_ns": max_mtime_ns,
        "device": root_device,
    }
    movable_entries = [
        (relative, device, inode, mode, size, mtime_ns)
        for (
            relative,
            device,
            inode,
            mode,
            size,
            mtime_ns,
            _ctime_ns,
        ) in entries
    ]
    movable_material = {
        "entries": movable_entries,
        "allocated_bytes": allocated,
        "apparent_bytes": apparent,
        "max_mtime_ns": max_mtime_ns,
        "device": root_device,
    }
    return {
        "path": str(path),
        "entry_count": len(entries),
        "allocated_bytes": allocated,
        "apparent_bytes": apparent,
        "max_mtime_ns": max_mtime_ns,
        "identity_sha256": _sha256_json(
            {"path": str(path), **identity_material}
        ),
        "content_identity_sha256": _sha256_json(identity_material),
        "movable_identity_sha256": _sha256_json(movable_material),
        "device": root_device,
    }


def _process_observation(policy: dict[str, Any]) -> dict[str, Any]:
    limits = policy["limits"]
    max_processes = limits["max_processes"]
    max_fds = limits["max_open_file_descriptors"]
    uid = os.geteuid()
    paths: list[dict[str, Any]] = []
    build_pids: list[int] = []
    process_count = 0
    fd_count = 0
    complete = True
    errors: list[str] = []
    proc = Path("/proc")
    for entry in sorted(proc.iterdir(), key=lambda item: item.name):
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != uid:
                continue
        except FileNotFoundError:
            continue
        process_count += 1
        if process_count > max_processes:
            complete = False
            errors.append("process-limit-exceeded")
            break
        pid = int(entry.name)
        try:
            raw_cmdline = (entry / "cmdline").read_bytes()
            command = raw_cmdline.replace(b"\0", b" ").decode("utf-8", errors="replace")
            lowered = command.lower()
            if (
                "docker buildx build" in lowered
                or "docker build " in lowered
                or "buildctl build" in lowered
            ):
                build_pids.append(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            complete = False
            errors.append(f"cmdline-permission:{pid}")
        for kind, link in (("cwd", entry / "cwd"), ("exe", entry / "exe")):
            try:
                paths.append({"pid": pid, "kind": kind, "path": os.readlink(link)})
            except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
                pass
        fd_root = entry / "fd"
        try:
            descriptors = list(fd_root.iterdir())
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            complete = False
            errors.append(f"fd-permission:{pid}")
            continue
        for descriptor in descriptors:
            fd_count += 1
            if fd_count > max_fds:
                complete = False
                errors.append("fd-limit-exceeded")
                break
            try:
                target = os.readlink(descriptor)
            except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
                continue
            if target.startswith("/"):
                paths.append({"pid": pid, "kind": "fd", "path": target})
        if fd_count > max_fds:
            break
    unique = {
        (item["pid"], item["kind"], item["path"]): item
        for item in paths
    }
    return {
        "complete": complete,
        "process_count": min(process_count, max_processes),
        "open_file_descriptors_checked": min(fd_count, max_fds),
        "path_references": [unique[key] for key in sorted(unique)],
        "active_docker_build_pids": sorted(set(build_pids)),
        "errors": sorted(set(errors)),
    }


def _references_for_path(observation: dict[str, Any], path: Path) -> list[dict[str, Any]]:
    references: list[dict[str, Any]] = []
    for item in observation.get("path_references", []):
        raw = item.get("path")
        if not isinstance(raw, str) or not raw.startswith("/"):
            continue
        candidate = Path(raw.split(" (deleted)", 1)[0]).resolve(strict=False)
        if _path_inside(candidate, path):
            references.append({"pid": item["pid"], "kind": item["kind"]})
    return references


def _load_pins(policy: dict[str, Any], *, home: Path, now: int) -> dict[str, dict[str, Any]]:
    path = _expand_path(policy["pins"]["path"], home)
    if not path.exists():
        return {}
    value, _raw = _read_json_file(path)
    if value.get("schema_version") != 1 or value.get("kind") != PIN_KIND:
        raise PlanError("pin registry contract mismatch")
    entries = value.get("pins")
    if not isinstance(entries, list):
        raise PlanError("pin registry pins must be a list")
    result: dict[str, dict[str, Any]] = {}
    for item in entries:
        if not isinstance(item, dict):
            raise PlanError("pin entry must be an object")
        target = item.get("target")
        expires = item.get("expires_at_unix")
        reason = item.get("reason")
        if not isinstance(target, str) or not target:
            raise PlanError("pin target must be non-empty")
        if not isinstance(expires, int) or isinstance(expires, bool):
            raise PlanError("pin expiry must be an integer")
        if not isinstance(reason, str) or not reason.strip():
            raise PlanError("pin reason must be non-empty")
        if expires > now:
            result[target] = item
    return result


def _candidate_id(class_id: str, stable_key: str) -> str:
    digest = hashlib.sha256(stable_key.encode("utf-8")).hexdigest()[:20]
    return f"{class_id}:{digest}"


def _candidate(
    class_id: str,
    stable_key: str,
    kind: str,
    paths: list[dict[str, Any]],
    *,
    allocated_bytes: int,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    return {
        "class_id": class_id,
        "candidate_id": _candidate_id(class_id, stable_key),
        "kind": kind,
        "stable_key": stable_key,
        "paths": paths,
        "allocated_bytes": allocated_bytes,
        "metadata": metadata,
        "automatic_cleanup_authorized": False,
    }


def _exclusion(class_id: str, stable_key: str, reason: str, **evidence: Any) -> dict[str, Any]:
    return {
        "class_id": class_id,
        "stable_key": stable_key,
        "reason": reason,
        "evidence": evidence,
        "automatic_cleanup_authorized": False,
    }


def _snapshot_exclusion_reason(exc: Exception) -> str:
    return (
        "scan-time-budget-exceeded"
        if isinstance(exc, ScanDeadlineExceeded)
        else "snapshot-blocked"
    )


def _process_visibility_block(
    class_id: str, processes: dict[str, Any]
) -> dict[str, Any]:
    return {
        "candidates": [],
        "exclusions": [
            _exclusion(
                class_id,
                "process-observation",
                "process-observation-incomplete",
                errors=processes.get("errors", []),
                process_count=processes.get("process_count"),
                open_file_descriptors_checked=processes.get(
                    "open_file_descriptors_checked"
                ),
            )
        ],
    }


def _observe_filesystem_cache(
    policy: dict[str, Any],
    home: Path,
    now: int,
    processes: dict[str, Any],
    pins: dict[str, dict[str, Any]],
    overall_deadline: float | None = None,
) -> dict[str, Any]:
    class_id = "filesystem_cache"
    if not processes["complete"]:
        return _process_visibility_block(class_id, processes)
    candidates: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    max_entries = policy["limits"]["max_entries_per_candidate"]
    for target in policy["classes"][class_id]["targets"]:
        _check_scan_deadline(overall_deadline)
        root = _expand_path(target["path"], home)
        if not root.exists():
            exclusions.append(
                _exclusion(
                    class_id, str(root), "target-missing", target_id=target["id"]
                )
            )
            continue
        if root.is_symlink() or not root.is_dir():
            exclusions.append(
                _exclusion(
                    class_id,
                    str(root),
                    "target-not-regular-directory",
                    target_id=target["id"],
                )
            )
            continue
        try:
            children = sorted(root.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            exclusions.append(
                _exclusion(
                    class_id,
                    str(root),
                    "target-unreadable",
                    error=str(exc)[:300],
                )
            )
            continue
        for child in children:
            _check_scan_deadline(overall_deadline)
            stable = str(child)
            try:
                snapshot = _tree_snapshot(
                    child,
                    max_entries=max_entries,
                    deadline_monotonic=_candidate_deadline(
                        policy, overall_deadline
                    ),
                )
            except Exception as exc:
                exclusions.append(
                    _exclusion(
                        class_id,
                        stable,
                        _snapshot_exclusion_reason(exc),
                        error=str(exc)[:300],
                    )
                )
                continue
            candidate_id = _candidate_id(class_id, stable)
            if candidate_id in pins or stable in pins:
                exclusions.append(
                    _exclusion(
                        class_id,
                        stable,
                        "pinned",
                        pin=pins.get(candidate_id) or pins.get(stable),
                    )
                )
                continue
            age_seconds = max(
                0, now - snapshot["max_mtime_ns"] // 1_000_000_000
            )
            if age_seconds < target["minimum_unused_seconds"]:
                exclusions.append(
                    _exclusion(
                        class_id, stable, "too-recent", age_seconds=age_seconds
                    )
                )
                continue
            references = _references_for_path(processes, child)
            if references:
                exclusions.append(
                    _exclusion(
                        class_id,
                        stable,
                        "active-process-reference",
                        references=references,
                    )
                )
                continue
            candidates.append(
                _candidate(
                    class_id,
                    stable,
                    "filesystem_entry",
                    [snapshot],
                    allocated_bytes=snapshot["allocated_bytes"],
                    metadata={
                        "target_id": target["id"],
                        "age_seconds": age_seconds,
                    },
                )
            )
    return {"candidates": candidates, "exclusions": exclusions}


def _trash_deletion_unix(info_path: Path) -> int:
    parser = configparser.ConfigParser(interpolation=None)
    with info_path.open("r", encoding="utf-8") as handle:
        parser.read_file(handle)
    if not parser.has_section("Trash Info"):
        raise ValueError("missing Trash Info section")
    value = parser.get("Trash Info", "DeletionDate")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.now().astimezone().tzinfo)
    return int(parsed.timestamp())


def _observe_trash(
    policy: dict[str, Any],
    home: Path,
    now: int,
    processes: dict[str, Any],
    pins: dict[str, dict[str, Any]],
    overall_deadline: float | None = None,
) -> dict[str, Any]:
    class_id = "trash"
    if not processes["complete"]:
        return _process_visibility_block(class_id, processes)
    spec = policy["classes"][class_id]
    root = _expand_path(spec["root"], home)
    files_root = root / "files"
    info_root = root / "info"
    candidates: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    max_entries = policy["limits"]["max_entries_per_candidate"]
    if not files_root.is_dir() or not info_root.is_dir():
        return {
            "candidates": [],
            "exclusions": [
                _exclusion(class_id, str(root), "trash-layout-missing")
            ],
        }
    for info_path in sorted(
        info_root.glob("*.trashinfo"), key=lambda item: item.name
    ):
        _check_scan_deadline(overall_deadline)
        name = info_path.name.removesuffix(".trashinfo")
        payload = files_root / name
        stable = str(payload)
        if not payload.exists() and not payload.is_symlink():
            exclusions.append(
                _exclusion(
                    class_id,
                    stable,
                    "payload-missing",
                    info_path=str(info_path),
                )
            )
            continue
        try:
            deleted_at = _trash_deletion_unix(info_path)
        except Exception as exc:
            exclusions.append(
                _exclusion(
                    class_id,
                    stable,
                    "trash-info-invalid",
                    error=str(exc)[:300],
                )
            )
            continue
        age_seconds = max(0, now - deleted_at)
        if age_seconds < spec["minimum_age_seconds"]:
            exclusions.append(
                _exclusion(
                    class_id, stable, "too-recent", age_seconds=age_seconds
                )
            )
            continue
        candidate_id = _candidate_id(class_id, stable)
        if candidate_id in pins or stable in pins:
            exclusions.append(
                _exclusion(
                    class_id,
                    stable,
                    "pinned",
                    pin=pins.get(candidate_id) or pins.get(stable),
                )
            )
            continue
        references = _references_for_path(processes, payload)
        if references:
            exclusions.append(
                _exclusion(
                    class_id,
                    stable,
                    "active-process-reference",
                    references=references,
                )
            )
            continue
        try:
            deadline = _candidate_deadline(policy, overall_deadline)
            payload_snapshot = _tree_snapshot(
                payload,
                max_entries=max_entries,
                deadline_monotonic=deadline,
            )
            info_snapshot = _tree_snapshot(
                info_path,
                max_entries=max_entries,
                deadline_monotonic=deadline,
            )
        except Exception as exc:
            exclusions.append(
                _exclusion(
                    class_id,
                    stable,
                    _snapshot_exclusion_reason(exc),
                    error=str(exc)[:300],
                )
            )
            continue
        candidates.append(
            _candidate(
                class_id,
                stable,
                "trash_pair",
                [payload_snapshot, info_snapshot],
                allocated_bytes=(
                    payload_snapshot["allocated_bytes"]
                    + info_snapshot["allocated_bytes"]
                ),
                metadata={
                    "name": name,
                    "deletion_unix": deleted_at,
                    "age_seconds": age_seconds,
                    "original_path_redacted_sha256": _sha256_json(
                        urllib.parse.unquote(parser_value(info_path, "Path"))
                    ),
                },
            )
        )
    return {"candidates": candidates, "exclusions": exclusions}


def parser_value(info_path: Path, key: str) -> str:
    parser = configparser.ConfigParser(interpolation=None)
    with info_path.open("r", encoding="utf-8") as handle:
        parser.read_file(handle)
    return parser.get("Trash Info", key, fallback="")


def _active_release_id(manifest_path: Path) -> str | None:
    if not manifest_path.exists():
        return None
    try:
        value, _raw = _read_json_file(manifest_path)
    except Exception:
        return None
    release_id = value.get("release_id")
    return release_id if isinstance(release_id, str) and release_id else None


def _observe_releases(
    policy: dict[str, Any],
    home: Path,
    now: int,
    processes: dict[str, Any],
    pins: dict[str, dict[str, Any]],
    overall_deadline: float | None = None,
) -> dict[str, Any]:
    class_id = "grabowski_releases"
    if not processes["complete"]:
        return _process_visibility_block(class_id, processes)
    spec = policy["classes"][class_id]
    root = _expand_path(spec["root"], home)
    manifest = _expand_path(spec["deployment_manifest"], home)
    candidates: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    if not root.is_dir():
        return {
            "candidates": [],
            "exclusions": [
                _exclusion(class_id, str(root), "release-root-missing")
            ],
        }
    releases = [
        path for path in root.iterdir() if path.is_dir() and not path.is_symlink()
    ]
    releases.sort(
        key=lambda path: (path.stat().st_mtime_ns, path.name), reverse=True
    )
    active = _active_release_id(manifest)
    release_names = {path.name for path in releases}
    if active is None or active not in release_names:
        return {
            "candidates": [],
            "exclusions": [
                _exclusion(
                    class_id,
                    str(root),
                    "active-release-identity-unavailable",
                    manifest_path=str(manifest),
                    manifest_release_id=active,
                )
            ],
            "observation": {
                "active_release_id": active,
                "fallback_release_ids": [],
            },
        }
    fallbacks = [path.name for path in releases if path.name != active][
        : spec["keep_newest_fallbacks"]
    ]
    protected = set(fallbacks)
    if active:
        protected.add(active)
    max_entries = policy["limits"]["max_entries_per_candidate"]
    for release in releases:
        _check_scan_deadline(overall_deadline)
        stable = str(release)
        if release.name in protected:
            exclusions.append(
                _exclusion(
                    class_id,
                    stable,
                    "active-or-fallback",
                    active=release.name == active,
                )
            )
            continue
        candidate_id = _candidate_id(class_id, stable)
        if candidate_id in pins or release.name in pins or stable in pins:
            exclusions.append(
                _exclusion(
                    class_id,
                    stable,
                    "pinned",
                    pin=(
                        pins.get(candidate_id)
                        or pins.get(release.name)
                        or pins.get(stable)
                    ),
                )
            )
            continue
        references = _references_for_path(processes, release)
        if references:
            exclusions.append(
                _exclusion(
                    class_id,
                    stable,
                    "active-process-reference",
                    references=references,
                )
            )
            continue
        try:
            snapshot = _tree_snapshot(
                release,
                max_entries=max_entries,
                deadline_monotonic=_candidate_deadline(
                    policy, overall_deadline
                ),
            )
        except Exception as exc:
            exclusions.append(
                _exclusion(
                    class_id,
                    stable,
                    _snapshot_exclusion_reason(exc),
                    error=str(exc)[:300],
                )
            )
            continue
        age_seconds = max(
            0, now - snapshot["max_mtime_ns"] // 1_000_000_000
        )
        if age_seconds < spec["minimum_age_seconds"]:
            exclusions.append(
                _exclusion(
                    class_id, stable, "too-recent", age_seconds=age_seconds
                )
            )
            continue
        candidates.append(
            _candidate(
                class_id,
                stable,
                "release_directory",
                [snapshot],
                allocated_bytes=snapshot["allocated_bytes"],
                metadata={
                    "release_id": release.name,
                    "age_seconds": age_seconds,
                },
            )
        )
    return {
        "candidates": candidates,
        "exclusions": exclusions,
        "observation": {
            "active_release_id": active,
            "fallback_release_ids": fallbacks,
        },
    }


def _observe_maintenance_journal(
    policy: dict[str, Any],
    home: Path,
    now: int,
    pins: dict[str, dict[str, Any]],
    overall_deadline: float | None = None,
) -> dict[str, Any]:
    class_id = "maintenance_journal"
    spec = policy["classes"][class_id]
    candidates: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    for configured in spec["roots"]:
        _check_scan_deadline(overall_deadline)
        root = _expand_path(configured, home)
        if not root.is_dir():
            exclusions.append(
                _exclusion(class_id, str(root), "journal-root-missing")
            )
            continue
        files = [
            path
            for path in root.glob("*.json")
            if path.is_file() and not path.is_symlink()
        ]
        files.sort(
            key=lambda path: (path.stat().st_mtime_ns, path.name), reverse=True
        )
        for index, path in enumerate(files):
            _check_scan_deadline(overall_deadline)
            stable = str(path)
            if index < spec["keep_newest_per_root"]:
                exclusions.append(
                    _exclusion(
                        class_id, stable, "retained-newest", rank=index + 1
                    )
                )
                continue
            try:
                snapshot = _tree_snapshot(
                    path,
                    max_entries=1,
                    deadline_monotonic=_candidate_deadline(
                        policy, overall_deadline
                    ),
                )
            except Exception as exc:
                exclusions.append(
                    _exclusion(
                        class_id,
                        stable,
                        _snapshot_exclusion_reason(exc),
                        error=str(exc)[:300],
                    )
                )
                continue
            age_seconds = max(
                0, now - snapshot["max_mtime_ns"] // 1_000_000_000
            )
            candidate_id = _candidate_id(class_id, stable)
            if candidate_id in pins or stable in pins:
                exclusions.append(
                    _exclusion(
                        class_id,
                        stable,
                        "pinned",
                        pin=pins.get(candidate_id) or pins.get(stable),
                    )
                )
                continue
            if age_seconds < spec["minimum_age_seconds"]:
                exclusions.append(
                    _exclusion(
                        class_id, stable, "too-recent", age_seconds=age_seconds
                    )
                )
                continue
            candidates.append(
                _candidate(
                    class_id,
                    stable,
                    "journal_file",
                    [snapshot],
                    allocated_bytes=snapshot["allocated_bytes"],
                    metadata={"age_seconds": age_seconds},
                )
            )
    return {"candidates": candidates, "exclusions": exclusions}


def _build_filter(spec: dict[str, Any]) -> str:
    hours = max(1, spec["minimum_unused_seconds"] // 3600)
    return f"until={hours}h"


def _build_cache_records(
    runner: CommandRunner,
    spec: dict[str, Any],
    *,
    max_records: int = 10_000,
) -> list[dict[str, Any]]:
    argv = [
        "docker",
        "buildx",
        "du",
        "--builder",
        spec["builder"],
        "--filter",
        _build_filter(spec),
        "--format",
        "json",
    ]
    result = _run_checked(runner, argv)
    records: list[dict[str, Any]] = []
    for line in str(result.get("stdout", "")).splitlines():
        if not line.strip():
            continue
        if len(records) >= max_records:
            raise PlanError("docker build cache record limit exceeded")
        value = json.loads(line)
        if not isinstance(value, dict):
            raise PlanError("docker buildx du emitted a non-object")
        record_id = value.get("ID")
        if (
            not isinstance(record_id, str)
            or BUILD_RECORD_ID_RE.fullmatch(record_id) is None
        ):
            raise PlanError("docker build cache record id is invalid")
        records.append(
            {
                "id": record_id,
                "size_bytes": _parse_size(value.get("Size")),
                "reclaimable": value.get("Reclaimable") is True,
                "mutable": value.get("Mutable") is True,
                "shared": value.get("Shared") is True,
                "type": (
                    value.get("Type")
                    if isinstance(value.get("Type"), str)
                    else None
                ),
                "created_at": (
                    value.get("CreatedAt")
                    if isinstance(value.get("CreatedAt"), str)
                    else None
                ),
                "last_used_at": (
                    value.get("LastUsedAt")
                    if isinstance(value.get("LastUsedAt"), str)
                    else None
                ),
            }
        )
    records.sort(key=lambda item: item["id"])
    return records


def _observe_docker_build_cache(
    policy: dict[str, Any], runner: CommandRunner, processes: dict[str, Any], pins: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    class_id = "docker_build_cache"
    spec = policy["classes"][class_id]
    exclusions: list[dict[str, Any]] = []
    if not processes.get("complete"):
        return _process_visibility_block(class_id, processes)
    try:
        records = _build_cache_records(
            runner,
            spec,
            max_records=policy["limits"]["max_docker_records"],
        )
    except Exception as exc:
        return {"candidates": [], "exclusions": [_exclusion(class_id, spec["builder"], "docker-observation-failed", error=str(exc)[:500])]}
    reclaimable = [record for record in records if record["reclaimable"] and not record["mutable"]]
    mutable = [record["id"] for record in records if record["mutable"]]
    if mutable:
        exclusions.append(_exclusion(class_id, spec["builder"], "mutable-build-cache-records", record_ids=mutable))
    if processes["active_docker_build_pids"]:
        exclusions.append(
            _exclusion(
                class_id,
                spec["builder"],
                "active-docker-build",
                pids=processes["active_docker_build_pids"],
            )
        )
        return {"candidates": [], "exclusions": exclusions, "observation": {"record_count": len(records)}}
    if not reclaimable:
        exclusions.append(_exclusion(class_id, spec["builder"], "no-reclaimable-records"))
        return {"candidates": [], "exclusions": exclusions, "observation": {"record_count": len(records)}}
    record_ids = [record["id"] for record in reclaimable]
    stable = f"{spec['builder']}:{_sha256_json(record_ids)}"
    candidate_id = _candidate_id(class_id, stable)
    if candidate_id in pins or spec["builder"] in pins:
        exclusions.append(_exclusion(class_id, stable, "pinned", pin=pins.get(candidate_id) or pins.get(spec["builder"])))
        return {"candidates": [], "exclusions": exclusions, "observation": {"record_count": len(records)}}
    candidate = _candidate(
        class_id,
        stable,
        "docker_build_cache_set",
        [],
        allocated_bytes=sum(record["size_bytes"] for record in reclaimable),
        metadata={
            "builder": spec["builder"],
            "filter": _build_filter(spec),
            "record_ids": record_ids,
            "records_sha256": _sha256_json(reclaimable),
            "reserved_space_bytes": spec["reserved_space_bytes"],
            "max_used_space_bytes": spec["max_used_space_bytes"],
        },
    )
    return {"candidates": [candidate], "exclusions": exclusions, "observation": {"record_count": len(records)}}


def _docker_container_image_ids(
    runner: CommandRunner, *, max_records: int
) -> set[str]:
    listed = _run_checked(runner, ["docker", "container", "ls", "-aq"])
    container_ids = [
        line.strip()
        for line in str(listed.get("stdout", "")).splitlines()
        if line.strip()
    ]
    if len(container_ids) > max_records:
        raise PlanError("docker container record limit exceeded")
    if any(CONTAINER_ID_RE.fullmatch(item) is None for item in container_ids):
        raise PlanError("docker container id is invalid")
    if len(container_ids) != len(set(container_ids)):
        raise PlanError("docker container ids contain duplicates")
    if not container_ids:
        return set()
    inspected = _run_checked(
        runner,
        [
            "docker",
            "container",
            "inspect",
            "--format",
            "{{.Image}}",
            *container_ids,
        ],
    )
    lines = [
        line.strip()
        for line in str(inspected.get("stdout", "")).splitlines()
        if line.strip()
    ]
    if len(lines) != len(container_ids):
        raise PlanError("docker container inspect result count mismatch")
    result = set(lines)
    if any(IMAGE_ID_RE.fullmatch(item) is None for item in result):
        raise PlanError("docker container image reference is invalid")
    return result


def _parse_created(value: str) -> int:
    text = value.strip().strip('"')
    match = re.fullmatch(
        r"(?P<prefix>.+T\d{2}:\d{2}:\d{2})"
        r"(?:\.(?P<fraction>\d+))?"
        r"(?P<zone>Z|[+-]\d{2}:\d{2})",
        text,
    )
    if match is None:
        raise ValueError("Docker creation timestamp is not RFC3339")
    fraction = match.group("fraction")
    normalized_fraction = (fraction or "")[:6].ljust(6, "0")
    normalized = (
        f"{match.group('prefix')}.{normalized_fraction}"
        f"{match.group('zone').replace('Z', '+00:00')}"
    )
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def _normalize_reference_names(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise PlanError(f"docker image {label} is invalid")
    return sorted(set(value))


def _dangling_images(
    runner: CommandRunner, *, max_records: int = 10_000
) -> list[dict[str, Any]]:
    result = _run_checked(
        runner,
        [
            "docker",
            "image",
            "ls",
            "--filter",
            "dangling=true",
            "--no-trunc",
            "--format",
            "{{json .}}",
        ],
    )
    images: dict[str, dict[str, Any]] = {}
    for line in str(result.get("stdout", "")).splitlines():
        if not line.strip():
            continue
        if len(images) >= max_records:
            raise PlanError("docker image record limit exceeded")
        value = json.loads(line)
        if not isinstance(value, dict):
            raise PlanError("docker image list emitted a non-object")
        image_id = value.get("ID")
        if (
            not isinstance(image_id, str)
            or IMAGE_ID_RE.fullmatch(image_id) is None
        ):
            raise PlanError("docker image id is invalid")
        if value.get("Tag") not in {"<none>", None}:
            raise PlanError("dangling image query returned a tagged image")
        listed_containers_raw = value.get("Containers", "0")
        try:
            listed_containers = int(listed_containers_raw)
        except (TypeError, ValueError) as exc:
            raise PlanError("docker image container count is invalid") from exc
        if listed_containers < 0:
            raise PlanError("docker image container count is negative")
        inspected = _run_checked(
            runner,
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{json .}}",
                image_id,
            ],
        )
        inspected_value = json.loads(str(inspected.get("stdout", "")).strip())
        if not isinstance(inspected_value, dict):
            raise PlanError("docker image inspect emitted a non-object")
        if inspected_value.get("Id") != image_id:
            raise PlanError("docker image inspect identity mismatch")
        created_raw = inspected_value.get("Created")
        if not isinstance(created_raw, str) or not created_raw:
            raise PlanError("docker image creation timestamp is invalid")
        size_raw = inspected_value.get("Size")
        if not isinstance(size_raw, int) or isinstance(size_raw, bool) or size_raw < 0:
            raise PlanError("docker image size is invalid")
        repo_tags = _normalize_reference_names(
            inspected_value.get("RepoTags"), "RepoTags"
        )
        repo_digests = _normalize_reference_names(
            inspected_value.get("RepoDigests"), "RepoDigests"
        )
        images[image_id] = {
            "image_id": image_id,
            "created_unix": _parse_created(created_raw),
            "size_bytes": size_raw,
            "listed_container_count": listed_containers,
            "repo_tags": repo_tags,
            "repo_digests": repo_digests,
            "inspect_sha256": _sha256_json(inspected_value),
            "display_repository": (
                value.get("Repository")
                if isinstance(value.get("Repository"), str)
                else None
            ),
        }
    return [images[key] for key in sorted(images)]


def _observe_docker_images(
    policy: dict[str, Any],
    runner: CommandRunner,
    now: int,
    pins: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    class_id = "docker_images"
    spec = policy["classes"][class_id]
    candidates: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    try:
        referenced = _docker_container_image_ids(
            runner,
            max_records=policy["limits"]["max_docker_records"],
        )
        images = _dangling_images(
            runner,
            max_records=policy["limits"]["max_docker_records"],
        )
    except Exception as exc:
        return {
            "candidates": [],
            "exclusions": [
                _exclusion(
                    class_id,
                    "docker",
                    "docker-observation-failed",
                    error=str(exc)[:500],
                )
            ],
        }
    for image in images:
        image_id = image["image_id"]
        if image_id in referenced or image["listed_container_count"] > 0:
            exclusions.append(
                _exclusion(
                    class_id,
                    image_id,
                    "container-referenced",
                    listed_container_count=image["listed_container_count"],
                )
            )
            continue
        reference_names = image["repo_tags"] + image["repo_digests"]
        if reference_names:
            exclusions.append(
                _exclusion(
                    class_id,
                    image_id,
                    "image-has-reference-name",
                    reference_names=reference_names,
                )
            )
            continue
        age_seconds = max(0, now - image["created_unix"])
        candidate_id = _candidate_id(class_id, image_id)
        if candidate_id in pins or image_id in pins:
            exclusions.append(
                _exclusion(
                    class_id,
                    image_id,
                    "pinned",
                    pin=pins.get(candidate_id) or pins.get(image_id),
                )
            )
            continue
        if age_seconds < spec["minimum_age_seconds"]:
            exclusions.append(
                _exclusion(
                    class_id, image_id, "too-recent", age_seconds=age_seconds
                )
            )
            continue
        candidates.append(
            _candidate(
                class_id,
                image_id,
                "docker_dangling_image",
                [],
                allocated_bytes=image["size_bytes"],
                metadata={
                    "image_id": image_id,
                    "created_unix": image["created_unix"],
                    "age_seconds": age_seconds,
                    "inspect_sha256": image["inspect_sha256"],
                    "display_repository": image["display_repository"],
                    "reported_virtual_size_bytes": image["size_bytes"],
                },
            )
        )
    return {
        "candidates": candidates,
        "exclusions": exclusions,
        "observation": {
            "container_referenced_image_ids": sorted(referenced)
        },
    }


def _observe_user_journal(policy: dict[str, Any], runner: CommandRunner) -> dict[str, Any]:
    class_id = "user_journal"
    spec = policy["classes"][class_id]
    command = spec["observation_command"]
    if not isinstance(command, list) or not all(isinstance(item, str) and item for item in command):
        raise PolicyError("user journal observation command is invalid")
    result = runner(command)
    return {
        "candidates": [],
        "exclusions": [
            _exclusion(
                class_id,
                "user-journal",
                "report-only-no-exact-target-set",
                policy_reason=spec["reason"],
                returncode=result.get("returncode"),
                output=str(result.get("stdout") or result.get("stderr") or "")[:1000],
            )
        ],
    }


def _plan_material(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in plan.items()
        if key not in {"plan_id", "plan_sha256", "plan_path"}
    }


def _observe_with_plan_budget(
    class_id: str,
    deadline_monotonic: float,
    operation: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    try:
        _check_scan_deadline(deadline_monotonic)
        result = operation()
        _check_scan_deadline(deadline_monotonic)
        return result
    except ScanDeadlineExceeded as exc:
        return {
            "candidates": [],
            "exclusions": [
                _exclusion(
                    class_id,
                    "plan-budget",
                    "plan-time-budget-exceeded",
                    error=str(exc),
                )
            ],
        }


def build_plan(
    policy: dict[str, Any],
    *,
    home: Path | None = None,
    now: int | None = None,
    runner: CommandRunner = _default_runner,
    write: bool = True,
) -> dict[str, Any]:
    resolved_home = (home or Path(policy["resolved_home"])).resolve(strict=True)
    generated = int(time.time()) if now is None else int(now)
    processes = _process_observation(policy)
    pins = _load_pins(policy, home=resolved_home, now=generated)
    deadline = time.monotonic() + policy["limits"]["max_plan_seconds"]
    classes = {
        "filesystem_cache": _observe_with_plan_budget(
            "filesystem_cache",
            deadline,
            lambda: _observe_filesystem_cache(
                policy,
                resolved_home,
                generated,
                processes,
                pins,
                deadline,
            ),
        ),
        "trash": _observe_with_plan_budget(
            "trash",
            deadline,
            lambda: _observe_trash(
                policy,
                resolved_home,
                generated,
                processes,
                pins,
                deadline,
            ),
        ),
        "grabowski_releases": _observe_with_plan_budget(
            "grabowski_releases",
            deadline,
            lambda: _observe_releases(
                policy,
                resolved_home,
                generated,
                processes,
                pins,
                deadline,
            ),
        ),
        "maintenance_journal": _observe_with_plan_budget(
            "maintenance_journal",
            deadline,
            lambda: _observe_maintenance_journal(
                policy, resolved_home, generated, pins, deadline
            ),
        ),
        "docker_build_cache": _observe_with_plan_budget(
            "docker_build_cache",
            deadline,
            lambda: _observe_docker_build_cache(
                policy, runner, processes, pins
            ),
        ),
        "docker_images": _observe_with_plan_budget(
            "docker_images",
            deadline,
            lambda: _observe_docker_images(
                policy, runner, generated, pins
            ),
        ),
        "user_journal": _observe_with_plan_budget(
            "user_journal",
            deadline,
            lambda: _observe_user_journal(policy, runner),
        ),
    }
    total_candidates = sum(len(value["candidates"]) for value in classes.values())
    if total_candidates > policy["limits"]["max_plan_candidates"]:
        raise PlanError("plan candidate limit exceeded")
    for value in classes.values():
        value["candidates"].sort(key=lambda item: item["candidate_id"])
        value["exclusions"].sort(key=lambda item: (item["stable_key"], item["reason"]))
    plan: dict[str, Any] = {
        "schema_version": 1,
        "kind": PLAN_KIND,
        "policy_id": policy["policy_id"],
        "policy_sha256": policy["policy_sha256"],
        "generated_at_unix": generated,
        "home": str(resolved_home),
        "process_observation": processes,
        "pins": [pins[key] for key in sorted(pins)],
        "classes": classes,
        "summary": {
            "candidate_count": total_candidates,
            "candidate_allocated_bytes": sum(
                candidate["allocated_bytes"]
                for value in classes.values()
                for candidate in value["candidates"]
            ),
            "candidate_bytes_semantics": (
                "class_specific_reported_target_bytes_not_global_free_space"
            ),
            "exclusion_count": sum(
                len(value["exclusions"]) for value in classes.values()
            ),
            "docker_volumes_considered": False,
            "automatic_cleanup_authorized": False,
        },
        "safety": policy["safety"],
    }
    digest = _sha256_json(_plan_material(plan))
    plan["plan_id"] = digest
    plan["plan_sha256"] = digest
    if write:
        state_root = Path(policy["resolved_state_root"])
        plan_path = state_root / "plans" / f"{digest}.json"
        plan["plan_path"] = str(plan_path)
        _atomic_json(plan_path, plan)
    return plan


def _verify_plan(plan: dict[str, Any], policy: dict[str, Any], expected_sha256: str) -> None:
    if plan.get("schema_version") != 1 or plan.get("kind") != PLAN_KIND:
        raise ApplyError("plan schema or kind mismatch")
    if (
        plan.get("policy_id") != policy["policy_id"]
        or plan.get("policy_sha256") != policy["policy_sha256"]
    ):
        raise ApplyError("plan policy identity mismatch")
    if plan.get("home") != policy["resolved_home"]:
        raise ApplyError("plan home identity mismatch")
    classes = plan.get("classes")
    if not isinstance(classes, dict) or set(classes) != set(policy["classes"]):
        raise ApplyError("plan classes do not match policy classes")
    for class_id, value in classes.items():
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("candidates"), list)
            or not isinstance(value.get("exclusions"), list)
        ):
            raise ApplyError(f"plan class structure is invalid: {class_id}")
    supplied = plan.get("plan_sha256")
    calculated = _sha256_json(_plan_material(plan))
    if supplied != calculated or supplied != expected_sha256 or SHA256_RE.fullmatch(expected_sha256) is None:
        raise ApplyError("plan SHA-256 mismatch")
    if plan.get("plan_id") != calculated:
        raise ApplyError("plan id mismatch")


def _receipt_material(receipt: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in receipt.items() if key != "receipt_sha256"}


def _write_receipt(path: Path, receipt: dict[str, Any]) -> dict[str, Any]:
    value = dict(receipt)
    value["receipt_sha256"] = _sha256_json(_receipt_material(value))
    _atomic_json(path, value)
    return value


def _read_receipt(path: Path) -> dict[str, Any]:
    value, _raw = _read_json_file(path)
    if value.get("schema_version") != 1 or value.get("kind") != RECEIPT_KIND:
        raise ApplyError("receipt schema or kind mismatch")
    supplied = value.get("receipt_sha256")
    if supplied != _sha256_json(_receipt_material(value)):
        raise ApplyError("receipt integrity mismatch")
    return value


def _absolute_lexical_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or not value.startswith("/"):
        raise ApplyError(f"{label} must be an absolute path")
    normalized = Path(os.path.normpath(value))
    if str(normalized) != value:
        raise ApplyError(f"{label} is not lexically normalized")
    return normalized


def _candidate_snapshot_paths(candidate: dict[str, Any]) -> list[Path]:
    paths = candidate.get("paths")
    if not isinstance(paths, list):
        raise ApplyError("candidate paths must be a list")
    result: list[Path] = []
    for snapshot in paths:
        if not isinstance(snapshot, dict):
            raise ApplyError("candidate snapshot must be an object")
        path = _absolute_lexical_path(
            snapshot.get("path"), "candidate snapshot path"
        )
        for key in (
            "identity_sha256",
            "content_identity_sha256",
            "movable_identity_sha256",
        ):
            if (
                not isinstance(snapshot.get(key), str)
                or SHA256_RE.fullmatch(snapshot[key]) is None
            ):
                raise ApplyError(f"candidate snapshot {key} is invalid")
        for key in (
            "entry_count",
            "allocated_bytes",
            "apparent_bytes",
            "max_mtime_ns",
            "device",
        ):
            value = snapshot.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ApplyError(f"candidate snapshot {key} is invalid")
        result.append(path)
    return result


def _validate_plan_candidate_authorization(
    candidate: dict[str, Any], policy: dict[str, Any]
) -> None:
    class_id = candidate.get("class_id")
    stable_key = candidate.get("stable_key")
    kind = candidate.get("kind")
    metadata = candidate.get("metadata")
    allocated = candidate.get("allocated_bytes")
    candidate_id = candidate.get("candidate_id")
    if not isinstance(class_id, str) or class_id not in policy["classes"]:
        raise ApplyError("candidate class is not registered")
    if not isinstance(stable_key, str) or not stable_key:
        raise ApplyError("candidate stable key is invalid")
    if not isinstance(metadata, dict):
        raise ApplyError("candidate metadata must be an object")
    if not isinstance(allocated, int) or isinstance(allocated, bool) or allocated < 0:
        raise ApplyError("candidate allocated bytes are invalid")
    if candidate.get("automatic_cleanup_authorized") is not False:
        raise ApplyError("candidate automatic cleanup flag must remain false")
    if candidate_id != _candidate_id(class_id, stable_key):
        raise ApplyError("candidate id does not match class and stable key")
    paths = _candidate_snapshot_paths(candidate)
    home = Path(policy["resolved_home"])

    filesystem_classes = {
        "filesystem_cache",
        "trash",
        "grabowski_releases",
        "maintenance_journal",
    }
    if class_id in filesystem_classes and allocated != sum(
        snapshot["allocated_bytes"] for snapshot in candidate["paths"]
    ):
        raise ApplyError("filesystem candidate byte total is inconsistent")

    if class_id == "filesystem_cache":
        if kind != "filesystem_entry" or len(paths) != 1:
            raise ApplyError("filesystem cache candidate shape is invalid")
        target_id = metadata.get("target_id")
        targets = {
            item["id"]: _expand_path(item["path"], home)
            for item in policy["classes"][class_id]["targets"]
        }
        root = targets.get(target_id)
        stable = _absolute_lexical_path(stable_key, "filesystem stable key")
        if root is None or stable.parent != root or paths != [stable]:
            raise ApplyError("filesystem cache candidate is outside its registered root")
        return

    if class_id == "trash":
        if kind != "trash_pair" or len(paths) != 2:
            raise ApplyError("trash candidate shape is invalid")
        name = metadata.get("name")
        if not isinstance(name, str) or not name or Path(name).name != name:
            raise ApplyError("trash candidate name is invalid")
        root = _expand_path(policy["classes"][class_id]["root"], home)
        payload = root / "files" / name
        info = root / "info" / f"{name}.trashinfo"
        stable = _absolute_lexical_path(stable_key, "trash stable key")
        if stable != payload or paths != [payload, info]:
            raise ApplyError("trash candidate is outside the registered pair")
        return

    if class_id == "grabowski_releases":
        if kind != "release_directory" or len(paths) != 1:
            raise ApplyError("release candidate shape is invalid")
        release_id = metadata.get("release_id")
        if (
            not isinstance(release_id, str)
            or not release_id
            or Path(release_id).name != release_id
        ):
            raise ApplyError("release candidate identity is invalid")
        root = _expand_path(policy["classes"][class_id]["root"], home)
        expected = root / release_id
        stable = _absolute_lexical_path(stable_key, "release stable key")
        if stable != expected or paths != [expected]:
            raise ApplyError("release candidate is outside the registered root")
        return

    if class_id == "maintenance_journal":
        if kind != "journal_file" or len(paths) != 1:
            raise ApplyError("maintenance journal candidate shape is invalid")
        stable = _absolute_lexical_path(stable_key, "journal stable key")
        roots = [
            _expand_path(value, home)
            for value in policy["classes"][class_id]["roots"]
        ]
        if stable.suffix != ".json" or stable.parent not in roots or paths != [stable]:
            raise ApplyError("maintenance journal candidate is outside registered roots")
        return

    if class_id == "docker_build_cache":
        spec = policy["classes"][class_id]
        record_ids = metadata.get("record_ids")
        if (
            kind != "docker_build_cache_set"
            or paths
            or not isinstance(record_ids, list)
            or not record_ids
            or record_ids != sorted(set(record_ids))
            or any(
                not isinstance(item, str)
                or BUILD_RECORD_ID_RE.fullmatch(item) is None
                for item in record_ids
            )
        ):
            raise ApplyError("BuildKit candidate shape is invalid")
        expected_stable = f"{spec['builder']}:{_sha256_json(record_ids)}"
        if (
            stable_key != expected_stable
            or metadata.get("builder") != spec["builder"]
            or metadata.get("filter") != _build_filter(spec)
            or metadata.get("reserved_space_bytes")
            != spec["reserved_space_bytes"]
            or metadata.get("max_used_space_bytes")
            != spec["max_used_space_bytes"]
            or not isinstance(metadata.get("records_sha256"), str)
            or SHA256_RE.fullmatch(metadata["records_sha256"]) is None
        ):
            raise ApplyError("BuildKit candidate is not policy bound")
        return

    if class_id == "docker_images":
        image_id = metadata.get("image_id")
        if (
            kind != "docker_dangling_image"
            or paths
            or not isinstance(image_id, str)
            or IMAGE_ID_RE.fullmatch(image_id) is None
            or stable_key != image_id
            or metadata.get("reported_virtual_size_bytes") != allocated
            or not isinstance(metadata.get("inspect_sha256"), str)
            or SHA256_RE.fullmatch(metadata["inspect_sha256"]) is None
        ):
            raise ApplyError("Docker image candidate shape is invalid")
        return

    raise ApplyError(f"candidate class cannot be applied: {class_id}")


def _all_candidates(
    plan: dict[str, Any], policy: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    for class_id, value in plan["classes"].items():
        for candidate in value["candidates"]:
            candidate_id = candidate["candidate_id"]
            if candidate_id in candidates:
                raise ApplyError("duplicate candidate id in plan")
            if candidate.get("class_id") != class_id:
                raise ApplyError("candidate class mismatch")
            _validate_plan_candidate_authorization(candidate, policy)
            candidates[candidate_id] = candidate
    return candidates


def _verify_snapshot_at(
    path: Path,
    expected: dict[str, Any],
    policy: dict[str, Any],
    *,
    content_only: bool = False,
) -> dict[str, Any]:
    if not path.exists() and not path.is_symlink():
        raise FileNotFoundError(str(path))
    observed = _tree_snapshot(
        path,
        max_entries=policy["limits"]["max_entries_per_candidate"],
        deadline_monotonic=(
            time.monotonic()
            + policy["limits"]["max_scan_seconds_per_candidate"]
        ),
    )
    field = "movable_identity_sha256" if content_only else "identity_sha256"
    if observed.get(field) != expected.get(field):
        raise ApplyError(f"candidate identity drift: {path}")
    return observed


def _verify_path_candidate(
    candidate: dict[str, Any], policy: dict[str, Any]
) -> None:
    expected_paths = candidate["paths"]
    if not expected_paths:
        raise ApplyError("filesystem candidate has no paths")
    for expected in expected_paths:
        _verify_snapshot_at(Path(expected["path"]), expected, policy)


def _remove_quarantine_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)
    else:
        raise ApplyError(f"unsupported quarantine entry: {path}")


def _after_quarantine_move(
    index: int, source: Path, destination: Path
) -> None:
    del index, source, destination


def _apply_filesystem_candidate(
    candidate: dict[str, Any],
    policy: dict[str, Any],
    quarantine: Path,
    processes: dict[str, Any],
) -> dict[str, Any]:
    if not processes.get("complete"):
        raise ApplyError("process observation is incomplete before filesystem mutation")
    expected_paths = candidate["paths"]
    if not expected_paths:
        raise ApplyError("filesystem candidate has no paths")
    sources = [Path(item["path"]) for item in expected_paths]
    active_references = {
        str(source): _references_for_path(processes, source)
        for source in sources
        if _references_for_path(processes, source)
    }
    if active_references:
        raise ApplyError(
            f"active process references before filesystem mutation: {active_references}"
        )
    destinations = [
        quarantine / f"{index:03d}-{source.name}"
        for index, source in enumerate(sources)
    ]
    _ensure_private_directory(quarantine)
    allowed_destinations = set(destinations)
    unexpected = [
        child
        for child in quarantine.iterdir()
        if child not in allowed_destinations
    ]
    if unexpected:
        raise ApplyError("quarantine contains unexpected entries")

    states: list[str] = []
    quarantine_device = quarantine.stat().st_dev
    for source, destination, expected in zip(
        sources, destinations, expected_paths, strict=True
    ):
        source_exists = source.exists() or source.is_symlink()
        destination_exists = destination.exists() or destination.is_symlink()
        if source_exists and destination_exists:
            raise ApplyError("candidate exists at source and quarantine destination")
        if source_exists:
            observed = _verify_snapshot_at(source, expected, policy)
            if observed["device"] != quarantine_device:
                raise ApplyError(
                    "candidate and quarantine are on different filesystems"
                )
            states.append("source")
            continue
        if destination_exists:
            observed = _verify_snapshot_at(
                destination, expected, policy, content_only=True
            )
            if observed["device"] != quarantine_device:
                raise ApplyError(
                    "quarantine candidate moved across filesystems"
                )
            states.append("quarantine")
            continue
        states.append("absent")

    if all(state == "absent" for state in states):
        quarantine.rmdir()
        _fsync_directory(quarantine.parent)
        return {
            "status": "reconciled-absent",
            "freed_bytes": candidate["allocated_bytes"],
            "size_semantics": "allocated_filesystem_blocks_removed",
        }
    if "absent" in states:
        raise ApplyError("filesystem candidate is partially absent")

    moved_now: list[tuple[Path, Path]] = []
    try:
        for index, (source, destination, state) in enumerate(
            zip(sources, destinations, states, strict=True)
        ):
            if state == "quarantine":
                continue
            os.replace(source, destination)
            _fsync_directory(source.parent)
            _fsync_directory(quarantine)
            moved_now.append((source, destination))
            _after_quarantine_move(index, source, destination)
    except Exception:
        for source, destination in reversed(moved_now):
            if (destination.exists() or destination.is_symlink()) and not (
                source.exists() or source.is_symlink()
            ):
                os.replace(destination, source)
                _fsync_directory(source.parent)
        _fsync_directory(quarantine)
        raise

    for destination in destinations:
        _remove_quarantine_path(destination)
    quarantine.rmdir()
    _fsync_directory(quarantine.parent)
    return {
        "status": "removed",
        "freed_bytes": candidate["allocated_bytes"],
        "recovered_quarantine_paths": sum(
            state == "quarantine" for state in states
        ),
        "size_semantics": "allocated_filesystem_blocks_removed",
    }


def _current_build_candidate(
    policy: dict[str, Any], runner: CommandRunner
) -> tuple[list[str], int]:
    spec = policy["classes"]["docker_build_cache"]
    records = _build_cache_records(
        runner,
        spec,
        max_records=policy["limits"]["max_docker_records"],
    )
    reclaimable = [record for record in records if record["reclaimable"] and not record["mutable"]]
    return [record["id"] for record in reclaimable], sum(record["size_bytes"] for record in reclaimable)


def _apply_build_cache_candidate(
    candidate: dict[str, Any], policy: dict[str, Any], runner: CommandRunner
) -> dict[str, Any]:
    processes = _process_observation(policy)
    if not processes.get("complete"):
        raise ApplyError(
            "process observation is incomplete before BuildKit prune"
        )
    if processes["active_docker_build_pids"]:
        raise ApplyError("active Docker build detected before prune")
    expected_ids = candidate["metadata"]["record_ids"]
    current_ids, before_bytes = _current_build_candidate(policy, runner)
    if current_ids != expected_ids:
        raise ApplyError("Docker build cache candidate set drift")
    spec = policy["classes"]["docker_build_cache"]
    result = _run_checked(
        runner,
        [
            "docker",
            "buildx",
            "prune",
            "--builder",
            spec["builder"],
            "--force",
            "--filter",
            _build_filter(spec),
            "--reserved-space",
            str(spec["reserved_space_bytes"]),
            "--max-used-space",
            str(spec["max_used_space_bytes"]),
        ],
    )
    after_ids, after_bytes = _current_build_candidate(policy, runner)
    if not set(after_ids).issubset(set(expected_ids)):
        raise ApplyError("Docker build cache introduced unexpected candidate ids")
    return {
        "status": "pruned",
        "freed_bytes": max(0, before_bytes - after_bytes),
        "before_record_ids": current_ids,
        "after_record_ids": after_ids,
        "command_returncode": result["returncode"],
        "size_semantics": "buildkit_reported_reclaimable_bytes_delta",
    }


def _image_present(runner: CommandRunner, image_id: str) -> bool:
    result = runner(["docker", "image", "inspect", image_id])
    return int(result.get("returncode", 1)) == 0


def _apply_docker_image_candidate(
    candidate: dict[str, Any],
    policy: dict[str, Any],
    runner: CommandRunner,
    now: int,
) -> dict[str, Any]:
    image_id = candidate["metadata"]["image_id"]
    if not _image_present(runner, image_id):
        return {
            "status": "reconciled-absent",
            "freed_bytes": candidate["allocated_bytes"],
            "size_semantics": (
                "reported_virtual_image_bytes_removed_not_physical_reclaim"
            ),
        }
    referenced = _docker_container_image_ids(
        runner,
        max_records=policy["limits"]["max_docker_records"],
    )
    if image_id in referenced:
        raise ApplyError("Docker image became container referenced")
    current = {
        image["image_id"]: image
        for image in _dangling_images(
            runner,
            max_records=policy["limits"]["max_docker_records"],
        )
    }
    image = current.get(image_id)
    if image is None:
        raise ApplyError("Docker image is no longer dangling")
    if image["listed_container_count"] > 0:
        raise ApplyError("Docker image reports container references")
    if image["repo_tags"] or image["repo_digests"]:
        raise ApplyError("Docker image acquired a tag or digest reference")
    if image["inspect_sha256"] != candidate["metadata"].get(
        "inspect_sha256"
    ):
        raise ApplyError("Docker image inspect identity drift")
    age = max(0, now - image["created_unix"])
    if age < policy["classes"]["docker_images"]["minimum_age_seconds"]:
        raise ApplyError("Docker image no longer meets age policy")
    _run_checked(runner, ["docker", "image", "rm", image_id])
    if _image_present(runner, image_id):
        raise ApplyError("Docker image remains after removal")
    return {
        "status": "removed",
        "freed_bytes": candidate["allocated_bytes"],
        "reported_virtual_size_bytes": image["size_bytes"],
        "size_semantics": (
            "reported_virtual_image_bytes_removed_not_physical_reclaim"
        ),
    }


def _require_candidate_still_policy_eligible(
    candidate: dict[str, Any],
    policy: dict[str, Any],
    home: Path,
    now: int,
) -> None:
    class_id = candidate["class_id"]
    metadata = candidate["metadata"]
    max_entries = policy["limits"]["max_entries_per_candidate"]
    deadline = (
        time.monotonic()
        + policy["limits"]["max_scan_seconds_per_candidate"]
    )

    if class_id == "filesystem_cache":
        target_id = metadata["target_id"]
        target = next(
            item
            for item in policy["classes"][class_id]["targets"]
            if item["id"] == target_id
        )
        snapshot = _tree_snapshot(
            Path(candidate["stable_key"]),
            max_entries=max_entries,
            deadline_monotonic=deadline,
        )
        age = max(0, now - snapshot["max_mtime_ns"] // 1_000_000_000)
        if age < target["minimum_unused_seconds"]:
            raise ApplyError("filesystem cache candidate no longer meets age policy")
        return

    if class_id == "trash":
        info_path = Path(candidate["paths"][1]["path"])
        deleted_at = _trash_deletion_unix(info_path)
        age = max(0, now - deleted_at)
        if age < policy["classes"][class_id]["minimum_age_seconds"]:
            raise ApplyError("trash candidate no longer meets age policy")
        return

    if class_id == "grabowski_releases":
        snapshot = _tree_snapshot(
            Path(candidate["stable_key"]),
            max_entries=max_entries,
            deadline_monotonic=deadline,
        )
        age = max(0, now - snapshot["max_mtime_ns"] // 1_000_000_000)
        if age < policy["classes"][class_id]["minimum_age_seconds"]:
            raise ApplyError("release candidate no longer meets age policy")
        return

    if class_id == "maintenance_journal":
        path = Path(candidate["stable_key"])
        spec = policy["classes"][class_id]
        files = [
            item
            for item in path.parent.glob("*.json")
            if item.is_file() and not item.is_symlink()
        ]
        files.sort(
            key=lambda item: (item.stat().st_mtime_ns, item.name),
            reverse=True,
        )
        try:
            rank = files.index(path)
        except ValueError as exc:
            raise ApplyError("maintenance journal candidate disappeared") from exc
        if rank < spec["keep_newest_per_root"]:
            raise ApplyError("maintenance journal candidate became retained newest")
        snapshot = _tree_snapshot(
            path,
            max_entries=1,
            deadline_monotonic=deadline,
        )
        age = max(0, now - snapshot["max_mtime_ns"] // 1_000_000_000)
        if age < spec["minimum_age_seconds"]:
            raise ApplyError("maintenance journal candidate no longer meets age policy")
        return


def _protected_release_ids(
    policy: dict[str, Any], home: Path
) -> set[str]:
    spec = policy["classes"]["grabowski_releases"]
    root = _expand_path(spec["root"], home)
    manifest = _expand_path(spec["deployment_manifest"], home)
    if not root.is_dir() or root.is_symlink():
        raise ApplyError("Grabowski release root is unavailable before apply")
    releases = [
        path
        for path in root.iterdir()
        if path.is_dir() and not path.is_symlink()
    ]
    releases.sort(
        key=lambda path: (path.stat().st_mtime_ns, path.name),
        reverse=True,
    )
    active = _active_release_id(manifest)
    release_names = {path.name for path in releases}
    if active is None or active not in release_names:
        raise ApplyError("active Grabowski release identity is unavailable")
    ordered_fallbacks = [
        path.name for path in releases if path.name != active
    ][: spec["keep_newest_fallbacks"]]
    return {active, *ordered_fallbacks}


def _require_release_candidate_unprotected(
    candidate: dict[str, Any], policy: dict[str, Any], home: Path
) -> None:
    if candidate.get("class_id") != "grabowski_releases":
        return
    metadata = candidate.get("metadata")
    release_id = metadata.get("release_id") if isinstance(metadata, dict) else None
    if not isinstance(release_id, str) or not release_id:
        raise ApplyError("release candidate identity is missing")
    if release_id in _protected_release_ids(policy, home):
        raise ApplyError("release candidate became active or protected fallback")


def _candidate_pin_keys(candidate: dict[str, Any]) -> set[str]:
    metadata = candidate.get("metadata")
    values = {
        candidate.get("candidate_id"),
        candidate.get("stable_key"),
    }
    if isinstance(metadata, dict):
        values.update(
            metadata.get(key)
            for key in ("release_id", "image_id", "builder")
        )
    return {value for value in values if isinstance(value, str) and value}


def _require_candidates_unpinned(
    candidates: list[dict[str, Any]],
    policy: dict[str, Any],
    *,
    home: Path,
    now: int,
) -> None:
    pins = _load_pins(policy, home=home, now=now)
    pin_targets = set(pins)
    pinned = {
        candidate["candidate_id"]: sorted(
            _candidate_pin_keys(candidate) & pin_targets
        )
        for candidate in candidates
        if _candidate_pin_keys(candidate) & pin_targets
    }
    if pinned:
        raise ApplyError(f"selected candidates are pinned: {pinned}")


def apply_plan(
    policy: dict[str, Any],
    plan: dict[str, Any],
    *,
    expected_plan_sha256: str,
    confirmation: str,
    selected_candidate_ids: list[str],
    runner: CommandRunner = _default_runner,
    now: int | None = None,
) -> dict[str, Any]:
    lock_path = Path(policy["resolved_state_root"]) / "apply.lock"
    with _exclusive_state_lock(lock_path):
        return _apply_plan_locked(
            policy,
            plan,
            expected_plan_sha256=expected_plan_sha256,
            confirmation=confirmation,
            selected_candidate_ids=selected_candidate_ids,
            runner=runner,
            now=now,
        )


def _apply_plan_locked(
    policy: dict[str, Any],
    plan: dict[str, Any],
    *,
    expected_plan_sha256: str,
    confirmation: str,
    selected_candidate_ids: list[str],
    runner: CommandRunner = _default_runner,
    now: int | None = None,
) -> dict[str, Any]:
    _verify_plan(plan, policy, expected_plan_sha256)
    if confirmation != f"APPLY:{plan['plan_id']}":
        raise ApplyError("confirmation mismatch")
    if not selected_candidate_ids or len(selected_candidate_ids) != len(set(selected_candidate_ids)):
        raise ApplyError("selected candidate ids must be a unique non-empty list")
    candidates = _all_candidates(plan, policy)
    unknown = sorted(set(selected_candidate_ids) - set(candidates))
    if unknown:
        raise ApplyError(f"unknown candidate ids: {unknown}")
    for candidate_id in selected_candidate_ids:
        class_id = candidates[candidate_id]["class_id"]
        if policy["classes"][class_id]["apply_authorized"] is not True:
            raise ApplyError(f"class is report-only: {class_id}")
    generated = int(time.time()) if now is None else int(now)
    home = Path(plan["home"])
    selected = [
        candidates[candidate_id]
        for candidate_id in sorted(selected_candidate_ids)
    ]
    _require_candidates_unpinned(
        selected, policy, home=home, now=generated
    )
    request_material = {
        "plan_sha256": expected_plan_sha256,
        "selected_candidate_ids": [candidate["candidate_id"] for candidate in selected],
    }
    apply_id = _sha256_json(request_material)
    state_root = Path(policy["resolved_state_root"])
    receipt_path = state_root / "receipts" / f"{apply_id}.json"
    if receipt_path.exists():
        receipt = _read_receipt(receipt_path)
        if receipt.get("apply_id") != apply_id or receipt.get("request") != request_material:
            raise ApplyError("existing receipt request mismatch")
        if receipt.get("state") == "complete":
            return {**receipt, "replayed": True}
    else:
        receipt = {
            "schema_version": 1,
            "kind": RECEIPT_KIND,
            "state": "intent",
            "apply_id": apply_id,
            "plan_id": plan["plan_id"],
            "plan_sha256": expected_plan_sha256,
            "policy_sha256": policy["policy_sha256"],
            "request": request_material,
            "started_at_unix": generated,
            "updated_at_unix": generated,
            "current_candidate": None,
            "results": [],
            "before_allocated_bytes": sum(candidate["allocated_bytes"] for candidate in selected),
            "freed_bytes": 0,
            "freed_bytes_semantics": (
                "sum_of_class_specific_target_reported_bytes"
            ),
            "filesystem_free_space_delta_observed": False,
            "after_allocated_bytes": None,
            "error": None,
            "docker_volumes_touched": False,
            "automatic_cleanup_authorized": False,
        }
        receipt = _write_receipt(receipt_path, receipt)
    completed = {item["candidate_id"] for item in receipt.get("results", [])}
    quarantine_root = state_root / "quarantine" / apply_id
    _ensure_private_directory(quarantine_root)
    try:
        for candidate in selected:
            candidate_id = candidate["candidate_id"]
            if candidate_id in completed:
                continue
            candidate_quarantine = quarantine_root / hashlib.sha256(candidate_id.encode()).hexdigest()[:20]
            receipt["state"] = "applying"
            receipt["current_candidate"] = {
                "candidate_id": candidate_id,
                "class_id": candidate["class_id"],
                "quarantine_path": str(candidate_quarantine)
                if candidate["kind"] in {"filesystem_entry", "trash_pair", "release_directory", "journal_file"}
                else None,
            }
            receipt["updated_at_unix"] = int(time.time())
            receipt = _write_receipt(receipt_path, receipt)
            _require_candidates_unpinned(
                [candidate],
                policy,
                home=home,
                now=int(time.time()),
            )
            current_time = int(time.time())
            _require_candidate_still_policy_eligible(
                candidate, policy, home, current_time
            )
            _require_release_candidate_unprotected(
                candidate, policy, home
            )
            if candidate["kind"] in {
                "filesystem_entry",
                "trash_pair",
                "release_directory",
                "journal_file",
            }:
                result = _apply_filesystem_candidate(
                    candidate,
                    policy,
                    candidate_quarantine,
                    _process_observation(policy),
                )
            elif candidate["kind"] == "docker_build_cache_set":
                result = _apply_build_cache_candidate(candidate, policy, runner)
            elif candidate["kind"] == "docker_dangling_image":
                result = _apply_docker_image_candidate(candidate, policy, runner, generated)
            else:
                raise ApplyError(f"unsupported candidate kind: {candidate['kind']}")
            receipt["results"].append(
                {
                    "candidate_id": candidate_id,
                    "class_id": candidate["class_id"],
                    "kind": candidate["kind"],
                    "before_allocated_bytes": candidate["allocated_bytes"],
                    **result,
                }
            )
            receipt["freed_bytes"] = sum(item.get("freed_bytes", 0) for item in receipt["results"])
            receipt["current_candidate"] = None
            receipt["updated_at_unix"] = int(time.time())
            receipt = _write_receipt(receipt_path, receipt)
        receipt["state"] = "complete"
        receipt["completed_at_unix"] = int(time.time())
        receipt["updated_at_unix"] = receipt["completed_at_unix"]
        receipt["after_allocated_bytes"] = max(0, receipt["before_allocated_bytes"] - receipt["freed_bytes"])
        receipt["current_candidate"] = None
        receipt["error"] = None
        receipt = _write_receipt(receipt_path, receipt)
        try:
            quarantine_root.rmdir()
        except OSError:
            pass
        return {**receipt, "replayed": False}
    except Exception as exc:
        receipt["state"] = "blocked"
        receipt["updated_at_unix"] = int(time.time())
        receipt["error"] = {"class": type(exc).__name__, "message": str(exc)[:1000]}
        receipt = _write_receipt(receipt_path, receipt)
        return {**receipt, "replayed": False}


def update_pin(
    policy: dict[str, Any],
    *,
    target: str,
    reason: str,
    ttl_hours: int,
    home: Path | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    lock_path = Path(policy["resolved_state_root"]) / "apply.lock"
    with _exclusive_state_lock(lock_path):
        return _update_pin_locked(
            policy,
            target=target,
            reason=reason,
            ttl_hours=ttl_hours,
            home=home,
            now=now,
        )


def _update_pin_locked(
    policy: dict[str, Any],
    *,
    target: str,
    reason: str,
    ttl_hours: int,
    home: Path | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    if not isinstance(target, str) or not target.strip() or target != target.strip():
        raise ValueError("pin target must be a non-empty trimmed string")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("pin reason must be non-empty")
    maximum = policy["pins"]["max_ttl_hours"]
    if not isinstance(ttl_hours, int) or isinstance(ttl_hours, bool) or not 1 <= ttl_hours <= maximum:
        raise ValueError(f"pin ttl must be between 1 and {maximum} hours")
    generated = int(time.time()) if now is None else int(now)
    resolved_home = (home or Path(policy["resolved_home"])).resolve(strict=True)
    path = _expand_path(policy["pins"]["path"], resolved_home)
    existing: list[dict[str, Any]] = []
    if path.exists():
        value, _raw = _read_json_file(path)
        if value.get("schema_version") != 1 or value.get("kind") != PIN_KIND:
            raise ValueError("pin registry contract mismatch")
        raw_pins = value.get("pins")
        if not isinstance(raw_pins, list):
            raise ValueError("pin registry pins must be a list")
        existing = [item for item in raw_pins if isinstance(item, dict) and item.get("expires_at_unix", 0) > generated]
    filtered = [item for item in existing if item.get("target") != target]
    filtered.append(
        {
            "target": target,
            "reason": reason.strip(),
            "created_at_unix": generated,
            "expires_at_unix": generated + ttl_hours * 3600,
        }
    )
    filtered.sort(key=lambda item: item["target"])
    value = {"schema_version": 1, "kind": PIN_KIND, "pins": filtered}
    _atomic_json(path, value)
    return {"path": str(path), "target": target, "expires_at_unix": generated + ttl_hours * 3600}


def _load_plan(path: Path) -> dict[str, Any]:
    value, _raw = _read_json_file(path, max_bytes=32 * 1024 * 1024)
    return value


def _print_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Plan and explicitly apply bounded cache maintenance.")
    parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--no-write", action="store_true")
    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--plan", type=Path, required=True)
    apply_parser.add_argument("--expected-plan-sha256", required=True)
    apply_parser.add_argument("--confirmation", required=True)
    apply_parser.add_argument("--candidate", action="append", required=True)
    pin_parser = subparsers.add_parser("pin")
    pin_parser.add_argument("--target", required=True)
    pin_parser.add_argument("--reason", required=True)
    pin_parser.add_argument("--ttl-hours", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        policy = load_policy(args.policy)
        if args.operation == "plan":
            _print_json(build_plan(policy, write=not args.no_write))
            return 0
        if args.operation == "apply":
            plan = _load_plan(args.plan)
            result = apply_plan(
                policy,
                plan,
                expected_plan_sha256=args.expected_plan_sha256,
                confirmation=args.confirmation,
                selected_candidate_ids=args.candidate,
            )
            _print_json(result)
            return 0 if result["state"] == "complete" else 4
        if args.operation == "pin":
            _print_json(
                update_pin(
                    policy,
                    target=args.target,
                    reason=args.reason,
                    ttl_hours=args.ttl_hours,
                )
            )
            return 0
    except (PolicyError, PlanError, ApplyError, ValueError, OSError, json.JSONDecodeError) as exc:
        _print_json({"status": "blocked", "error_class": type(exc).__name__, "error": str(exc)})
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
