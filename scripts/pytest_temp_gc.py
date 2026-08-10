#!/usr/bin/env python3
"""Safely remove orphaned pytest ``garbage-*`` cleanup residues.

Pytest protects numbered temp sessions with PID lock files and deliberately
waits three days before treating a lock as stale.  If a pytest process is
killed after renaming an old session to ``garbage-<uuid>`` but before its
recursive removal completes, that grace period can leave a very large tree in
/tmp.  This helper shortens only that orphaned-garbage window.  It never
selects ``pytest-N`` or ``pytest-current`` sessions.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import sys
import time
from typing import Any

SCHEMA_VERSION = 1
GARBAGE_NAME = re.compile(
    r"^garbage-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
DEFAULT_MIN_AGE_SECONDS = 600
DEFAULT_MAX_ENTRIES = 500_000


def default_root(uid: int | None = None) -> Path:
    uid = os.getuid() if uid is None else uid
    user = pwd.getpwuid(uid).pw_name
    return Path("/tmp") / f"pytest-of-{user}"


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _unescape_mount_path(value: str) -> str:
    # Linux mountinfo escaping documented in proc_pid_mountinfo(5).
    return (
        value.replace(r"\040", " ")
        .replace(r"\011", "\t")
        .replace(r"\012", "\n")
        .replace(r"\134", "\\")
    )


def mount_points(mountinfo: Path = Path("/proc/self/mountinfo")) -> list[Path]:
    points: list[Path] = []
    try:
        lines = mountinfo.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return points
    for line in lines:
        fields = line.split()
        if len(fields) < 5:
            continue
        points.append(Path(_unescape_mount_path(fields[4])))
    return points


def _target_from_proc_link(link: Path) -> Path | None:
    try:
        target = os.readlink(link)
    except OSError:
        return None
    if target.endswith(" (deleted)"):
        target = target[: -len(" (deleted)")]
    if not target.startswith("/"):
        return None
    return Path(target)


def process_references(candidate: Path, uid: int, proc_root: Path = Path("/proc")) -> list[str]:
    """Return same-UID processes whose cwd/root/open file points into candidate."""
    refs: list[str] = []
    try:
        processes = list(proc_root.iterdir())
    except OSError:
        return ["proc_unreadable"]
    for proc in processes:
        if not proc.name.isdigit():
            continue
        try:
            if proc.stat().st_uid != uid:
                continue
        except OSError:
            continue
        pid = proc.name
        for label in ("cwd", "root"):
            target = _target_from_proc_link(proc / label)
            if target is not None and (target == candidate or _is_within(target, candidate)):
                refs.append(f"pid={pid}:{label}")
        fd_dir = proc / "fd"
        try:
            fds = list(fd_dir.iterdir())
        except OSError:
            # Some same-UID services deliberately make /proc/<pid>/fd unreadable.
            # The authoritative liveness proof for a pytest garbage tree is its
            # own creator PID lock; this scan is additional defense-in-depth.
            continue
        for fd in fds:
            target = _target_from_proc_link(fd)
            if target is not None and (target == candidate or _is_within(target, candidate)):
                refs.append(f"pid={pid}:fd={fd.name}")
                if len(refs) >= 32:
                    return refs
    return refs


def _tree_safety(candidate: Path, uid: int, root_dev: int, max_entries: int) -> tuple[bool, str, int]:
    """Verify ownership/filesystem/type invariants without following symlinks."""
    stack = [candidate]
    seen = 0
    while stack:
        directory = stack.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            return False, f"scan_error:{type(exc).__name__}", seen
        for entry in entries:
            seen += 1
            if seen > max_entries:
                return False, "entry_limit_exceeded", seen
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                return False, f"stat_error:{type(exc).__name__}", seen
            if info.st_uid != uid:
                return False, "foreign_owner", seen
            if info.st_dev != root_dev:
                return False, "foreign_filesystem", seen
            mode = info.st_mode
            if stat.S_ISDIR(mode):
                stack.append(Path(entry.path))
            elif stat.S_ISREG(mode) or stat.S_ISLNK(mode):
                continue
            else:
                return False, "special_file", seen
    return True, "safe", seen


def _chmod_for_remove(path: Path, uid: int, *, directory: bool) -> None:
    info = path.lstat()
    if info.st_uid != uid or stat.S_ISLNK(info.st_mode):
        raise PermissionError(f"refusing chmod outside owner/type invariant: {path}")
    extra = stat.S_IRUSR | stat.S_IWUSR
    if directory:
        extra |= stat.S_IXUSR
    os.chmod(path, info.st_mode | extra, follow_symlinks=False)


def remove_tree(candidate: Path, uid: int) -> None:
    """rmtree with pytest-like owner-bound chmod recovery for read-only fixtures."""
    if not getattr(shutil.rmtree, "avoids_symlink_attacks", False):
        raise RuntimeError("platform shutil.rmtree is not symlink-attack resistant")

    def onerror(func: Any, path_text: str, exc_info: Any) -> None:
        exc = exc_info[1]
        if isinstance(exc, FileNotFoundError):
            return
        if not isinstance(exc, PermissionError):
            raise exc
        path = Path(path_text)
        if path != candidate and not _is_within(path, candidate):
            raise PermissionError(f"refusing chmod outside candidate: {path}")
        # A read-only parent can block unlinking an otherwise writable file.
        chain = [path]
        chain.extend(parent for parent in path.parents if parent == candidate or _is_within(parent, candidate))
        for item in reversed(chain):
            try:
                is_dir = item.is_dir() and not item.is_symlink()
                _chmod_for_remove(item, uid, directory=is_dir)
            except FileNotFoundError:
                continue
        func(path_text)

    shutil.rmtree(candidate, onerror=onerror)


def evaluate_candidate(
    candidate: Path,
    *,
    uid: int,
    root: Path,
    root_dev: int,
    now: float,
    min_age_seconds: int,
    max_entries: int,
    mounts: list[Path],
    proc_root: Path = Path("/proc"),
) -> dict[str, Any]:
    result: dict[str, Any] = {"path": str(candidate), "name": candidate.name}
    if not GARBAGE_NAME.fullmatch(candidate.name):
        return {**result, "decision": "skip", "reason": "name_mismatch"}
    try:
        info = candidate.lstat()
    except OSError as exc:
        return {**result, "decision": "skip", "reason": f"lstat_error:{type(exc).__name__}"}
    if not stat.S_ISDIR(info.st_mode) or candidate.is_symlink():
        return {**result, "decision": "skip", "reason": "not_plain_directory"}
    if info.st_uid != uid:
        return {**result, "decision": "skip", "reason": "foreign_owner"}
    if info.st_dev != root_dev:
        return {**result, "decision": "skip", "reason": "foreign_filesystem"}

    lock = candidate / ".lock"
    lock_pid: int | None = None
    timestamp = info.st_mtime
    if not lock.exists() and not lock.is_symlink():
        return {**result, "decision": "skip", "reason": "missing_lock"}
    if lock.exists() or lock.is_symlink():
        try:
            lock_info = lock.lstat()
        except OSError as exc:
            return {**result, "decision": "skip", "reason": f"lock_lstat_error:{type(exc).__name__}"}
        if not stat.S_ISREG(lock_info.st_mode) or stat.S_ISLNK(lock_info.st_mode):
            return {**result, "decision": "skip", "reason": "invalid_lock_type"}
        if lock_info.st_uid != uid:
            return {**result, "decision": "skip", "reason": "foreign_lock_owner"}
        try:
            lock_text = lock.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as exc:
            return {**result, "decision": "skip", "reason": f"lock_read_error:{type(exc).__name__}"}
        if not lock_text.isdigit() or int(lock_text) <= 0:
            return {**result, "decision": "skip", "reason": "invalid_lock_pid"}
        lock_pid = int(lock_text)
        timestamp = lock_info.st_mtime
        if (proc_root / str(lock_pid)).exists():
            return {**result, "decision": "skip", "reason": "lock_pid_alive", "lock_pid": lock_pid}

    age_seconds = max(0.0, now - timestamp)
    result.update({"age_seconds": round(age_seconds, 3), "lock_pid": lock_pid})
    if age_seconds < min_age_seconds:
        return {**result, "decision": "skip", "reason": "too_young"}

    resolved = candidate.resolve(strict=False)
    if resolved.parent != root:
        return {**result, "decision": "skip", "reason": "resolved_outside_root"}
    for mount in mounts:
        if mount == resolved or _is_within(mount, resolved):
            return {**result, "decision": "skip", "reason": "mount_present", "mount": str(mount)}

    safe, reason, entries = _tree_safety(candidate, uid, root_dev, max_entries)
    result["entries_verified"] = entries
    if not safe:
        return {**result, "decision": "skip", "reason": reason}

    refs = process_references(resolved, uid, proc_root=proc_root)
    if refs:
        return {**result, "decision": "skip", "reason": "process_reference", "references": refs}
    return {**result, "decision": "remove", "reason": "orphaned_pytest_garbage"}


def collect(
    root: Path,
    *,
    uid: int | None = None,
    now: float | None = None,
    min_age_seconds: int = DEFAULT_MIN_AGE_SECONDS,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    dry_run: bool = False,
    proc_root: Path = Path("/proc"),
    mounts: list[Path] | None = None,
) -> dict[str, Any]:
    uid = os.getuid() if uid is None else uid
    now = time.time() if now is None else now
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "heim_pc_pytest_temp_gc_report",
        "root": str(root),
        "uid": uid,
        "min_age_seconds": min_age_seconds,
        "max_entries": max_entries,
        "dry_run": dry_run,
        "candidates": [],
        "eligible": 0,
        "removed": 0,
        "skipped": 0,
        "errors": [],
        "does_not_touch": ["pytest-N", "pytest-current", "non-pytest paths"],
    }
    try:
        root_info = root.lstat()
    except FileNotFoundError:
        report["status"] = "ok"
        report["root_present"] = False
        return report
    except OSError as exc:
        report["status"] = "error"
        report["errors"].append(f"root_lstat:{type(exc).__name__}")
        return report
    report["root_present"] = True
    if not stat.S_ISDIR(root_info.st_mode) or root.is_symlink() or root_info.st_uid != uid:
        report["status"] = "error"
        report["errors"].append("unsafe_root")
        return report
    root_resolved = root.resolve(strict=True)
    if root_resolved != root:
        report["status"] = "error"
        report["errors"].append("root_resolution_changed")
        return report

    all_mounts = mount_points() if mounts is None else mounts
    for candidate in sorted(root.iterdir(), key=lambda p: p.name):
        if not candidate.name.startswith("garbage-"):
            continue
        assessment = evaluate_candidate(
            candidate,
            uid=uid,
            root=root_resolved,
            root_dev=root_info.st_dev,
            now=now,
            min_age_seconds=min_age_seconds,
            max_entries=max_entries,
            mounts=all_mounts,
            proc_root=proc_root,
        )
        if assessment["decision"] == "remove" and not dry_run:
            try:
                # Recheck the creator PID immediately before mutation.
                lock_pid = assessment.get("lock_pid")
                if isinstance(lock_pid, int) and (proc_root / str(lock_pid)).exists():
                    assessment.update(decision="skip", reason="lock_pid_revived")
                else:
                    refs = process_references(candidate, uid, proc_root=proc_root)
                    if refs:
                        assessment.update(decision="skip", reason="process_reference_recheck", references=refs)
                    else:
                        remove_tree(candidate, uid)
                        assessment["removed"] = not candidate.exists()
                        if not assessment["removed"]:
                            raise OSError("candidate still exists after removal")
            except Exception as exc:  # Fail closed and surface the residue.
                assessment.update(decision="error", reason=f"remove_error:{type(exc).__name__}")
                report["errors"].append(f"{candidate.name}:{type(exc).__name__}:{exc}")
        report["candidates"].append(assessment)
        if assessment["decision"] == "remove":
            report["eligible"] += 1
            if assessment.get("removed") is True:
                report["removed"] += 1
        elif assessment["decision"] == "skip":
            report["skipped"] += 1
    report["status"] = "error" if report["errors"] else "ok"
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--min-age-seconds", type=int, default=DEFAULT_MIN_AGE_SECONDS)
    parser.add_argument("--max-entries", type=int, default=DEFAULT_MAX_ENTRIES)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.min_age_seconds < 60:
        parser.error("--min-age-seconds must be at least 60")
    if not 1_000 <= args.max_entries <= 2_000_000:
        parser.error("--max-entries must be between 1000 and 2000000")
    root = default_root()
    report = collect(
        root,
        min_age_seconds=args.min_age_seconds,
        max_entries=args.max_entries,
        dry_run=args.dry_run,
    )
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
