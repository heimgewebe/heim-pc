#!/usr/bin/env python3
"""Plan or transactionally install persistent Heim-PC host-health files."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import stat
import subprocess
import sys
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TARGET_ROOT = Path("/")
LOCK_RELATIVE = "var/lib/heim-pc/host-health/install.lock"
BACKUP_ROOT_RELATIVE = "var/lib/heim-pc/host-health/install-backups"
RECEIPT_RELATIVE = "var/lib/heim-pc/host-health/install-receipt.v2.json"
STRICT_PROFILE = "/usr/local/libexec/heim-pc/ensure-performance-profile"

FILES = (
    ("config/host-health-remediation.v1.json", "etc/heim-pc/host-health-remediation.v1.json", 0o644),
    ("scripts/ensure_performance_profile.py", "usr/local/libexec/heim-pc/ensure-performance-profile", 0o755),
    ("scripts/host_health_diagnostics.py", "usr/local/sbin/heim-pc-host-health", 0o755),
    ("systemd/system/cpu-governor.service", "etc/systemd/system/cpu-governor.service", 0o644),
    (
        "systemd/system/cpu-governor.service.d/zz-heim-pc-strict-profile.conf",
        "etc/systemd/system/cpu-governor.service.d/zz-heim-pc-strict-profile.conf",
        0o644,
    ),
    (
        "systemd/system/heim-pc-mce-edac-monitor.service",
        "etc/systemd/system/heim-pc-mce-edac-monitor.service",
        0o644,
    ),
    (
        "systemd/system/heim-pc-mce-edac-monitor.timer",
        "etc/systemd/system/heim-pc-mce-edac-monitor.timer",
        0o644,
    ),
    (
        "systemd/journald.conf.d/zz-heim-pc-retention.conf",
        "etc/systemd/journald.conf.d/zz-heim-pc-retention.conf",
        0o644,
    ),
    (
        "systemd/user/fluidsynth.service.d/zz-heim-pc-gdm-guard.conf",
        "etc/systemd/user/fluidsynth.service.d/zz-heim-pc-gdm-guard.conf",
        0o644,
    ),
)

REMOVALS = (
    "etc/systemd/journald.conf.d/50-heim-pc-retention.conf",
    "etc/systemd/journald.conf.d/99-heim-pc-retention.conf",
    "etc/systemd/system/cpu-governor.service.d/10-verified-profile.conf",
    "usr/local/sbin/heim-pc-set-performance-profile",
    "etc/systemd/user/fluidsynth.service.d/10-interactive-user.conf",
    "etc/systemd/user/fluidsynth.service.d/50-heim-pc-gdm-guard.conf",
)

SYSTEM_UNIT_DIRS = (
    "etc/systemd/system",
    "run/systemd/system",
    "usr/local/lib/systemd/system",
    "usr/lib/systemd/system",
    "lib/systemd/system",
)
USER_UNIT_DIRS = (
    "etc/systemd/user",
    "run/systemd/user",
    "usr/local/lib/systemd/user",
    "usr/lib/systemd/user",
    "lib/systemd/user",
)

# Tests may replace this hook. Production leaves it as None.
TRANSACTION_FAULT_HOOK: Callable[[int, str], None] | None = None


class InstallError(RuntimeError):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def re_full_commit(value: str) -> bool:
    return len(value) == 40 and all(character in "0123456789abcdef" for character in value)


def _git(
    root: Path,
    argv: list[str],
    *,
    text: bool,
) -> subprocess.CompletedProcess[Any]:
    environment = os.environ.copy()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    return subprocess.run(
        ["git", *argv],
        cwd=root,
        text=text,
        capture_output=True,
        check=False,
        env=environment,
    )


def repository_identity(root: Path) -> tuple[str, bool]:
    head = _git(root, ["rev-parse", "--verify", "HEAD^{commit}"], text=True)
    status_result = _git(
        root,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        text=True,
    )
    if head.returncode != 0 or status_result.returncode != 0:
        raise InstallError("cannot determine repository identity")
    commit = head.stdout.strip()
    if not re_full_commit(commit):
        raise InstallError("repository HEAD is invalid")
    return commit, bool(status_result.stdout.strip())


def _committed_sources(root: Path, commit: str) -> dict[str, bytes]:
    verified = _git(root, ["rev-parse", "--verify", f"{commit}^{{commit}}"], text=True)
    if verified.returncode != 0 or verified.stdout.strip() != commit:
        raise InstallError("expected Git commit object is unavailable")
    result: dict[str, bytes] = {}
    for source_relative, _target_relative, _mode in FILES:
        tree = _git(root, ["ls-tree", "-z", commit, "--", source_relative], text=False)
        if tree.returncode != 0 or not tree.stdout:
            raise InstallError(f"committed source is missing: {source_relative}")
        metadata, separator, tree_path = tree.stdout.partition(b"\t")
        fields = metadata.split()
        if (
            separator != b"\t"
            or tree_path.rstrip(b"\0").decode("utf-8", "strict") != source_relative
            or len(fields) != 3
            or fields[1] != b"blob"
            or fields[0] not in {b"100644", b"100755"}
        ):
            raise InstallError(f"committed source is not a regular blob: {source_relative}")
        blob = _git(root, ["cat-file", "blob", f"{commit}:{source_relative}"], text=False)
        if blob.returncode != 0:
            raise InstallError(f"cannot read committed source blob: {source_relative}")
        result[source_relative] = blob.stdout
    _validate_committed_contract(result)
    return result


def _validate_committed_contract(source_data: dict[str, bytes]) -> None:
    try:
        config = json.loads(
            source_data["config/host-health-remediation.v1.json"].decode("utf-8")
        )
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallError("committed deployment contract is invalid") from exc
    deployment = config.get("deployment")
    mce = config.get("mce_edac")
    expected_deployment = {
        "source_binding": "expected_git_commit_tree",
        "exclusive_lock": f"/{LOCK_RELATIVE}",
        "receipt": f"/{RECEIPT_RELATIVE}",
        "target_regular_file_owner": "root:root",
        "target_operations": "descriptor_relative_nofollow",
        "transaction": "preflight_stage_fsync_commit_verify_or_rollback",
        "activation_performed": False,
    }
    if not isinstance(deployment, dict) or any(
        deployment.get(key) != value
        for key, value in expected_deployment.items()
    ):
        raise InstallError("committed deployment contract differs from installer constants")
    if set(deployment.get("legacy_removals", [])) != {
        f"/{relative}" for relative in REMOVALS
    }:
        raise InstallError("committed legacy removal contract differs from installer targets")
    if (
        not isinstance(mce, dict)
        or mce.get("state_schema_version") != 2
        or mce.get("deduplication")
        != "bounded_constituent_overlap_and_boundary_span"
        or mce.get("constituent_evidence_limit")
        != mce.get("max_journal_entries")
    ):
        raise InstallError("committed MCE evidence contract is inconsistent")


def _relative_parts(relative: str) -> tuple[str, ...]:
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or ".." in path.parts or "." in path.parts:
        raise InstallError(f"unsafe target relative path: {relative}")
    return path.parts


def _nofollow_flags(flags: int) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise InstallError("platform lacks O_NOFOLLOW")
    return flags | nofollow | getattr(os, "O_CLOEXEC", 0)


def _open_root(target_root: Path) -> int:
    absolute = Path(os.path.abspath(os.fspath(target_root)))
    try:
        descriptor = os.open(
            absolute,
            _nofollow_flags(os.O_RDONLY | os.O_DIRECTORY),
        )
    except OSError as exc:
        raise InstallError(f"cannot safely open target root {absolute}: {exc}") from exc
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise InstallError(f"target root is not a directory: {absolute}")
    return descriptor


def _open_directory(
    root_fd: int,
    relative_parts: tuple[str, ...],
    *,
    create: bool,
    created: list[str] | None = None,
    final_mode: int = 0o755,
) -> int | None:
    descriptor = os.dup(root_fd)
    walked: list[str] = []
    try:
        for index, part in enumerate(relative_parts):
            walked.append(part)
            try:
                child = os.open(
                    part,
                    _nofollow_flags(os.O_RDONLY | os.O_DIRECTORY),
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                if not create:
                    os.close(descriptor)
                    return None
                mode = final_mode if index == len(relative_parts) - 1 else 0o755
                try:
                    os.mkdir(part, mode, dir_fd=descriptor)
                except FileExistsError:
                    pass
                else:
                    os.fsync(descriptor)
                    if created is not None:
                        created.append("/".join(walked))
                child = os.open(
                    part,
                    _nofollow_flags(os.O_RDONLY | os.O_DIRECTORY),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise InstallError(
                    f"unsafe or unreadable target directory: {'/'.join(walked)}: {exc}"
                ) from exc
            if not stat.S_ISDIR(os.fstat(child).st_mode):
                os.close(child)
                raise InstallError(f"target parent is not a directory: {'/'.join(walked)}")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _open_parent(
    root_fd: int,
    relative: str,
    *,
    create: bool,
    created: list[str] | None = None,
    parent_mode: int = 0o755,
) -> tuple[int | None, str]:
    parts = _relative_parts(relative)
    parent = _open_directory(
        root_fd,
        parts[:-1],
        create=create,
        created=created,
        final_mode=parent_mode,
    )
    return parent, parts[-1]


def _read_descriptor(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _snapshot_at(parent_fd: int | None, name: str) -> dict[str, Any]:
    if parent_fd is None:
        return {"exists": False}
    try:
        descriptor = os.open(name, _nofollow_flags(os.O_RDONLY), dir_fd=parent_fd)
    except FileNotFoundError:
        return {"exists": False}
    except OSError as exc:
        raise InstallError(f"cannot safely open target {name}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise InstallError(f"target must be a regular file: {name}")
        data = _read_descriptor(descriptor)
        return {
            "exists": True,
            "data": data,
            "sha256": _sha256(data),
            "mode": stat.S_IMODE(metadata.st_mode),
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
        }
    finally:
        os.close(descriptor)


def _snapshot(root_fd: int, relative: str) -> dict[str, Any]:
    parent_fd, name = _open_parent(root_fd, relative, create=False)
    try:
        return _snapshot_at(parent_fd, name)
    finally:
        if parent_fd is not None:
            os.close(parent_fd)


def _same_snapshot(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if left.get("exists") != right.get("exists"):
        return False
    if not left.get("exists"):
        return True
    return all(
        left.get(key) == right.get(key)
        for key in ("data", "mode", "uid", "gid", "device", "inode")
    )


def _target_display(target_root: Path, relative: str) -> str:
    return str(Path(os.path.abspath(os.fspath(target_root))) / relative)


def _backup_relative(target_relative: str, before: bytes) -> str:
    safe_name = "__".join(_relative_parts(target_relative))
    return f"{BACKUP_ROOT_RELATIVE}/{safe_name}.{_sha256(before)}.bak"


def _expected_owner(target_root: Path) -> tuple[int, int]:
    if Path(os.path.abspath(os.fspath(target_root))) == DEFAULT_TARGET_ROOT:
        return 0, 0
    return os.geteuid(), os.getegid()


def _overlay_bytes(
    root_fd: int,
    relative: str,
    overlay: dict[str, bytes | None],
) -> bytes | None:
    if relative in overlay:
        return overlay[relative]
    snapshot = _snapshot(root_fd, relative)
    return snapshot["data"] if snapshot["exists"] else None


def _virtual_names(
    root_fd: int,
    directory: str,
    overlay: dict[str, bytes | None],
) -> set[str]:
    names: set[str] = set()
    directory_fd = _open_directory(
        root_fd,
        _relative_parts(directory),
        create=False,
    )
    if directory_fd is not None:
        try:
            names.update(os.listdir(directory_fd))
        finally:
            os.close(directory_fd)
    prefix = f"{directory}/"
    for relative, value in overlay.items():
        if relative.startswith(prefix) and "/" not in relative[len(prefix) :]:
            name = relative[len(prefix) :]
            if value is None:
                names.discard(name)
            else:
                names.add(name)
    return names


def _assignments(data: bytes, section_name: str, key_name: str) -> list[str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InstallError("systemd composition contains non-UTF-8 configuration") from exc
    section: str | None = None
    values: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section == section_name and "=" in line:
            key, value = line.split("=", 1)
            if key.strip() == key_name:
                values.append(value.strip())
    return values


def _effective_list_directive(
    root_fd: int,
    *,
    unit_dirs: tuple[str, ...],
    unit_name: str,
    section: str,
    key: str,
    overlay: dict[str, bytes | None],
) -> tuple[list[str], list[str]]:
    values: list[str] = []
    sources: list[str] = []
    for directory in unit_dirs:
        relative = f"{directory}/{unit_name}"
        data = _overlay_bytes(root_fd, relative, overlay)
        if data is not None:
            for value in _assignments(data, section, key):
                values = [] if value == "" else [*values, value]
            sources.append(relative)
            break

    stem, separator, suffix = unit_name.rpartition(".")
    drop_in_names = [f"{unit_name}.d"]
    if separator and "-" in stem:
        components = stem.split("-")
        for count in range(len(components) - 1, 0, -1):
            drop_in_names.append(
                f"{'-'.join(components[:count])}-.{suffix}.d"
            )
    if separator:
        drop_in_names.append(f"{suffix}.d")

    selected_drop_ins: dict[str, str] = {}
    for directory in unit_dirs:
        for drop_in_name in drop_in_names:
            drop_in_dir = f"{directory}/{drop_in_name}"
            for name in _virtual_names(root_fd, drop_in_dir, overlay):
                if name.endswith(".conf") and name not in selected_drop_ins:
                    selected_drop_ins[name] = f"{drop_in_dir}/{name}"
    for name in sorted(selected_drop_ins):
        relative = selected_drop_ins[name]
        data = _overlay_bytes(root_fd, relative, overlay)
        if data is None:
            continue
        for value in _assignments(data, section, key):
            values = [] if value == "" else [*values, value]
        sources.append(relative)
    return values, sources


def _verify_effective_composition(
    root_fd: int,
    overlay: dict[str, bytes | None] | None = None,
) -> dict[str, Any]:
    effective_overlay = {} if overlay is None else overlay
    exec_start, cpu_sources = _effective_list_directive(
        root_fd,
        unit_dirs=SYSTEM_UNIT_DIRS,
        unit_name="cpu-governor.service",
        section="Service",
        key="ExecStart",
        overlay=effective_overlay,
    )
    condition_user, fluid_sources = _effective_list_directive(
        root_fd,
        unit_dirs=USER_UNIT_DIRS,
        unit_name="fluidsynth.service",
        section="Unit",
        key="ConditionUser",
        overlay=effective_overlay,
    )
    if exec_start != [STRICT_PROFILE]:
        raise InstallError(
            "effective cpu-governor.service ExecStart is not the strict committed wrapper"
        )
    if condition_user != ["!gdm"]:
        raise InstallError(
            "effective fluidsynth.service ConditionUser must contain only !gdm"
        )
    return {
        "cpu_governor": {
            "exec_start": exec_start,
            "sources": cpu_sources,
            "verified": True,
        },
        "fluidsynth": {
            "condition_user": condition_user,
            "sources": fluid_sources,
            "verified": True,
        },
    }


def verify_effective_composition(target_root: Path) -> dict[str, Any]:
    root_fd = _open_root(target_root)
    try:
        return _verify_effective_composition(root_fd)
    finally:
        os.close(root_fd)


def _build_plan(
    *,
    root_fd: int,
    source_data: dict[str, bytes],
    target_root: Path,
    uid: int,
    gid: int,
) -> tuple[list[dict[str, Any]], dict[str, bytes | None], dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    overlay: dict[str, bytes | None] = {}

    for target_relative in REMOVALS:
        before = _snapshot(root_fd, target_relative)
        backup_relative = (
            _backup_relative(target_relative, before["data"]) if before["exists"] else None
        )
        if backup_relative is not None:
            backup_before = _snapshot(root_fd, backup_relative)
            if backup_before["exists"] and (
                backup_before["data"] != before["data"]
                or backup_before["mode"] != 0o600
                or backup_before["uid"] != uid
                or backup_before["gid"] != gid
            ):
                raise InstallError(f"backup collision: {backup_relative}")
        entries.append(
            {
                "operation": "remove_obsolete",
                "source": None,
                "target_relative": target_relative,
                "target": _target_display(target_root, target_relative),
                "mode": None,
                "before": before,
                "action": "planned_removal" if before["exists"] else "absent",
                "sha256": before.get("sha256"),
                "backup_relative": backup_relative,
                "backup": (
                    _target_display(target_root, backup_relative)
                    if backup_relative is not None
                    else None
                ),
            }
        )
        overlay[target_relative] = None

    for source_relative, target_relative, mode in FILES:
        data = source_data[source_relative]
        before = _snapshot(root_fd, target_relative)
        changed = (
            not before["exists"]
            or before["data"] != data
            or before["mode"] != mode
            or before["uid"] != uid
            or before["gid"] != gid
        )
        backup_relative = None
        if before["exists"] and before["data"] != data:
            backup_relative = _backup_relative(target_relative, before["data"])
            backup_before = _snapshot(root_fd, backup_relative)
            if backup_before["exists"] and (
                backup_before["data"] != before["data"]
                or backup_before["mode"] != 0o600
                or backup_before["uid"] != uid
                or backup_before["gid"] != gid
            ):
                raise InstallError(f"backup collision: {backup_relative}")
        entries.append(
            {
                "operation": "install",
                "source": source_relative,
                "source_sha256": _sha256(data),
                "target_relative": target_relative,
                "target": _target_display(target_root, target_relative),
                "mode": oct(mode),
                "mode_int": mode,
                "uid": uid,
                "gid": gid,
                "data": data,
                "before": before,
                "action": "planned" if changed else "unchanged",
                "sha256": _sha256(data),
                "backup_relative": backup_relative,
                "backup": (
                    _target_display(target_root, backup_relative)
                    if backup_relative is not None
                    else None
                ),
            }
        )
        overlay[target_relative] = data

    composition = _verify_effective_composition(root_fd, overlay)
    return entries, overlay, composition


def _public_entry(item: dict[str, Any], *, applied: bool) -> dict[str, Any]:
    action = item["action"]
    before = item["before"]
    if applied:
        if action == "planned":
            action = "installed"
        elif action == "planned_removal":
            action = "removed"
    return {
        "operation": item["operation"],
        "source": item.get("source"),
        "source_sha256": item.get("source_sha256"),
        "target": item["target"],
        "mode": item.get("mode"),
        "uid": item.get("uid"),
        "gid": item.get("gid"),
        "action": action,
        "sha256": item.get("sha256"),
        "backup": item.get("backup"),
        "before": (
            {
                "sha256": before["sha256"],
                "mode": oct(before["mode"]),
                "uid": before["uid"],
                "gid": before["gid"],
            }
            if before["exists"]
            else None
        ),
    }


def _write_temp(
    parent_fd: int,
    target_name: str,
    data: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
    role: str,
) -> str:
    for _attempt in range(32):
        name = f".{target_name}.{role}.{secrets.token_hex(8)}"
        try:
            descriptor = os.open(
                name,
                _nofollow_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
                mode,
                dir_fd=parent_fd,
            )
            break
        except FileExistsError:
            continue
    else:
        raise InstallError(f"cannot allocate staged file for {target_name}")
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise InstallError(f"short staged write for {target_name}")
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_uid != uid
            or metadata.st_gid != gid
        ):
            raise InstallError(f"staged file metadata verification failed for {target_name}")
    except Exception:
        try:
            os.unlink(name, dir_fd=parent_fd)
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
    return name


def _remove_created_directories(root_fd: int, created: list[str]) -> None:
    for relative in reversed(created):
        parts = _relative_parts(relative)
        parent = _open_directory(root_fd, parts[:-1], create=False)
        if parent is None:
            continue
        try:
            try:
                os.rmdir(parts[-1], dir_fd=parent)
            except OSError as exc:
                if exc.errno not in {errno.ENOTEMPTY, errno.ENOENT}:
                    raise
            os.fsync(parent)
        finally:
            os.close(parent)


def _preimage_matches(parent_fd: int, name: str, expected: dict[str, Any]) -> bool:
    return _same_snapshot(_snapshot_at(parent_fd, name), expected)


def _stage_operation(
    root_fd: int,
    operation: dict[str, Any],
    *,
    created: list[str],
) -> dict[str, Any]:
    parent_fd, name = _open_parent(
        root_fd,
        operation["relative"],
        create=True,
        created=created,
        parent_mode=operation.get("parent_mode", 0o755),
    )
    assert parent_fd is not None
    staged_name = None
    rollback_name = None
    try:
        if not _preimage_matches(parent_fd, name, operation["before"]):
            raise InstallError(f"target preimage changed before staging: {operation['relative']}")
        if operation["kind"] == "install":
            staged_name = _write_temp(
                parent_fd,
                name,
                operation["data"],
                mode=operation["mode"],
                uid=operation["uid"],
                gid=operation["gid"],
                role="stage",
            )
        if operation["before"]["exists"]:
            rollback_name = _write_temp(
                parent_fd,
                name,
                operation["before"]["data"],
                mode=operation["before"]["mode"],
                uid=operation["before"]["uid"],
                gid=operation["before"]["gid"],
                role="rollback",
            )
        staged_snapshot = (
            _snapshot_at(parent_fd, staged_name) if staged_name is not None else None
        )
        rollback_snapshot = (
            _snapshot_at(parent_fd, rollback_name) if rollback_name is not None else None
        )
        os.fsync(parent_fd)
        return {
            **operation,
            "parent_fd": parent_fd,
            "name": name,
            "staged_name": staged_name,
            "rollback_name": rollback_name,
            "staged_snapshot": staged_snapshot,
            "rollback_snapshot": rollback_snapshot,
        }
    except Exception:
        for temporary_name in (staged_name, rollback_name):
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
        try:
            os.fsync(parent_fd)
        except OSError:
            pass
        os.close(parent_fd)
        raise


def _cleanup_staged(staged: list[dict[str, Any]]) -> None:
    for operation in staged:
        parent_fd = operation["parent_fd"]
        for key in ("staged_name", "rollback_name"):
            name = operation.get(key)
            if name is not None:
                try:
                    os.unlink(name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
        try:
            os.fsync(parent_fd)
        except OSError:
            pass
        os.close(parent_fd)


def _rollback(committed: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for operation in reversed(committed):
        parent_fd = operation["parent_fd"]
        try:
            current = _snapshot_at(parent_fd, operation["name"])
            if operation["kind"] == "install":
                expected_current = {
                    "exists": True,
                    "data": operation["data"],
                    "mode": operation["mode"],
                    "uid": operation["uid"],
                    "gid": operation["gid"],
                }
                if not all(
                    current.get(key) == expected_current.get(key)
                    for key in ("exists", "data", "mode", "uid", "gid")
                ):
                    raise InstallError("installed target changed before rollback")
            elif current["exists"]:
                raise InstallError("removed target was replaced before rollback")

            if operation["before"]["exists"]:
                rollback_name = operation["rollback_name"]
                if rollback_name is None:
                    raise InstallError("rollback image is missing")
                if not _same_snapshot(
                    _snapshot_at(parent_fd, rollback_name),
                    operation["rollback_snapshot"],
                ):
                    raise InstallError("rollback image changed before restoration")
                os.replace(
                    rollback_name,
                    operation["name"],
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                operation["rollback_name"] = None
            elif current["exists"]:
                os.unlink(operation["name"], dir_fd=parent_fd)
            os.fsync(parent_fd)
        except Exception as exc:  # rollback must attempt every committed target
            errors.append(f"{operation['relative']}: {exc}")
    return errors


def _verify_operation(root_fd: int, operation: dict[str, Any]) -> None:
    final = _snapshot(root_fd, operation["relative"])
    if operation["kind"] == "remove":
        if final["exists"]:
            raise InstallError(f"obsolete target removal readback failed: {operation['relative']}")
        return
    if (
        not final["exists"]
        or final["data"] != operation["data"]
        or final["mode"] != operation["mode"]
        or final["uid"] != operation["uid"]
        or final["gid"] != operation["gid"]
    ):
        raise InstallError(f"installed target readback failed: {operation['relative']}")


def _apply_operations(
    root_fd: int,
    operations: list[dict[str, Any]],
    *,
    created: list[str],
) -> None:
    staged: list[dict[str, Any]] = []
    committed: list[dict[str, Any]] = []
    failure: Exception | None = None
    rollback_errors: list[str] = []
    try:
        for operation in operations:
            staged.append(_stage_operation(root_fd, operation, created=created))
        for index, operation in enumerate(staged, start=1):
            parent_fd = operation["parent_fd"]
            if not _preimage_matches(parent_fd, operation["name"], operation["before"]):
                raise InstallError(
                    f"target preimage changed before commit: {operation['relative']}"
                )
            if operation["kind"] == "install":
                if not _same_snapshot(
                    _snapshot_at(parent_fd, operation["staged_name"]),
                    operation["staged_snapshot"],
                ):
                    raise InstallError(
                        f"staged target changed before commit: {operation['relative']}"
                    )
                os.replace(
                    operation["staged_name"],
                    operation["name"],
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                operation["staged_name"] = None
            else:
                os.unlink(operation["name"], dir_fd=parent_fd)
            os.fsync(parent_fd)
            committed.append(operation)
            if TRANSACTION_FAULT_HOOK is not None:
                TRANSACTION_FAULT_HOOK(index, operation["relative"])
        for operation in operations:
            _verify_operation(root_fd, operation)
        _verify_effective_composition(root_fd)
    except Exception as exc:
        failure = exc
        rollback_errors = _rollback(committed)
    _cleanup_staged(staged)
    if failure is not None:
        if not rollback_errors:
            _remove_created_directories(root_fd, created)
        detail = f"; rollback failures: {', '.join(rollback_errors)}" if rollback_errors else ""
        raise InstallError(
            f"transaction failed and was rolled back: {failure}{detail}"
        ) from failure


def _open_lock(root_fd: int, uid: int, gid: int):
    created: list[str] = []
    parent_fd, name = _open_parent(
        root_fd,
        LOCK_RELATIVE,
        create=True,
        created=created,
        parent_mode=0o700,
    )
    assert parent_fd is not None
    descriptor: int | None = None
    try:
        descriptor = os.open(
            name,
            _nofollow_flags(os.O_RDWR | os.O_CREAT),
            0o600,
            dir_fd=parent_fd,
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise InstallError("installer lock is not a regular file")
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, uid, gid)
        os.fsync(descriptor)
        os.fsync(parent_fd)
        return os.fdopen(descriptor, "r+b")
    except InstallError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise InstallError(f"cannot safely prepare installer lock: {exc}") from exc
    finally:
        os.close(parent_fd)


def _transaction_operations(
    *,
    root_fd: int,
    entries: list[dict[str, Any]],
    receipt_bytes: bytes,
    uid: int,
    gid: int,
) -> list[dict[str, Any]]:
    operations: list[dict[str, Any]] = []
    backups_added: set[str] = set()
    for item in entries:
        backup_relative = item.get("backup_relative")
        if backup_relative is not None and backup_relative not in backups_added:
            backup_before = _snapshot(root_fd, backup_relative)
            if not backup_before["exists"]:
                operations.append(
                    {
                        "kind": "install",
                        "relative": backup_relative,
                        "data": item["before"]["data"],
                        "mode": 0o600,
                        "uid": uid,
                        "gid": gid,
                        "before": backup_before,
                        "parent_mode": 0o700,
                    }
                )
            backups_added.add(backup_relative)
    for item in entries:
        if item["action"] == "planned":
            operations.append(
                {
                    "kind": "install",
                    "relative": item["target_relative"],
                    "data": item["data"],
                    "mode": item["mode_int"],
                    "uid": uid,
                    "gid": gid,
                    "before": item["before"],
                }
            )
        elif item["action"] == "planned_removal":
            operations.append(
                {
                    "kind": "remove",
                    "relative": item["target_relative"],
                    "before": item["before"],
                }
            )
    receipt_before = _snapshot(root_fd, RECEIPT_RELATIVE)
    operations.append(
        {
            "kind": "install",
            "relative": RECEIPT_RELATIVE,
            "data": receipt_bytes,
            "mode": 0o600,
            "uid": uid,
            "gid": gid,
            "before": receipt_before,
            "parent_mode": 0o700,
        }
    )
    return operations


def _base_receipt(
    *,
    apply: bool,
    head: str,
    dirty: bool,
    target_root: Path,
    entries: list[dict[str, Any]],
    composition: dict[str, Any],
    installed_at: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "kind": (
            "heim_pc_host_health_remediation_install_receipt"
            if apply
            else "heim_pc_host_health_remediation_install_plan"
        ),
        "valid": apply,
        "apply": apply,
        "repository_head": head,
        "repository_dirty": dirty,
        "source_binding": {
            "kind": "git_commit_tree",
            "commit": head,
            "mutable_worktree_source_bytes_used": False,
            "files": {
                item["source"]: item["source_sha256"]
                for item in entries
                if item.get("source") is not None
            },
        },
        "target_root": str(Path(os.path.abspath(os.fspath(target_root)))),
        "installed_at": installed_at,
        "files": [_public_entry(item, applied=apply) for item in entries],
        "effective_systemd_composition": composition,
        "transaction": {
            "exclusive_lock": (
                _target_display(target_root, LOCK_RELATIVE) if apply else None
            ),
            "preflight_complete_before_staging": True,
            "descriptor_relative_nofollow": True,
            "staged_and_fsynced": apply,
            "rollback_images_staged": apply,
            "partial_failure_rollback": apply,
            "receipt_relative": RECEIPT_RELATIVE if apply else None,
        },
        "activation_performed": False,
        "activation_required": [
            "systemctl daemon-reload",
            "systemctl restart systemd-journald",
            (
                "systemd-analyze cat-config systemd/journald.conf; verify the final "
                "SystemMaxUse=2G, SystemKeepFree=20G and MaxRetentionSec=14day"
            ),
            "systemctl enable --now heim-pc-mce-edac-monitor.timer",
            "systemctl restart cpu-governor.service",
            "restart GDM user manager or reboot before evaluating its FluidSynth condition",
        ],
        "does_not_establish": [
            "systemd_activation",
            "firmware_flash",
            "BIOS_SVM_enablement",
            "absence_of_future_path_substitution_after_the_installer_exits",
        ],
    }


def install(
    *,
    source_root: Path,
    target_root: Path,
    apply: bool,
    expected_head: str | None,
) -> dict[str, Any]:
    target_root = Path(os.path.abspath(os.fspath(target_root)))
    root_fd = _open_root(target_root)
    uid, gid = _expected_owner(target_root)
    try:
        if apply:
            if expected_head is None or not re_full_commit(expected_head):
                raise InstallError("--apply requires a full 40-character --expected-head")
            if target_root == DEFAULT_TARGET_ROOT and os.geteuid() != 0:
                raise InstallError("installing below / requires root")
            with _open_lock(root_fd, uid, gid) as lock_handle:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                head, dirty = repository_identity(source_root)
                if head != expected_head:
                    raise InstallError("repository HEAD differs from --expected-head")
                if dirty:
                    raise InstallError("repository must be clean for a commit-bound install")
                source_data = _committed_sources(source_root, expected_head)
                entries, _overlay, composition = _build_plan(
                    root_fd=root_fd,
                    source_data=source_data,
                    target_root=target_root,
                    uid=uid,
                    gid=gid,
                )
                installed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                receipt = _base_receipt(
                    apply=True,
                    head=head,
                    dirty=dirty,
                    target_root=target_root,
                    entries=entries,
                    composition=composition,
                    installed_at=installed_at,
                )
                receipt_bytes = (
                    json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
                ).encode("utf-8")
                operations = _transaction_operations(
                    root_fd=root_fd,
                    entries=entries,
                    receipt_bytes=receipt_bytes,
                    uid=uid,
                    gid=gid,
                )
                created: list[str] = []
                _apply_operations(root_fd, operations, created=created)
                return receipt

        head, dirty = repository_identity(source_root)
        if expected_head is not None and head != expected_head:
            raise InstallError("repository HEAD differs from --expected-head")
        source_data = _committed_sources(source_root, head)
        entries, _overlay, composition = _build_plan(
            root_fd=root_fd,
            source_data=source_data,
            target_root=target_root,
            uid=uid,
            gid=gid,
        )
        return _base_receipt(
            apply=False,
            head=head,
            dirty=dirty,
            target_root=target_root,
            entries=entries,
            composition=composition,
        )
    finally:
        os.close(root_fd)


def install_files(
    *,
    source_root: Path,
    target_root: Path,
    apply: bool,
    expected_head: str | None = None,
) -> list[dict[str, Any]]:
    return install(
        source_root=source_root,
        target_root=target_root,
        apply=apply,
        expected_head=expected_head,
    )["files"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-root", type=Path, default=DEFAULT_TARGET_ROOT)
    parser.add_argument("--expected-head")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        receipt = install(
            source_root=ROOT,
            target_root=args.target_root,
            apply=args.apply,
            expected_head=args.expected_head,
        )
    except InstallError as exc:
        print(
            json.dumps(
                {
                    "schema_version": 2,
                    "kind": "heim_pc_host_health_remediation_install_error",
                    "error": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
