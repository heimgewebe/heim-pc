#!/usr/bin/env python3
"""Plan or install the persistent Heim-PC host-health files without activating them."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TARGET_ROOT = Path("/")
JOURNALD_DROP_IN_NAME = "zz-heim-pc-retention.conf"
OBSOLETE_JOURNALD_DROP_INS = (
    "50-heim-pc-retention.conf",
    "99-heim-pc-retention.conf",
)

FILES = (
    ("config/host-health-remediation.v1.json", "etc/heim-pc/host-health-remediation.v1.json", 0o644),
    ("scripts/ensure_performance_profile.py", "usr/local/libexec/heim-pc/ensure-performance-profile", 0o755),
    ("scripts/host_health_diagnostics.py", "usr/local/sbin/heim-pc-host-health", 0o755),
    ("systemd/system/cpu-governor.service", "etc/systemd/system/cpu-governor.service", 0o644),
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
        f"systemd/journald.conf.d/{JOURNALD_DROP_IN_NAME}",
        f"etc/systemd/journald.conf.d/{JOURNALD_DROP_IN_NAME}",
        0o644,
    ),
    (
        "systemd/user/fluidsynth.service.d/50-heim-pc-gdm-guard.conf",
        "etc/systemd/user/fluidsynth.service.d/50-heim-pc-gdm-guard.conf",
        0o644,
    ),
)


class InstallError(RuntimeError):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def repository_identity(root: Path) -> tuple[str, bool]:
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if head.returncode != 0 or status.returncode != 0:
        raise InstallError("cannot determine repository identity")
    commit = head.stdout.strip()
    if not re_full_commit(commit):
        raise InstallError("repository HEAD is invalid")
    return commit, bool(status.stdout.strip())


def re_full_commit(value: str) -> bool:
    return len(value) == 40 and all(character in "0123456789abcdef" for character in value)


def _target_path(target_root: Path, relative: str) -> Path:
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise InstallError(f"unsafe target relative path: {relative}")
    return target_root / relative


def _assert_safe_path(path: Path, *, target_root: Path, allow_absent: bool) -> None:
    try:
        path.relative_to(target_root)
    except ValueError as exc:
        raise InstallError(f"target escapes target root: {path}") from exc
    current = target_root
    for part in path.relative_to(target_root).parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise InstallError(f"target parent must not be a symlink: {current}")
    if path.is_symlink():
        raise InstallError(f"target must not be a symlink: {path}")
    if not path.exists():
        if allow_absent:
            return
        raise InstallError(f"target does not exist: {path}")
    if not stat.S_ISREG(path.lstat().st_mode):
        raise InstallError(f"target must be a regular file: {path}")


def _atomic_write(
    path: Path,
    data: bytes,
    *,
    mode: int,
    target_root: Path,
    expected_current: bytes | None,
) -> None:
    _assert_safe_path(path, target_root=target_root, allow_absent=True)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    _assert_safe_path(path, target_root=target_root, allow_absent=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        current = path.read_bytes() if path.exists() else None
        if current != expected_current:
            raise InstallError(f"target preimage changed before replacement: {path}")
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        temporary.unlink(missing_ok=True)
    _assert_safe_path(path, target_root=target_root, allow_absent=False)
    if path.read_bytes() != data or stat.S_IMODE(path.stat().st_mode) != mode:
        raise InstallError(f"installed target readback failed: {path}")


def _backup_path(backup_root: Path, target_relative: str, before: bytes) -> Path:
    safe_name = target_relative.replace("/", "__")
    return backup_root / f"{safe_name}.{_sha256(before)}"


def _backup_existing(
    *,
    backup_root: Path,
    target_relative: str,
    before: bytes,
    target_root: Path,
) -> str:
    backup_target = _backup_path(backup_root, target_relative, before)
    _assert_safe_path(backup_target, target_root=target_root, allow_absent=True)
    backup_target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _assert_safe_path(backup_target, target_root=target_root, allow_absent=True)
    if backup_target.exists():
        if backup_target.read_bytes() != before:
            raise InstallError(f"backup collision: {backup_target}")
    else:
        _atomic_write(
            backup_target,
            before,
            mode=0o600,
            target_root=target_root,
            expected_current=None,
        )
    return str(backup_target)


def _remove_file(
    path: Path,
    *,
    target_root: Path,
    expected_current: bytes,
) -> None:
    _assert_safe_path(path, target_root=target_root, allow_absent=False)
    current = path.read_bytes() if path.exists() else None
    if current != expected_current:
        raise InstallError(f"target preimage changed before removal: {path}")
    path.unlink()
    directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    if path.exists() or path.is_symlink():
        raise InstallError(f"obsolete target removal readback failed: {path}")


def install_files(
    *,
    source_root: Path,
    target_root: Path,
    apply: bool,
) -> list[dict[str, Any]]:
    target_root = Path(os.path.abspath(os.fspath(target_root)))
    if target_root.is_symlink() or not target_root.is_dir():
        raise InstallError(f"target root must be a real directory: {target_root}")
    if apply and target_root == DEFAULT_TARGET_ROOT and os.geteuid() != 0:
        raise InstallError("installing below / requires root")
    backup_root = target_root / "var/lib/heim-pc/host-health/install-backups"
    source_data: dict[str, bytes] = {}
    for source_relative, _target_relative, _mode in FILES:
        source = source_root / source_relative
        if source.is_symlink() or not source.is_file():
            raise InstallError(f"source must be a regular file: {source}")
        source_data[source_relative] = source.read_bytes()

    results: list[dict[str, Any]] = []
    for obsolete_name in OBSOLETE_JOURNALD_DROP_INS:
        target_relative = f"etc/systemd/journald.conf.d/{obsolete_name}"
        target = _target_path(target_root, target_relative)
        _assert_safe_path(target, target_root=target_root, allow_absent=True)
        before = target.read_bytes() if target.exists() else None
        backup: str | None = None
        if apply and before is not None:
            backup = _backup_existing(
                backup_root=backup_root,
                target_relative=target_relative,
                before=before,
                target_root=target_root,
            )
            _remove_file(
                target,
                target_root=target_root,
                expected_current=before,
            )
        results.append(
            {
                "operation": "remove_obsolete",
                "source": None,
                "target": str(target),
                "mode": None,
                "action": (
                    "absent"
                    if before is None
                    else ("removed" if apply else "planned_removal")
                ),
                "sha256": _sha256(before) if before is not None else None,
                "backup": backup,
            }
        )

    for source_relative, target_relative, mode in FILES:
        data = source_data[source_relative]
        target = _target_path(target_root, target_relative)
        _assert_safe_path(target, target_root=target_root, allow_absent=True)
        before = target.read_bytes() if target.exists() else None
        changed = before != data or (
            target.exists() and stat.S_IMODE(target.stat().st_mode) != mode
        )
        backup: str | None = None
        if apply and changed:
            if before is not None and before != data:
                backup = _backup_existing(
                    backup_root=backup_root,
                    target_relative=target_relative,
                    before=before,
                    target_root=target_root,
                )
            _atomic_write(
                target,
                data,
                mode=mode,
                target_root=target_root,
                expected_current=before,
            )
        results.append(
            {
                "operation": "install",
                "source": source_relative,
                "target": str(target),
                "mode": oct(mode),
                "action": "unchanged" if not changed else ("installed" if apply else "planned"),
                "sha256": _sha256(data),
                "backup": backup,
            }
        )
    return results


def install(
    *,
    source_root: Path,
    target_root: Path,
    apply: bool,
    expected_head: str | None,
) -> dict[str, Any]:
    head, dirty = repository_identity(source_root)
    if expected_head is not None and head != expected_head:
        raise InstallError("repository HEAD differs from --expected-head")
    if apply and dirty:
        raise InstallError("repository must be clean for a commit-bound install")
    files = install_files(
        source_root=source_root,
        target_root=target_root,
        apply=apply,
    )
    return {
        "schema_version": 1,
        "kind": "heim_pc_host_health_remediation_install_receipt",
        "apply": apply,
        "repository_head": head,
        "repository_dirty": dirty,
        "target_root": str(target_root),
        "files": files,
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
            "deployment",
            "systemd_activation",
            "firmware_flash",
            "BIOS_SVM_enablement",
        ],
    }


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
                    "schema_version": 1,
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
