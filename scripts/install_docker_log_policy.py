#!/usr/bin/env python3
"""Install the minimal bounded Docker logging defaults without replacing unrelated daemon settings."""

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
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
POLICY_RELATIVE_PATH = "config/runaway-guard.v1.json"
DEFAULT_TARGET = Path("/etc/docker/daemon.json")
DEFAULT_BACKUP_ROOT = Path("/var/lib/heim-pc/runaway-guard/docker-daemon-backups")


class InstallError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(argv: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise InstallError(f"{' '.join(argv)} failed: {detail[:1000]}")
    return completed


def repository_identity(root: Path) -> tuple[str, bool]:
    head = run(["git", "rev-parse", "HEAD"], cwd=root).stdout.strip()
    if len(head) != 40 or any(character not in "0123456789abcdef" for character in head):
        raise InstallError("repository HEAD is invalid")
    status = run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=root).stdout
    return head, bool(status.strip())


def repository_blob(root: Path, *, head: str, relative_path: str) -> bytes:
    completed = subprocess.run(
        ["git", "show", f"{head}:{relative_path}"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise InstallError(f"cannot read commit-bound blob {relative_path}: {detail[:500]}")
    return completed.stdout


def docker_policy(policy_data: bytes) -> dict[str, Any]:
    try:
        policy = json.loads(policy_data)
    except json.JSONDecodeError as exc:
        raise InstallError(f"policy is invalid JSON: {exc}") from exc
    if not isinstance(policy, dict):
        raise InstallError("policy must be a JSON object")
    if policy.get("schema_version") != 1 or policy.get("kind") != "heim_pc_minimal_runaway_guard":
        raise InstallError("unsupported policy identity")
    desired = policy.get("docker")
    if not isinstance(desired, dict):
        raise InstallError("docker policy is missing")
    driver = desired.get("log-driver")
    options = desired.get("log-opts")
    if driver != "local":
        raise InstallError("docker log-driver must be local")
    if not isinstance(options, dict) or not options:
        raise InstallError("docker log-opts must be a non-empty object")
    normalized_options: dict[str, str] = {}
    for key, value in options.items():
        if not isinstance(key, str) or not key or not isinstance(value, str) or not value:
            raise InstallError("docker log-opts keys and values must be non-empty strings")
        normalized_options[key] = value
    if normalized_options.get("max-size") is None or normalized_options.get("max-file") is None:
        raise InstallError("docker log policy requires max-size and max-file")
    return {"log-driver": driver, "log-opts": normalized_options}


def decode_existing(data: bytes | None) -> dict[str, Any]:
    if data is None:
        return {}
    try:
        value = json.loads(data)
    except json.JSONDecodeError as exc:
        raise InstallError(f"existing Docker daemon configuration is invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise InstallError("existing Docker daemon configuration must be a JSON object")
    return value


def merge_daemon_config(existing: dict[str, Any], desired: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    current_driver = merged.get("log-driver")
    if current_driver is not None and current_driver != desired["log-driver"]:
        raise InstallError(
            f"existing log-driver {current_driver!r} conflicts with desired {desired['log-driver']!r}"
        )
    current_options = merged.get("log-opts", {})
    if not isinstance(current_options, dict):
        raise InstallError("existing log-opts must be a JSON object")
    merged_options = dict(current_options)
    for key, value in desired["log-opts"].items():
        current = merged_options.get(key)
        if current is not None and current != value:
            raise InstallError(
                f"existing log-opts.{key} {current!r} conflicts with desired {value!r}"
            )
        merged_options[key] = value
    merged["log-driver"] = desired["log-driver"]
    merged["log-opts"] = merged_options
    return merged


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _assert_safe_target(path: Path, *, allow_absent: bool) -> None:
    if path.is_symlink():
        raise InstallError(f"path must not be a symlink: {path}")
    if not path.exists():
        if allow_absent:
            return
        raise InstallError(f"path does not exist: {path}")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise InstallError(f"path must be a regular file: {path}")


_EXPECTED_UNSET = object()


def atomic_install(
    path: Path,
    data: bytes,
    *,
    mode: int,
    expected_current: bytes | None | object = _EXPECTED_UNSET,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise InstallError(f"target parent is unsafe: {path.parent}")
    _assert_safe_target(path, allow_absent=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        if expected_current is not _EXPECTED_UNSET:
            _assert_safe_target(path, allow_absent=True)
            current = path.read_bytes() if path.exists() else None
            if current != expected_current:
                raise InstallError(f"target preimage changed before replacement: {path}")
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)
    _assert_safe_target(path, allow_absent=False)
    if path.read_bytes() != data or stat.S_IMODE(path.stat().st_mode) != mode:
        raise InstallError(f"installed file readback failed: {path}")


def apply_policy(
    *,
    target: Path,
    backup_root: Path,
    policy_data: bytes,
    apply: bool,
) -> dict[str, Any]:
    target = _absolute_without_resolving(target)
    backup_root = _absolute_without_resolving(backup_root)
    if target == DEFAULT_TARGET and apply and os.geteuid() != 0:
        raise InstallError("installing /etc/docker/daemon.json requires root")
    _assert_safe_target(target, allow_absent=True)
    before = target.read_bytes() if target.exists() else None
    existing = decode_existing(before)
    desired = docker_policy(policy_data)
    merged = merge_daemon_config(existing, desired)
    after = (json.dumps(merged, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    changed = before != after
    backup: dict[str, Any] | None = None
    if apply and changed:
        if before is not None:
            before_sha256 = sha256(before)
            backup_path = backup_root / f"daemon-{before_sha256}.json"
            backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            if backup_root.is_symlink() or not backup_root.is_dir():
                raise InstallError(f"backup root is unsafe: {backup_root}")
            if backup_path.exists():
                _assert_safe_target(backup_path, allow_absent=False)
                if backup_path.read_bytes() != before:
                    raise InstallError(f"existing backup content mismatch: {backup_path}")
            else:
                atomic_install(backup_path, before, mode=0o600, expected_current=None)
            backup = {
                "path": str(backup_path),
                "sha256": before_sha256,
            }
        atomic_install(target, after, mode=0o644, expected_current=before)
    readback = target.read_bytes() if apply and target.exists() else after
    if apply and readback != after:
        raise InstallError("Docker daemon configuration readback differs from planned content")
    return {
        "target": str(target),
        "apply": apply,
        "action": "unchanged" if not changed else ("installed" if apply else "planned"),
        "before_sha256": sha256(before) if before is not None else None,
        "after_sha256": sha256(after),
        "policy_sha256": sha256(policy_data),
        "backup": backup,
        "restart_required": changed,
        "existing_containers_require_recreation": True,
        "desired": desired,
    }


def install(
    *,
    target: Path,
    backup_root: Path,
    apply: bool,
    expected_head: str | None,
) -> dict[str, Any]:
    head, dirty = repository_identity(ROOT)
    if dirty:
        raise InstallError("repository must be clean before a commit-bound install")
    if expected_head is not None and head != expected_head:
        raise InstallError("repository HEAD differs from expected_head")
    policy_data = repository_blob(ROOT, head=head, relative_path=POLICY_RELATIVE_PATH)
    result = apply_policy(
        target=target,
        backup_root=backup_root,
        policy_data=policy_data,
        apply=apply,
    )
    receipt = {
        "schema_version": 1,
        "kind": "heim_pc_docker_log_policy_install_receipt",
        "generated_at_unix": int(time.time()),
        "repository_head": head,
        "repository_dirty": dirty,
        **result,
        "does_not_establish": [
            "docker_daemon_restarted",
            "existing_container_log_driver_migration",
            "future_container_recreation_success",
        ],
    }
    receipt["receipt_sha256"] = sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--backup-root", type=Path, default=DEFAULT_BACKUP_ROOT)
    parser.add_argument("--expected-head")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        receipt = install(
            target=args.target,
            backup_root=args.backup_root,
            apply=args.apply,
            expected_head=args.expected_head,
        )
    except (InstallError, OSError, ValueError) as exc:
        print(json.dumps({"kind": "heim_pc_docker_log_policy_install_error", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
