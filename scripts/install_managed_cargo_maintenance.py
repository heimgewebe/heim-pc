#!/usr/bin/env python3
"""Install one commit-bound managed Cargo maintenance release and user timer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SERVICE_TEMPLATE = ROOT / "systemd/user/heim-pc-managed-cargo-maintenance.service.in"
TIMER_SOURCE = ROOT / "systemd/user/heim-pc-managed-cargo-maintenance.timer"
SOURCES = {
    "scripts/managed_cargo_maintenance.py": ROOT / "scripts/managed_cargo_maintenance.py",
    "scripts/managed_cargo_gc.py": ROOT / "scripts/managed_cargo_gc.py",
    "scripts/managed_build.py": ROOT / "scripts/managed_build.py",
    "config/managed-build.v1.json": ROOT / "config/managed-build.v1.json",
}
UNIT_NAME = "heim-pc-managed-cargo-maintenance"


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


def repository_identity(root: Path) -> tuple[str, bool]:
    head = run(["git", "rev-parse", "HEAD"], cwd=root).stdout.strip()
    if len(head) != 40 or any(character not in "0123456789abcdef" for character in head):
        raise InstallError("repository HEAD is invalid")
    status = run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=root).stdout
    return head, bool(status.strip())


def verify_unit_files(service_path: Path, timer_path: Path) -> dict[str, Any]:
    completed = subprocess.run(
        ["systemd-analyze", "--user", "--generators=no", "--man=no", "verify", str(service_path), str(timer_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    targets = (str(service_path), str(timer_path))
    diagnostics = [line for line in completed.stderr.splitlines() if any(path in line for path in targets)]
    if diagnostics:
        raise InstallError("unit verification reported target diagnostics: " + " | ".join(diagnostics[:10]))
    if completed.returncode == 0:
        return {"status": "verified", "returncode": 0}
    known_host_failure = (
        completed.returncode == -signal.SIGABRT
        and "Failed to allocate device monitor" in completed.stderr
        and "Assertion '*_head == _item' failed" in completed.stderr
    )
    if known_host_failure:
        return {"status": "host-verifier-unavailable", "returncode": completed.returncode}
    detail = (completed.stderr or completed.stdout).strip()
    raise InstallError(f"systemd-analyze verify failed: {detail[:1000]}")


def systemd_path(path: Path, *, label: str) -> str:
    raw = str(path)
    if not path.is_absolute() or any(character.isspace() for character in raw) or any(character in {"%", "\\", "\"", "'"} for character in raw):
        raise InstallError(f"{label} is not a safe absolute systemd path: {path}")
    return raw


def atomic_install(target: Path, data: bytes, mode: int) -> dict[str, Any]:
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.is_symlink():
        raise InstallError(f"install target must not be a symlink: {target}")
    before = target.read_bytes() if target.exists() else None
    action = "unchanged" if before == data and stat.S_IMODE(target.stat().st_mode) == mode else "installed"
    if action == "installed":
        fd, name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
    else:
        os.chmod(target, mode)
    metadata = target.lstat()
    if target.is_symlink() or not stat.S_ISREG(metadata.st_mode) or target.read_bytes() != data or stat.S_IMODE(metadata.st_mode) != mode:
        raise InstallError(f"installed target readback failed: {target}")
    return {"path": str(target), "action": action, "mode": format(mode, "04o"), "sha256": sha256(data)}


def install(*, home: Path, release_root: Path, apply: bool, enable: bool, start: bool, expected_head: str | None = None) -> dict[str, Any]:
    head, dirty = repository_identity(ROOT)
    if dirty:
        raise InstallError("repository must be clean before a commit-bound install")
    if expected_head is not None and head != expected_head:
        raise InstallError("repository HEAD differs from expected_head")
    release = release_root / head
    blobs = {relative: repository_blob(ROOT, head=head, relative_path=relative) for relative in SOURCES}
    service_template = repository_blob(ROOT, head=head, relative_path="systemd/user/heim-pc-managed-cargo-maintenance.service.in")
    timer_data = repository_blob(ROOT, head=head, relative_path="systemd/user/heim-pc-managed-cargo-maintenance.timer")
    release_path = systemd_path(release, label="release root")
    home_path = systemd_path(home, label="home")
    service_data = service_template.decode("utf-8").replace("@RELEASE_ROOT@", release_path).replace("@HOME@", home_path).encode("utf-8")
    if b"@RELEASE_ROOT@" in service_data or b"@HOME@" in service_data:
        raise InstallError("service template rendering is incomplete")
    unit_root = home / ".config/systemd/user"
    service_target = unit_root / f"{UNIT_NAME}.service"
    timer_target = unit_root / f"{UNIT_NAME}.timer"
    release_files = {release / relative: (data, 0o755 if relative.startswith("scripts/") else 0o600) for relative, data in blobs.items()}
    planned = [{"path": str(path), "mode": format(mode, "04o"), "sha256": sha256(data)} for path, (data, mode) in release_files.items()]
    planned.extend([
        {"path": str(service_target), "mode": "0644", "sha256": sha256(service_data)},
        {"path": str(timer_target), "mode": "0644", "sha256": sha256(timer_data)},
    ])
    installed: list[dict[str, Any]] = []
    systemd = "not-applied"
    unit_verification: dict[str, Any] = {"status": "not-applied"}
    if apply:
        for directory in (
            home / ".local/state/heim-pc/managed-builds/maintenance",
            home / ".cache/heim-pc/managed-builds",
            home / ".local/state/heim-pc/managed-builds",
        ):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            metadata = directory.lstat()
            if (
                directory.is_symlink()
                or not directory.is_dir()
                or metadata.st_uid != os.getuid()
            ):
                raise InstallError(f"runtime directory is unsafe: {directory}")
            os.chmod(directory, 0o700)
        for path, (data, mode) in release_files.items():
            installed.append(atomic_install(path, data, mode))
        installed.append(atomic_install(service_target, service_data, 0o644))
        installed.append(atomic_install(timer_target, timer_data, 0o644))
        unit_verification = verify_unit_files(service_target, timer_target)
        run(["systemctl", "--user", "daemon-reload"])
        for unit in (f"{UNIT_NAME}.service", f"{UNIT_NAME}.timer"):
            state = run(["systemctl", "--user", "show", unit, "--property=LoadState", "--value"]).stdout.strip()
            if state != "loaded":
                raise InstallError(f"systemd unit did not load after daemon-reload: {unit}={state!r}")
        if enable:
            run(["systemctl", "--user", "enable", "--now", f"{UNIT_NAME}.timer"])
            systemd = "timer-enabled"
        else:
            systemd = "installed"
        if start:
            run(["systemctl", "--user", "start", f"{UNIT_NAME}.service"])
            systemd += "+service-started"
    receipt = {
        "schema_version": 1,
        "kind": "heim_pc_managed_cargo_maintenance_install_receipt",
        "generated_at_unix": int(time.time()),
        "repository_head": head,
        "repository_dirty": dirty,
        "release_root": str(release),
        "apply": apply,
        "enable": enable,
        "start": start,
        "planned": planned,
        "installed": installed,
        "systemd": systemd,
        "unit_verification": unit_verification,
        "does_not_establish": ["future_cleanup_success", "cache_obsolescence", "worktree or source cleanup authority"],
    }
    receipt["receipt_sha256"] = sha256(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    if apply:
        receipt_path = home / ".local/state/heim-pc/managed-builds/maintenance/install-receipts" / f"{head}.json"
        atomic_install(receipt_path, (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode("utf-8"), 0o600)
        receipt["receipt_path"] = str(receipt_path)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--release-root", type=Path, default=Path.home() / ".local/lib/heim-pc/managed-cargo-maintenance/releases")
    parser.add_argument("--expected-head")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--enable", action="store_true")
    parser.add_argument("--start", action="store_true")
    args = parser.parse_args()
    if (args.enable or args.start) and not args.apply:
        parser.error("--enable and --start require --apply")
    try:
        result = install(home=args.home.expanduser().resolve(), release_root=args.release_root.expanduser().resolve(), apply=args.apply, enable=args.enable, start=args.start, expected_head=args.expected_head)
    except (InstallError, OSError, ValueError) as exc:
        print(json.dumps({"kind": "heim_pc_managed_cargo_maintenance_install_error", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
