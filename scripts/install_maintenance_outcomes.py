#!/usr/bin/env python3
"""Install one commit-bound read-only maintenance outcome collector and timer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
UNIT_NAME = "heim-pc-maintenance-outcomes"
SCRIPT_PATH = "scripts/maintenance_outcomes.py"
POLICY_PATH = "config/maintenance-producers.v1.json"
SERVICE_PATH = "systemd/user/heim-pc-maintenance-outcomes.service.in"
TIMER_PATH = "systemd/user/heim-pc-maintenance-outcomes.timer"


class InstallError(RuntimeError):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run(argv: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise InstallError(f"{' '.join(argv)} failed: {detail[:1000]}")
    return completed


def _repository_identity(root: Path) -> tuple[str, bool]:
    head = _run(["git", "rev-parse", "HEAD"], cwd=root).stdout.strip()
    if len(head) != 40 or any(character not in "0123456789abcdef" for character in head):
        raise InstallError("repository HEAD is invalid")
    status = _run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root,
    ).stdout
    return head, bool(status.strip())


def _repository_blob(root: Path, *, head: str, relative_path: str) -> bytes:
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


def _safe_systemd_path(path: Path, *, label: str) -> str:
    raw = str(path)
    if (
        not path.is_absolute()
        or any(character.isspace() for character in raw)
        or any(character in {"%", "\\", '"', "'"} for character in raw)
    ):
        raise InstallError(f"{label} is not a safe absolute systemd path: {path}")
    return raw


def _atomic_install(target: Path, data: bytes, mode: int) -> dict[str, Any]:
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_metadata = target.parent.lstat()
    if (
        target.parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.getuid()
        or target.is_symlink()
    ):
        raise InstallError(f"install path is not owner-controlled: {target}")
    before = target.read_bytes() if target.exists() else None
    action = (
        "unchanged"
        if before == data and stat.S_IMODE(target.stat().st_mode) == mode
        else "installed"
    )
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
            directory_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)
    else:
        os.chmod(target, mode)
    metadata = target.lstat()
    if target.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise InstallError(f"installed target is unsafe: {target}")
    if target.read_bytes() != data or stat.S_IMODE(metadata.st_mode) != mode:
        raise InstallError(f"installed target readback failed: {target}")
    return {
        "path": str(target),
        "action": action,
        "mode": format(mode, "04o"),
        "sha256": _sha256(data),
    }


def _verify_units(service_path: Path, timer_path: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [
            "systemd-analyze",
            "--user",
            "--generators=no",
            "--man=no",
            "verify",
            str(service_path),
            str(timer_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    target_paths = (str(service_path), str(timer_path))
    diagnostics = [
        line
        for line in completed.stderr.splitlines()
        if any(target in line for target in target_paths)
    ]
    if diagnostics:
        raise InstallError(
            "unit verification reported target diagnostics: "
            + " | ".join(diagnostics[:10])
        )
    if completed.returncode == 0:
        return {"status": "verified", "returncode": 0}
    known_host_failure = (
        completed.returncode == -signal.SIGABRT
        and "Failed to allocate device monitor" in completed.stderr
        and "Assertion '*_head == _item' failed" in completed.stderr
    )
    if known_host_failure:
        return {
            "status": "host-verifier-unavailable",
            "returncode": completed.returncode,
        }
    detail = (completed.stderr or completed.stdout).strip()
    raise InstallError(f"systemd-analyze verify failed: {detail[:1000]}")


def install(
    *,
    home: Path,
    release_root: Path,
    apply: bool,
    enable: bool,
    start: bool,
    expected_head: str | None = None,
) -> dict[str, Any]:
    head, dirty = _repository_identity(ROOT)
    if dirty:
        raise InstallError("repository must be clean before a commit-bound install")
    if expected_head is not None and expected_head != head:
        raise InstallError("repository HEAD differs from expected_head")

    release = release_root / head
    script_data = _repository_blob(ROOT, head=head, relative_path=SCRIPT_PATH)
    policy_data = _repository_blob(ROOT, head=head, relative_path=POLICY_PATH)
    service_template = _repository_blob(ROOT, head=head, relative_path=SERVICE_PATH)
    timer_data = _repository_blob(ROOT, head=head, relative_path=TIMER_PATH)

    release_path = _safe_systemd_path(release, label="release root")
    home_path = _safe_systemd_path(home, label="home")
    service_text = (
        service_template.decode("utf-8")
        .replace("@RELEASE_ROOT@", release_path)
        .replace("@HOME@", home_path)
    )
    if "@RELEASE_ROOT@" in service_text or "@HOME@" in service_text:
        raise InstallError("service template rendering is incomplete")
    service_data = service_text.encode("utf-8")

    release_files = {
        release / SCRIPT_PATH: (script_data, 0o755),
        release / POLICY_PATH: (policy_data, 0o600),
    }
    unit_root = home / ".config/systemd/user"
    service_target = unit_root / f"{UNIT_NAME}.service"
    timer_target = unit_root / f"{UNIT_NAME}.timer"

    planned = [
        {"path": str(path), "mode": format(mode, "04o"), "sha256": _sha256(data)}
        for path, (data, mode) in release_files.items()
    ]
    planned.extend(
        [
            {"path": str(service_target), "mode": "0644", "sha256": _sha256(service_data)},
            {"path": str(timer_target), "mode": "0644", "sha256": _sha256(timer_data)},
        ]
    )

    installed: list[dict[str, Any]] = []
    unit_verification: dict[str, Any] = {"status": "not-applied"}
    systemd_state = "not-applied"
    if apply:
        state_root = home / ".local/state/heim-pc/maintenance-outcomes"
        state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        metadata = state_root.lstat()
        if state_root.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise InstallError(f"runtime directory is unsafe: {state_root}")
        os.chmod(state_root, 0o700)

        for path, (data, mode) in release_files.items():
            installed.append(_atomic_install(path, data, mode))
        installed.append(_atomic_install(service_target, service_data, 0o644))
        installed.append(_atomic_install(timer_target, timer_data, 0o644))
        unit_verification = _verify_units(service_target, timer_target)

        _run(["systemctl", "--user", "daemon-reload"])
        for unit in (f"{UNIT_NAME}.service", f"{UNIT_NAME}.timer"):
            load_state = _run(
                ["systemctl", "--user", "show", unit, "--property=LoadState", "--value"]
            ).stdout.strip()
            if load_state != "loaded":
                raise InstallError(f"systemd unit did not load: {unit}={load_state!r}")
        systemd_state = "installed"
        if enable:
            _run(["systemctl", "--user", "enable", "--now", f"{UNIT_NAME}.timer"])
            systemd_state = "timer-enabled"
        if start:
            _run(["systemctl", "--user", "start", f"{UNIT_NAME}.service"])
            result = _run(
                ["systemctl", "--user", "show", f"{UNIT_NAME}.service", "--property=Result", "--value"]
            ).stdout.strip()
            if result != "success":
                raise InstallError(f"collector service result is not success: {result!r}")
            systemd_state += "+service-started"

    receipt: dict[str, Any] = {
        "schema_version": 1,
        "kind": "heim_pc_maintenance_outcomes_install_receipt",
        "generated_at_unix": int(time.time()),
        "repository_head": head,
        "repository_dirty": dirty,
        "release_root": str(release),
        "apply": apply,
        "enable": enable,
        "start": start,
        "planned": planned,
        "installed": installed,
        "systemd": systemd_state,
        "unit_verification": unit_verification,
        "does_not_establish": [
            "future_collector_success",
            "maintenance_producer_correctness",
            "automatic_repair_authority",
            "automatic_cleanup_authority",
        ],
    }
    receipt["receipt_sha256"] = _sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    if apply:
        receipt_path = (
            home
            / ".local/state/heim-pc/maintenance-outcomes/install-receipts"
            / f"{head}.json"
        )
        _atomic_install(
            receipt_path,
            (
                json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2)
                + "\n"
            ).encode("utf-8"),
            0o600,
        )
        receipt["receipt_path"] = str(receipt_path)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument(
        "--release-root",
        type=Path,
        default=Path.home() / ".local/lib/heim-pc/maintenance-outcomes/releases",
    )
    parser.add_argument("--expected-head")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--enable", action="store_true")
    parser.add_argument("--start", action="store_true")
    args = parser.parse_args()
    if (args.enable or args.start) and not args.apply:
        parser.error("--enable and --start require --apply")
    try:
        receipt = install(
            home=args.home.expanduser().resolve(),
            release_root=args.release_root.expanduser().resolve(),
            apply=args.apply,
            enable=args.enable,
            start=args.start,
            expected_head=args.expected_head,
        )
    except (InstallError, OSError, ValueError) as exc:
        print(
            json.dumps(
                {"kind": "heim_pc_maintenance_outcomes_install_error", "error": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
