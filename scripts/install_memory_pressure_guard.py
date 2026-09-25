#!/usr/bin/env python3
"""Install the commit-bound independent Grabowski memory guard."""

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
SYSTEM_SERVICE_TEMPLATE = ROOT / "systemd/system/heim-pc-grabowski-memory-guard.service.in"
SOURCES = {
    "scripts/grabowski_memory_guard.py": ROOT / "scripts/grabowski_memory_guard.py",
    "config/memory-pressure-guard.v1.json": ROOT / "config/memory-pressure-guard.v1.json",
}
UNIT_NAME = "heim-pc-grabowski-memory-guard"
DEFAULT_RELEASE_ROOT = Path("/usr/local/lib/heim-pc/memory-pressure-guard/releases")
SYSTEM_UNIT_PATH = Path("/etc/systemd/system") / f"{UNIT_NAME}.service"
STATE_DIR = Path("/var/lib/heim-pc/grabowski-memory-guard")
SYSTEMCTL = "/usr/bin/systemctl"
PYTHON = "/usr/bin/python3"


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
    if len(head) != 40 or any(ch not in "0123456789abcdef" for ch in head):
        raise InstallError("repository HEAD is invalid")
    status = run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root,
    ).stdout
    return head, bool(status.strip())


def systemd_path(path: Path, *, label: str) -> str:
    raw = str(path)
    if (
        not path.is_absolute()
        or any(ch.isspace() for ch in raw)
        or any(ch in {"%", "\\", '"', "'"} for ch in raw)
    ):
        raise InstallError(f"{label} is not a safe absolute systemd path: {path}")
    return raw


def rooted(system_root: Path, live_path: Path) -> Path:
    if system_root == Path("/"):
        return live_path
    return system_root / live_path.relative_to("/")


def atomic_install(target: Path, data: bytes, mode: int) -> dict[str, Any]:
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise InstallError(f"install target must be regular or absent: {target}")
    before = target.read_bytes() if target.exists() else None
    before_mode = stat.S_IMODE(target.stat().st_mode) if target.exists() else None
    action = "unchanged" if before == data and before_mode == mode else "installed"
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
    if (
        target.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or target.read_bytes() != data
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise InstallError(f"installed target readback failed: {target}")
    return {
        "path": str(target),
        "action": action,
        "mode": format(mode, "04o"),
        "sha256": sha256(data),
    }


def verify_unit_file(path: Path) -> dict[str, Any]:
    completed = subprocess.run(
        ["systemd-analyze", "--generators=no", "--man=no", "verify", str(path)],
        text=True,
        capture_output=True,
        check=False,
    )
    target_diagnostics = [
        line for line in completed.stderr.splitlines() if str(path) in line
    ]
    if target_diagnostics:
        raise InstallError(
            "unit verification reported target diagnostics: "
            + " | ".join(target_diagnostics[:10])
        )
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


def plan(
    *,
    system_root: Path,
    release_root: Path,
    head: str,
    blobs: dict[str, bytes],
    service_template: bytes,
) -> tuple[list[dict[str, Any]], dict[Path, tuple[bytes, int]], Path, Path]:
    live_release = release_root / head
    release_text = systemd_path(live_release, label="release root")
    service_data = service_template.decode("utf-8").replace(
        "@SYSTEM_RELEASE_ROOT@", release_text
    ).encode("utf-8")
    if b"@SYSTEM_RELEASE_ROOT@" in service_data:
        raise InstallError("service template rendering is incomplete")
    release = rooted(system_root, live_release)
    service_target = rooted(system_root, SYSTEM_UNIT_PATH)
    files = {
        **{
            release / relative: (data, 0o755 if relative.startswith("scripts/") else 0o600)
            for relative, data in blobs.items()
        },
        service_target: (service_data, 0o644),
    }
    planned = [
        {"path": str(path), "mode": format(mode, "04o"), "sha256": sha256(data)}
        for path, (data, mode) in files.items()
    ]
    return planned, files, release, service_target


def parse_json_stdout(completed: subprocess.CompletedProcess[str], *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise InstallError(f"{label} returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise InstallError(f"{label} returned a non-object")
    return value


def observe_only_preflight(release: Path) -> dict[str, Any]:
    completed = run(
        [
            PYTHON,
            str(release / "scripts/grabowski_memory_guard.py"),
            "--policy",
            str(release / "config/memory-pressure-guard.v1.json"),
            "--state-dir",
            str(STATE_DIR),
            "--observe-only",
        ]
    )
    value = parse_json_stdout(completed, label="guard observe-only preflight")
    action = value.get("action")
    result = value.get("result")
    if action not in {"none", "warn"} or result not in {"observed", "observe-only"}:
        raise InstallError(
            f"guard preflight is not safe for automatic activation: action={action!r}, result={result!r}"
        )
    return value


def install(
    *,
    system_root: Path,
    release_root: Path,
    apply: bool,
    enable: bool,
    start: bool,
    expected_head: str | None = None,
) -> dict[str, Any]:
    if (enable or start) and not apply:
        raise InstallError("enable/start require apply")
    if apply and system_root == Path("/") and os.geteuid() != 0:
        raise InstallError("live system guard installation requires root")
    if (enable or start) and system_root != Path("/"):
        raise InstallError("service control requires the live system root")

    head, dirty = repository_identity(ROOT)
    if dirty:
        raise InstallError("repository must be clean before a commit-bound install")
    if expected_head is not None and head != expected_head:
        raise InstallError("repository HEAD differs from expected_head")

    blobs = {
        relative: repository_blob(ROOT, head=head, relative_path=relative)
        for relative in SOURCES
    }
    service_template = repository_blob(
        ROOT,
        head=head,
        relative_path="systemd/system/heim-pc-grabowski-memory-guard.service.in",
    )
    planned, files, release, service_target = plan(
        system_root=system_root,
        release_root=release_root,
        head=head,
        blobs=blobs,
        service_template=service_template,
    )

    installed: list[dict[str, Any]] = []
    verification: dict[str, Any] = {"status": "not-applied"}
    systemd_state = "not-applied"
    preflight: dict[str, Any] | None = None

    if apply:
        for path, (data, mode) in files.items():
            installed.append(atomic_install(path, data, mode))
        verification = verify_unit_file(service_target)

        if system_root == Path("/"):
            run([SYSTEMCTL, "daemon-reload"])
            load_state = run(
                [SYSTEMCTL, "show", f"{UNIT_NAME}.service", "--property=LoadState", "--value"]
            ).stdout.strip()
            if load_state != "loaded":
                raise InstallError(f"guard unit did not load: {load_state!r}")
            systemd_state = "installed"
            if enable:
                run([SYSTEMCTL, "enable", f"{UNIT_NAME}.service"])
                systemd_state = "enabled"
            if start:
                preflight = observe_only_preflight(release)
                run([SYSTEMCTL, "start", f"{UNIT_NAME}.service"])
                properties = run(
                    [
                        SYSTEMCTL,
                        "show",
                        f"{UNIT_NAME}.service",
                        "--property=ActiveState",
                        "--property=MainPID",
                        "--property=ControlGroup",
                        "--no-pager",
                    ]
                ).stdout
                parsed = {
                    key: value
                    for key, value in (
                        line.split("=", 1)
                        for line in properties.splitlines()
                        if "=" in line
                    )
                }
                try:
                    main_pid = int(parsed.get("MainPID", "0"))
                except ValueError as exc:
                    raise InstallError("guard MainPID readback is invalid") from exc
                if parsed.get("ActiveState") != "active" or main_pid <= 0:
                    raise InstallError("guard did not become active")
                if parsed.get("ControlGroup") != f"/system.slice/{UNIT_NAME}.service":
                    raise InstallError("guard cgroup readback is invalid")
                systemd_state += "+started-active"
        else:
            systemd_state = "staged-root-installed"

    receipt = {
        "schema_version": 1,
        "kind": "heim_pc_grabowski_memory_guard_install_receipt",
        "generated_at_unix": int(time.time()),
        "repository_head": head,
        "repository_dirty": dirty,
        "release_root": str(release),
        "apply": apply,
        "enable": enable,
        "start": start,
        "planned": planned,
        "installed": installed,
        "unit_verification": verification,
        "systemd_state": systemd_state,
        "observe_only_preflight": preflight,
        "does_not_establish": [
            "internal_root_cause_of_grabowski_memory_growth",
            "future_restart_correctness_under_all_failure_modes",
            "absence_of_future_global_oom_from_other_processes",
            "permanent_optimality_of_guard_thresholds",
        ],
    }
    receipt["receipt_sha256"] = sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--release-root",
        type=Path,
        default=DEFAULT_RELEASE_ROOT,
    )
    parser.add_argument("--system-root", type=Path, default=Path("/"))
    parser.add_argument("--expected-head")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--enable", action="store_true")
    parser.add_argument("--start", action="store_true")
    args = parser.parse_args()
    try:
        result = install(
            system_root=args.system_root.expanduser().resolve(),
            release_root=args.release_root.expanduser(),
            apply=args.apply,
            enable=args.enable,
            start=args.start,
            expected_head=args.expected_head,
        )
    except (InstallError, OSError, ValueError) as exc:
        print(
            json.dumps(
                {"kind": "heim_pc_grabowski_memory_guard_install_error", "error": str(exc)},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
