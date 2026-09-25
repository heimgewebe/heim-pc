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


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _ensure_parent_directories(path: Path) -> None:
    missing: list[Path] = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        parent = cursor.parent
        if parent == cursor:
            raise InstallError(f"cannot resolve parent directory for {path}")
        cursor = parent
    if cursor.is_symlink() or not cursor.is_dir():
        raise InstallError(f"install parent ancestor is unsafe: {cursor}")

    path.mkdir(parents=True, exist_ok=True, mode=0o755)
    for directory in reversed(missing):
        metadata = directory.lstat()
        if directory.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise InstallError(f"created install directory is unsafe: {directory}")
        os.chmod(directory, 0o755)


def atomic_install(target: Path, data: bytes, mode: int) -> dict[str, Any]:
    _ensure_parent_directories(target.parent)
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
            _fsync_directory(target.parent)
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


def verify_unit_data(data: bytes) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="heim-pc-guard-unit-verify-") as temporary:
        path = Path(temporary) / f"{UNIT_NAME}.service"
        path.write_bytes(data)
        os.chmod(path, 0o644)
        return verify_unit_file(path)


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


def parse_json_stdout(
    completed: subprocess.CompletedProcess[str], *, label: str
) -> dict[str, Any]:
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
            "--preflight-only",
        ]
    )
    value = parse_json_stdout(completed, label="guard activation preflight")
    state = value.get("persistent_state")
    if not isinstance(state, dict):
        raise InstallError("guard preflight omitted persistent state evidence")
    if state.get("circuit_open") is not False:
        raise InstallError("guard preflight refused because the persistent circuit is open")
    if state.get("pending_action") is not None:
        raise InstallError("guard preflight refused because a pending action exists")
    action = value.get("action")
    result = value.get("result")
    if result != "preflight" or action not in {"none", "warn", "cooldown"}:
        raise InstallError(
            "guard preflight is not safe for automatic activation: "
            f"action={action!r}, result={result!r}"
        )
    return value


def existing_unit_enabled() -> bool:
    completed = subprocess.run(
        [SYSTEMCTL, "is-enabled", f"{UNIT_NAME}.service"],
        text=True,
        capture_output=True,
        check=False,
    )
    return completed.returncode == 0 and completed.stdout.strip() in {
        "enabled",
        "enabled-runtime",
    }


def existing_unit_active() -> bool:
    completed = subprocess.run(
        [SYSTEMCTL, "is-active", f"{UNIT_NAME}.service"],
        text=True,
        capture_output=True,
        check=False,
    )
    return completed.returncode == 0 and completed.stdout.strip() == "active"


def expected_guard_argv(release: Path) -> list[str]:
    return [
        PYTHON,
        str(release / "scripts/grabowski_memory_guard.py"),
        "--policy",
        str(release / "config/memory-pressure-guard.v1.json"),
        "--state-dir",
        str(STATE_DIR),
        "--loop",
    ]


def read_process_argv(pid: int) -> list[str]:
    if pid <= 0:
        raise InstallError("guard process pid must be positive")
    path = Path("/proc") / str(pid) / "cmdline"
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise InstallError(f"cannot read guard process argv: {exc}") from exc
    argv = [
        os.fsdecode(part)
        for part in raw.split(b"\0")
        if part
    ]
    if not argv:
        raise InstallError("guard process argv is empty")
    return argv


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
    if apply and system_root == Path("/") and expected_head is None:
        raise InstallError("live system guard installation requires expected_head")
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
    preexisting_enabled = False
    preexisting_active = False
    running_argv: list[str] | None = None

    if apply:
        live_system = system_root == Path("/")
        service_data, service_mode = files[service_target]
        verification = verify_unit_data(service_data)

        if live_system:
            preexisting_enabled = existing_unit_enabled()
            preexisting_active = existing_unit_active()

            # Publish immutable release files first.  Do not replace or enable the
            # boot unit until the new release has passed the safety preflight.
            for path, (data, mode) in files.items():
                if path == service_target:
                    continue
                installed.append(atomic_install(path, data, mode))

            if enable or start or preexisting_enabled or preexisting_active:
                preflight = observe_only_preflight(release)

            installed.append(atomic_install(service_target, service_data, service_mode))
            run([SYSTEMCTL, "daemon-reload"])
            load_state = run(
                [
                    SYSTEMCTL,
                    "show",
                    f"{UNIT_NAME}.service",
                    "--property=LoadState",
                    "--value",
                ]
            ).stdout.strip()
            if load_state != "loaded":
                raise InstallError(f"guard unit did not load: {load_state!r}")
            systemd_state = "installed"

            if enable:
                run([SYSTEMCTL, "enable", f"{UNIT_NAME}.service"])
                systemd_state = "enabled"
            elif preexisting_enabled and preexisting_active:
                systemd_state = "installed-existing-enabled-active"
            elif preexisting_enabled:
                systemd_state = "installed-existing-enabled"
            elif preexisting_active:
                systemd_state = "installed-existing-active"

            if start:
                run([SYSTEMCTL, "restart", f"{UNIT_NAME}.service"])
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

                running_argv = read_process_argv(main_pid)
                expected_argv = expected_guard_argv(release)
                if running_argv != expected_argv:
                    raise InstallError(
                        "running guard does not match the installed release: "
                        f"expected={expected_argv!r}, observed={running_argv!r}"
                    )
                systemd_state += "+restarted-active-exact-release"
        else:
            for path, (data, mode) in files.items():
                installed.append(atomic_install(path, data, mode))
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
        "preexisting_enabled": preexisting_enabled,
        "preexisting_active": preexisting_active,
        "planned": planned,
        "installed": installed,
        "unit_verification": verification,
        "systemd_state": systemd_state,
        "observe_only_preflight": preflight,
        "running_argv": running_argv,
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
                {
                    "kind": "heim_pc_grabowski_memory_guard_install_error",
                    "error": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())