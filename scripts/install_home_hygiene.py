#!/usr/bin/env python3
"""Install the commit-bound Heim-PC home-hygiene runtime and user timers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
UNIT_PREFIX = "heim-pc-home-hygiene"
SCRIPT_PATH = "scripts/home_hygiene.py"
POLICY_PATH = "config/home-hygiene.v1.json"
UNIT_TEMPLATES = {
    "heim-pc-home-hygiene.service": "systemd/user/heim-pc-home-hygiene.service.in",
    "heim-pc-home-hygiene.timer": "systemd/user/heim-pc-home-hygiene.timer",
    "heim-pc-coredump-retention.service": "systemd/user/heim-pc-coredump-retention.service.in",
    "heim-pc-coredump-retention.timer": "systemd/user/heim-pc-coredump-retention.timer",
}


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
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=root
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


def _ensure_owned_directory_chain(
    path: Path, *, home: Path, final_mode: int = 0o700
) -> None:
    try:
        relative = path.relative_to(home)
    except ValueError as exc:
        raise InstallError(f"runtime path escapes HOME: {path}") from exc
    home_metadata = home.lstat()
    if (
        home.is_symlink()
        or not stat.S_ISDIR(home_metadata.st_mode)
        or home_metadata.st_uid != os.getuid()
    ):
        raise InstallError(f"HOME is not owner-controlled: {home}")
    current = home
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            os.mkdir(current, 0o700)
            metadata = current.lstat()
        if (
            current.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
        ):
            raise InstallError(f"runtime directory chain is unsafe: {current}")
    os.chmod(path, final_mode)


def _atomic_install(
    target: Path, data: bytes, mode: int, *, home: Path
) -> dict[str, Any]:
    _ensure_owned_directory_chain(target.parent, home=home)
    if target.is_symlink():
        raise InstallError(f"install target is a symlink: {target}")
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


def _ensure_directory(path: Path, *, home: Path, mode: int = 0o700) -> dict[str, Any]:
    _ensure_owned_directory_chain(path, home=home, final_mode=mode)
    return {"path": str(path), "mode": format(mode, "04o")}


def _verify_units(paths: list[Path]) -> dict[str, Any]:
    completed = subprocess.run(
        [
            "systemd-analyze",
            "--user",
            "--generators=no",
            "--man=no",
            "verify",
            *(str(path) for path in paths),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    target_paths = tuple(str(path) for path in paths)
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


def _load_policy_blob(data: bytes, *, home: Path) -> dict[str, Any]:
    try:
        policy = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallError(f"policy blob is invalid: {exc}") from exc
    if policy.get("schema_version") != 1 or policy.get("kind") != "heim_pc.home_hygiene_policy":
        raise InstallError("policy blob contract is incompatible")
    return policy


def _home_path(value: str, *, home: Path) -> Path:
    if not value.startswith("${HOME}/"):
        raise InstallError("policy path must be HOME-rooted")
    path = home / value.removeprefix("${HOME}/")
    normalized = Path(os.path.normpath(path))
    try:
        normalized.relative_to(home)
    except ValueError as exc:
        raise InstallError("policy path escapes HOME") from exc
    return normalized


def _root_plan(policy: dict[str, Any], *, home: Path, user_name: str) -> dict[str, Any]:
    coredumps = policy["coredumps"]
    kernel_pattern = coredumps["kernel_pattern"].replace("${HOME}", str(home), 1)
    if "${HOME}" in kernel_pattern or not kernel_pattern.startswith(str(home) + "/"):
        raise InstallError("kernel core pattern rendering failed")
    sysctl = (
        "# Managed by heim-pc home-hygiene.v1\n"
        f"kernel.core_pattern={kernel_pattern}\n"
        "kernel.core_uses_pid=0\n"
        "fs.suid_dumpable=0\n"
    ).encode("utf-8")
    limit_kib = int(coredumps["per_file_limit_bytes"]) // 1024
    limits = (
        "# Managed by heim-pc home-hygiene.v1\n"
        f"{user_name} soft core {limit_kib}\n"
        f"{user_name} hard core {limit_kib}\n"
    ).encode("utf-8")
    return {
        "sysctl": {
            "path": "/etc/sysctl.d/60-heim-pc-coredump.conf",
            "content": sysctl.decode("utf-8"),
            "sha256": _sha256(sysctl),
            "apply_argv": ["sysctl", "--system"],
        },
        "limits": {
            "path": "/etc/security/limits.d/60-heim-pc-coredump.conf",
            "content": limits.decode("utf-8"),
            "sha256": _sha256(limits),
            "activation": "new login sessions",
        },
        "does_not_establish": [
            "root_files_installed",
            "sysctl_applied",
            "existing_session_limit_changed",
        ],
    }


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
    try:
        release_root.relative_to(home)
    except ValueError as exc:
        raise InstallError("release_root must remain below HOME") from exc
    if release_root == home:
        raise InstallError("release_root must not equal HOME")
    release = release_root / head
    script_data = _repository_blob(ROOT, head=head, relative_path=SCRIPT_PATH)
    policy_data = _repository_blob(ROOT, head=head, relative_path=POLICY_PATH)
    policy = _load_policy_blob(policy_data, home=home)
    release_path = _safe_systemd_path(release, label="release root")
    home_path = _safe_systemd_path(home, label="home")

    release_files = {
        release / SCRIPT_PATH: (script_data, 0o755),
        release / POLICY_PATH: (policy_data, 0o600),
    }
    unit_root = home / ".config/systemd/user"
    rendered_units: dict[Path, bytes] = {}
    for unit_name, relative_path in UNIT_TEMPLATES.items():
        data = _repository_blob(ROOT, head=head, relative_path=relative_path)
        if relative_path.endswith(".in"):
            text = (
                data.decode("utf-8")
                .replace("@RELEASE_ROOT@", release_path)
                .replace("@HOME@", home_path)
            )
            if "@RELEASE_ROOT@" in text or "@HOME@" in text:
                raise InstallError(f"unit template rendering is incomplete: {relative_path}")
            data = text.encode("utf-8")
        rendered_units[unit_root / unit_name] = data

    planned = [
        {"path": str(path), "mode": format(mode, "04o"), "sha256": _sha256(data)}
        for path, (data, mode) in release_files.items()
    ]
    planned.extend(
        {"path": str(path), "mode": "0644", "sha256": _sha256(data)}
        for path, data in rendered_units.items()
    )

    installed: list[dict[str, Any]] = []
    directories: list[dict[str, Any]] = []
    unit_verification: dict[str, Any] = {"status": "not-applied"}
    systemd_state = "not-applied"
    if apply:
        state_root = _home_path(policy["state_root"], home=home)
        artifact_root = _home_path(policy["artifact_root"], home=home)
        core_directory = _home_path(policy["coredumps"]["directory"], home=home)
        for directory in (state_root, artifact_root, core_directory):
            directories.append(_ensure_directory(directory, home=home))
        for relative in sorted(set(policy["artifact_categories"].values())):
            directories.append(_ensure_directory(artifact_root / relative, home=home))
        for path, (data, mode) in release_files.items():
            installed.append(_atomic_install(path, data, mode, home=home))
        for path, data in rendered_units.items():
            installed.append(_atomic_install(path, data, 0o644, home=home))
        unit_verification = _verify_units(list(rendered_units))
        _run(["systemctl", "--user", "daemon-reload"])
        for unit_name in UNIT_TEMPLATES:
            load_state = _run(
                ["systemctl", "--user", "show", unit_name, "--property=LoadState", "--value"]
            ).stdout.strip()
            if load_state != "loaded":
                raise InstallError(f"systemd unit did not load: {unit_name}={load_state!r}")
        systemd_state = "installed"
        if enable:
            _run(
                [
                    "systemctl",
                    "--user",
                    "enable",
                    "--now",
                    "heim-pc-home-hygiene.timer",
                    "heim-pc-coredump-retention.timer",
                ]
            )
            systemd_state = "timers-enabled"
        if start:
            _run(["systemctl", "--user", "start", "heim-pc-home-hygiene.service"])
            result = _run(
                [
                    "systemctl",
                    "--user",
                    "show",
                    "heim-pc-home-hygiene.service",
                    "--property=Result",
                    "--value",
                ]
            ).stdout.strip()
            if result != "success":
                raise InstallError(f"home hygiene service result is not success: {result!r}")
            systemd_state += "+inventory-started"

    receipt: dict[str, Any] = {
        "schema_version": 1,
        "kind": "heim_pc.home_hygiene_install_receipt",
        "generated_at_unix": int(time.time()),
        "repository_head": head,
        "repository_dirty": dirty,
        "release_root": str(release),
        "apply": apply,
        "enable": enable,
        "start": start,
        "planned": planned,
        "installed": installed,
        "directories": directories,
        "systemd": systemd_state,
        "unit_verification": unit_verification,
        "root_plan": _root_plan(policy, home=home, user_name=home.name),
        "does_not_establish": [
            "future_inventory_success",
            "root_plan_applied",
            "permission_to_quarantine_home_files",
            "permission_to_migrate_legacy_aliases",
        ],
    }
    receipt["receipt_sha256"] = _sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    if apply:
        receipt_path = (
            home
            / ".local/state/heim-pc/home-hygiene/install-receipts"
            / f"{head}.json"
        )
        _atomic_install(
            receipt_path,
            (json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
                "utf-8"
            ),
            0o600,
            home=home,
        )
        receipt["receipt_path"] = str(receipt_path)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument(
        "--release-root",
        type=Path,
        default=Path.home() / ".local/lib/heim-pc/home-hygiene/releases",
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
                {"kind": "heim_pc.home_hygiene_install_error", "error": str(exc)},
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
