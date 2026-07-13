#!/usr/bin/env python3
"""Install the canonical machine-readable heim-pc entry and local pointer files."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import stat as stat_module
import tempfile
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE_CONTRACT = ROOT / "manifest/operator-entry.v1.json"
SOURCE_AGENT_POINTER = ROOT / "config/agents/home-AGENTS.md"
SOURCE_REPOS_AGENT_POINTER = ROOT / "config/agents/repos-root-AGENTS.md"
SOURCE_README_POINTER = ROOT / "config/agents/home-README.md"
RECEIPT_RELATIVE_PATH = Path(".local/state/heim-pc/operator-entry-install-receipt.v1.json")
LOCK_RELATIVE_PATH = Path(".local/state/heim-pc/operator-entry-install.lock")
BACKUP_RELATIVE_PATH = Path(".local/state/heim-pc/operator-entry-backups")


class InstallConflict(RuntimeError):
    """Raised when an existing local projection differs without explicit replacement."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_existing(target: Path) -> bytes | None:
    if target.is_symlink():
        raise InstallConflict(f"refusing symlink target: {target}")
    if not target.exists():
        return None
    if not target.is_file():
        raise InstallConflict(f"refusing non-file target: {target}")
    return target.read_bytes()


def _assert_safe_target(home: Path, target: Path) -> None:
    resolved_home = home.resolve()
    try:
        target.resolve(strict=False).relative_to(resolved_home)
    except ValueError as exc:
        raise InstallConflict(f"target escapes home directory: {target}") from exc

    current = target.parent
    while current != resolved_home:
        if current.exists() and current.is_symlink():
            raise InstallConflict(f"refusing symlink parent: {current}")
        if current.parent == current:
            raise InstallConflict(f"cannot prove target is below home: {target}")
        current = current.parent


def _atomic_write(target: Path, value: bytes, mode: int, *, expected_before: bytes | None) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    current = _read_existing(target)
    if current != expected_before:
        raise InstallConflict(f"target changed after preflight: {target}")

    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.operator-entry-",
        dir=target.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        temporary.replace(target)
        directory_fd = os.open(target.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _no_follow_flags(base_flags: int) -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise InstallConflict("platform lacks O_NOFOLLOW; refusing security-sensitive installation")
    return base_flags | no_follow | getattr(os, "O_CLOEXEC", 0)


def _open_lock_file(lock_path: Path):
    if lock_path.is_symlink():
        raise InstallConflict(f"refusing symlink lock file: {lock_path}")
    try:
        descriptor = os.open(lock_path, _no_follow_flags(os.O_RDWR | os.O_CREAT), 0o600)
    except OSError as exc:
        raise InstallConflict(f"cannot safely open lock file {lock_path}: {exc}") from exc
    try:
        if not stat_module.S_ISREG(os.fstat(descriptor).st_mode):
            raise InstallConflict(f"lock path is not a regular file: {lock_path}")
        os.fchmod(descriptor, 0o600)
        return os.fdopen(descriptor, "r+b")
    except Exception:
        os.close(descriptor)
        raise


def _chmod_unchanged_regular(target: Path, expected_bytes: bytes, mode: int) -> None:
    try:
        descriptor = os.open(target, _no_follow_flags(os.O_RDONLY))
    except OSError as exc:
        raise InstallConflict(f"cannot safely reopen unchanged target {target}: {exc}") from exc
    try:
        if not stat_module.S_ISREG(os.fstat(descriptor).st_mode):
            raise InstallConflict(f"unchanged target is not a regular file: {target}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            if handle.read() != expected_bytes:
                raise InstallConflict(f"target changed after preflight: {target}")
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def _backup_path(home: Path, target: Path, before_sha256: str) -> Path:
    relative = target.relative_to(home)
    safe_name = "__".join(relative.parts)
    return home / BACKUP_RELATIVE_PATH / f"{safe_name}.{before_sha256[:12]}.bak"


def _plan(home: Path) -> list[dict[str, Any]]:
    mappings = [
        (SOURCE_CONTRACT, home / ".config/heimgewebe/operator-entry.v1.json", 0o644),
        (SOURCE_AGENT_POINTER, home / "AGENTS.md", 0o644),
        (SOURCE_REPOS_AGENT_POINTER, home / "repos/AGENTS.md", 0o644),
        (SOURCE_README_POINTER, home / "README.md", 0o644),
    ]
    plan: list[dict[str, Any]] = []
    for source, target, mode in mappings:
        _assert_safe_target(home, target)
        source_bytes = source.read_bytes()
        before_bytes = _read_existing(target)
        before_sha256 = _sha256_bytes(before_bytes) if before_bytes is not None else None
        after_sha256 = _sha256_bytes(source_bytes)
        action = "unchanged" if before_bytes == source_bytes else "install"
        plan.append(
            {
                "source": source,
                "target": target,
                "mode": mode,
                "sourceBytes": source_bytes,
                "beforeBytes": before_bytes,
                "beforeSha256": before_sha256,
                "afterSha256": after_sha256,
                "action": action,
                "requiresReplacement": before_bytes is not None and before_bytes != source_bytes,
            }
        )
    return plan


def _public_item(item: dict[str, Any], *, backup: Path | None = None) -> dict[str, Any]:
    return {
        "source": str(item["source"]),
        "target": str(item["target"]),
        "mode": oct(item["mode"]),
        "action": item["action"],
        "requiresReplacement": item["requiresReplacement"],
        "beforeSha256": item["beforeSha256"],
        "afterSha256": item["afterSha256"],
        "backup": str(backup) if backup is not None else None,
    }


def _validate_source_contract() -> None:
    contract = json.loads(SOURCE_CONTRACT.read_text(encoding="utf-8"))
    if contract.get("kind") != "heim_pc_operator_entry" or contract.get("schemaVersion") != 1:
        raise ValueError("operator entry source has an unsupported kind or schemaVersion")
    path_resolution = contract.get("pathResolution", {})
    if path_resolution.get("publicTemplateContainsResolvedHostPath") is not False:
        raise ValueError("operator entry source must declare unresolved public host paths")


def install(*, home: Path, apply: bool, replace_existing: bool = False) -> dict[str, Any]:
    home = home.expanduser().resolve()
    if not home.is_dir():
        raise ValueError(f"home directory does not exist: {home}")
    _validate_source_contract()

    if not apply:
        plan = _plan(home)
        return {
            "schemaVersion": 1,
            "kind": "heim_pc_operator_entry_install_plan",
            "apply": False,
            "replaceExisting": replace_existing,
            "home": str(home),
            "sourceContractSha256": _sha256_bytes(SOURCE_CONTRACT.read_bytes()),
            "requiresReplaceExisting": any(item["requiresReplacement"] for item in plan),
            "files": [_public_item(item) for item in plan],
            "doesNotEstablish": [
                "filesystem_mutation",
                "grabowski_runtime_health",
                "connector_snapshot_freshness",
                "systemkatalog_semantic_truth",
                "task_priority",
            ],
        }

    state_root = home / ".local/state/heim-pc"
    _assert_safe_target(home, state_root / "placeholder")
    state_root.mkdir(parents=True, exist_ok=True)
    lock_path = home / LOCK_RELATIVE_PATH
    _assert_safe_target(home, lock_path)
    with _open_lock_file(lock_path) as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        plan = _plan(home)
        conflicts = [str(item["target"]) for item in plan if item["requiresReplacement"]]
        if conflicts and not replace_existing:
            raise InstallConflict(
                "existing projections differ; rerun with --replace-existing after reviewing the plan: "
                + ", ".join(conflicts)
            )

        public_files: list[dict[str, Any]] = []
        for item in plan:
            backup: Path | None = None
            if item["action"] == "install":
                if item["beforeBytes"] is not None:
                    backup = _backup_path(home, item["target"], item["beforeSha256"])
                    _assert_safe_target(home, backup)
                    backup.parent.mkdir(parents=True, exist_ok=True)
                    existing_backup = _read_existing(backup)
                    if existing_backup is None:
                        _atomic_write(backup, item["beforeBytes"], 0o600, expected_before=None)
                    elif existing_backup != item["beforeBytes"]:
                        raise InstallConflict(f"backup path contains different data: {backup}")
                _atomic_write(
                    item["target"],
                    item["sourceBytes"],
                    item["mode"],
                    expected_before=item["beforeBytes"],
                )
            else:
                _chmod_unchanged_regular(item["target"], item["sourceBytes"], item["mode"])
            public_files.append(_public_item(item, backup=backup))

        receipt_path = home / RECEIPT_RELATIVE_PATH
        _assert_safe_target(home, receipt_path)
        receipt = {
            "schemaVersion": 1,
            "kind": "heim_pc_operator_entry_install_receipt",
            "valid": True,
            "apply": True,
            "replaceExisting": replace_existing,
            "installedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "home": str(home),
            "sourceContractSha256": _sha256_bytes(SOURCE_CONTRACT.read_bytes()),
            "receiptPath": str(receipt_path),
            "transaction": {
                "serializedByLock": str(lock_path),
                "preconditionBound": True,
                "perFileAtomic": True,
                "crossFileAtomicityClaimed": False,
            },
            "files": public_files,
            "doesNotEstablish": [
                "grabowski_runtime_health",
                "connector_snapshot_freshness",
                "systemkatalog_semantic_truth",
                "task_priority",
            ],
        }
        receipt_bytes = (json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
        receipt_before = _read_existing(receipt_path)
        _atomic_write(receipt_path, receipt_bytes, 0o600, expected_before=receipt_before)
        return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--replace-existing",
        action="store_true",
        help="replace differing existing projections after backing them up",
    )
    args = parser.parse_args()
    try:
        receipt = install(
            home=args.home,
            apply=args.apply,
            replace_existing=args.replace_existing,
        )
    except InstallConflict as exc:
        print(
            json.dumps(
                {"kind": "heim_pc_operator_entry_install_conflict", "error": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(
            json.dumps(
                {"kind": "heim_pc_operator_entry_install_error", "error": str(exc)},
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
