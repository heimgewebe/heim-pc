#!/usr/bin/env python3
"""Install the canonical machine-readable heim-pc entry and local pointer files."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import stat as stat_module
import subprocess
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
SOURCE_MANAGED_BUILD = ROOT / "scripts/managed_build.py"
SOURCE_STORAGE_INVENTORY = ROOT / "scripts/storage_inventory.py"
SOURCE_MANAGED_BUILD_POLICY = ROOT / "config/managed-build.v1.json"
INSTALLED_MANAGED_BUILD_ROOT = Path(".local/lib/heim-pc/managed-build")
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
        (
            SOURCE_MANAGED_BUILD,
            home / INSTALLED_MANAGED_BUILD_ROOT / "scripts/managed_build.py",
            0o755,
        ),
        (
            SOURCE_STORAGE_INVENTORY,
            home / INSTALLED_MANAGED_BUILD_ROOT / "scripts/storage_inventory.py",
            0o755,
        ),
        (
            SOURCE_MANAGED_BUILD_POLICY,
            home / INSTALLED_MANAGED_BUILD_ROOT / "config/managed-build.v1.json",
            0o644,
        ),
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


def _validate_source_contract(source_bytes: bytes | None = None) -> None:
    contract = json.loads(SOURCE_CONTRACT.read_bytes() if source_bytes is None else source_bytes)
    if contract.get("kind") != "heim_pc_operator_entry" or contract.get("schemaVersion") != 1:
        raise ValueError("operator entry source has an unsupported kind or schemaVersion")
    path_resolution = contract.get("pathResolution", {})
    if path_resolution.get("publicTemplateContainsResolvedHostPath") is not False:
        raise ValueError("operator entry source must declare unresolved public host paths")


def _canonical_git(*argv: str) -> bytes:
    # Do not let caller-provided Git environment or repository hooks select a
    # different source. This checks local canonical refs; it never fetches.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    })
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "-c", "core.fsmonitor=false",
             "-c", "core.hooksPath=" + os.devnull, *argv],
            env=env, capture_output=True, check=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallConflict("cannot establish canonical Git source") from exc
    return result.stdout


def _convergence_source(home: Path, plan: list[dict[str, Any]]) -> str:
    """Bind the proposed bytes to the clean canonical local main checkout."""
    if ROOT != home / "repos/heim-pc":
        raise InstallConflict("automatic convergence requires the canonical heim-pc checkout")
    if _canonical_git("rev-parse", "--show-toplevel").decode().strip() != str(ROOT):
        raise InstallConflict("unexpected canonical Git worktree")
    origin = _canonical_git("config", "--local", "--get", "remote.origin.url").decode().strip()
    if origin not in {
        "https://github.com/heimgewebe/heim-pc",
        "https://github.com/heimgewebe/heim-pc.git",
        "git@github.com:heimgewebe/heim-pc.git",
        "ssh://git@github.com/heimgewebe/heim-pc.git",
    }:
        raise InstallConflict("unexpected canonical Git origin")
    if _canonical_git("symbolic-ref", "--short", "HEAD").strip() != b"main":
        raise InstallConflict("automatic convergence requires main")
    head = _canonical_git("rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    if (
        _canonical_git("rev-parse", "--verify", "refs/remotes/origin/main^{commit}").decode().strip()
        != head
        or _canonical_git("status", "--porcelain", "--untracked-files=no")
    ):
        raise InstallConflict("canonical main is dirty or does not match local origin/main")
    # Use the frozen plan bytes, not a second read of mutable working files.
    _validate_source_contract(plan[0]["sourceBytes"])
    for item in plan:
        source = item["source"]
        relative = source.relative_to(ROOT).as_posix()
        if source.resolve() != source or not source.is_file():
            raise InstallConflict(f"unexpected source file: {source}")
        if _canonical_git("cat-file", "blob", f"{head}:{relative}") != item["sourceBytes"]:
            raise InstallConflict(f"source differs from the canonical commit: {relative}")
    if _canonical_git("rev-parse", "--verify", "HEAD^{commit}").decode().strip() != head:
        raise InstallConflict("canonical source changed during preflight")
    if _canonical_git("rev-parse", "--verify", "refs/remotes/origin/main^{commit}").decode().strip() != head:
        raise InstallConflict("canonical tracking ref changed during preflight")
    return head


def _convergence_preimage(home: Path, plan: list[dict[str, Any]]) -> tuple[dict[str, Any], bytes]:
    """Only replace projections previously installed by this managed installer."""
    receipt_path = home / RECEIPT_RELATIVE_PATH
    _assert_safe_target(home, receipt_path)
    raw = _read_existing(receipt_path)
    if raw is None:
        raise InstallConflict("automatic convergence requires an existing installation receipt")
    try:
        prior = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise InstallConflict("invalid previous installation receipt") from exc
    if (
        not isinstance(prior, dict)
        or prior.get("schemaVersion") != 1
        or prior.get("kind") != "heim_pc_operator_entry_install_receipt"
        or prior.get("valid") is not True
        or prior.get("apply") is not True
        or prior.get("home") != str(home)
        or prior.get("receiptPath") != str(receipt_path)
        or not isinstance(prior.get("files"), list)
    ):
        raise InstallConflict("invalid previous installation receipt")
    by_target = {}
    for entry in prior["files"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("target"), str):
            raise InstallConflict("invalid previous installation receipt file binding")
        if entry["target"] in by_target:
            raise InstallConflict("duplicate previous installation receipt target")
        by_target[entry["target"]] = entry
    if set(by_target) != {str(item["target"]) for item in plan}:
        raise InstallConflict("managed projection set changed; review the explicit installer plan")
    for item in plan:
        entry = by_target[str(item["target"])]
        digest = entry.get("afterSha256")
        if (
            entry.get("source") != str(item["source"])
            or entry.get("mode") != oct(item["mode"])
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise InstallConflict("invalid previous installation receipt file binding")
        # A partial previous install may already have reached the new bytes.
        # Neither an unrelated edit nor a deletion is an implicit replacement mandate.
        if item["beforeSha256"] not in (digest, item["afterSha256"]):
            raise InstallConflict(f"managed projection has an unknown preimage: {item['target']}")
        if stat_module.S_IMODE(item["target"].stat().st_mode) != item["mode"]:
            raise InstallConflict(f"managed projection has an unexpected mode: {item['target']}")
    if prior.get("sourceContractSha256") != by_target[str(plan[0]["target"])]["afterSha256"]:
        raise InstallConflict("previous receipt contract digest does not match its file binding")
    return prior, raw


def install(
    *, home: Path, apply: bool, replace_existing: bool = False, converge: bool = False
) -> dict[str, Any]:
    home = home.expanduser().resolve()
    if not home.is_dir():
        raise ValueError(f"home directory does not exist: {home}")
    _validate_source_contract()
    if converge and replace_existing:
        raise InstallConflict("automatic convergence cannot be combined with --replace-existing")

    if not apply:
        plan = _plan(home)
        source_commit = _convergence_source(home, plan) if converge else None
        if converge:
            _convergence_preimage(home, plan)
        return {
            "schemaVersion": 1,
            "kind": "heim_pc_operator_entry_install_plan",
            "apply": False,
            "replaceExisting": replace_existing,
            "home": str(home),
            "sourceContractSha256": plan[0]["afterSha256"],
            **({"convergenceSourceCommit": source_commit} if converge else {}),
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
        source_commit = _convergence_source(home, plan) if converge else None
        prior_receipt, prior_bytes = _convergence_preimage(home, plan) if converge else (None, None)
        if converge and prior_receipt is not None and all(
            item["action"] == "unchanged" for item in plan
        ):
            old_digests = {entry["target"]: entry["afterSha256"] for entry in prior_receipt["files"]}
            if all(old_digests[str(item["target"])] == item["afterSha256"] for item in plan):
                return {
                    **prior_receipt,
                    "convergence": {"status": "unchanged", "sourceCommit": source_commit},
                }
        conflicts = [str(item["target"]) for item in plan if item["requiresReplacement"]]
        if conflicts and not (replace_existing or converge):
            raise InstallConflict(
                "existing projections differ; rerun with --replace-existing after reviewing the plan: "
                + ", ".join(conflicts)
            )

        if converge and _read_existing(home / RECEIPT_RELATIVE_PATH) != prior_bytes:
            raise InstallConflict("previous receipt changed after preflight")
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

        if converge:
            for item in plan:
                if (
                    _read_existing(item["target"]) != item["sourceBytes"]
                    or stat_module.S_IMODE(item["target"].stat().st_mode) != item["mode"]
                ):
                    raise InstallConflict(f"projection readback differs: {item['target']}")
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
            "sourceContractSha256": plan[0]["afterSha256"],
            **({"convergence": {"status": "applied", "sourceCommit": source_commit}} if converge else {}),
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
        receipt_before = prior_bytes if converge else _read_existing(receipt_path)
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
    parser.add_argument(
        "--converge",
        action="store_true",
        help="converge previously installed projections from clean canonical main; reject unknown edits",
    )
    args = parser.parse_args()
    try:
        receipt = install(
            home=args.home,
            apply=args.apply,
            replace_existing=args.replace_existing,
            converge=args.converge,
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
