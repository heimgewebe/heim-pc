#!/usr/bin/env python3
"""Inventory and maintain the Heim-PC home root through guarded lifecycle plans."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = ROOT / "config/home-hygiene.v1.json"
INVENTORY_KIND = "heim_pc.home_hygiene_inventory"
QUARANTINE_PLAN_KIND = "heim_pc.home_hygiene_quarantine_plan"
QUARANTINE_RECEIPT_KIND = "heim_pc.home_hygiene_quarantine_receipt"
ALIAS_PLAN_KIND = "heim_pc.home_hygiene_alias_plan"
ALIAS_RECEIPT_KIND = "heim_pc.home_hygiene_alias_receipt"
CORE_RECEIPT_KIND = "heim_pc.coredump_retention_receipt"
QUARANTINE_CONFIRMATION = "apply-home-quarantine"
ALIAS_CONFIRMATION = "apply-home-alias-migration"
MAX_TREE_ENTRIES = 200_000


class HygieneError(RuntimeError):
    """Raised when a home-hygiene operation cannot be proven safe."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(_canonical_json(value))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise HygieneError(f"unsafe receipt directory: {path.parent}")
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _path_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _rename_noreplace(source: Path, target: Path) -> None:
    """Atomically rename one entry without ever replacing an existing target."""
    if sys.platform != "linux":
        raise HygieneError("atomic no-replace rename requires Linux renameat2")
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as exc:
        raise HygieneError("atomic no-replace rename is unavailable") from exc
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = renameat2(
        -100,  # AT_FDCWD
        os.fsencode(source),
        -100,  # AT_FDCWD
        os.fsencode(target),
        1,  # RENAME_NOREPLACE
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise HygieneError(f"alias merge collision appeared: {target}")
    if error in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
        raise HygieneError(
            f"atomic no-replace rename is unavailable for {source} -> {target}"
        )
    raise OSError(error, os.strerror(error), str(source))


def _expand_home(value: Any, home: Path, *, label: str) -> Path:
    if not isinstance(value, str) or not value.startswith("${HOME}"):
        raise HygieneError(f"{label} must be HOME-rooted")
    suffix = value.removeprefix("${HOME}")
    if suffix and not suffix.startswith("/"):
        raise HygieneError(f"{label} has an invalid HOME suffix")
    path = home / suffix.removeprefix("/")
    normalized = Path(os.path.normpath(path))
    if not _path_within(normalized, home) and normalized != home:
        raise HygieneError(f"{label} escapes HOME")
    return normalized


def _required_int(value: Any, *, label: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise HygieneError(f"{label} must be an integer >= {minimum}")
    return value


def load_policy(path: Path, *, home: Path) -> dict[str, Any]:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HygieneError(f"cannot load policy: {exc}") from exc
    if policy.get("schema_version") != 1:
        raise HygieneError("unsupported home-hygiene schema_version")
    if policy.get("kind") != "heim_pc.home_hygiene_policy":
        raise HygieneError("invalid home-hygiene policy kind")
    expected_home = _expand_home(policy.get("home_root"), home, label="home_root")
    if expected_home != home:
        raise HygieneError("policy home_root does not match selected HOME")
    state_root = _expand_home(policy.get("state_root"), home, label="state_root")
    artifact_root = _expand_home(policy.get("artifact_root"), home, label="artifact_root")
    if state_root == home or artifact_root == home:
        raise HygieneError("state_root and artifact_root must be below HOME")

    allowed = policy.get("allowed_visible_top_level")
    if (
        not isinstance(allowed, list)
        or any(not isinstance(item, str) or not item or "/" in item for item in allowed)
        or len(set(allowed)) != len(allowed)
    ):
        raise HygieneError("allowed_visible_top_level is invalid")

    categories = policy.get("artifact_categories")
    if not isinstance(categories, dict) or not categories:
        raise HygieneError("artifact_categories must be a non-empty object")
    for key, value in categories.items():
        if (
            not isinstance(key, str)
            or not isinstance(value, str)
            or not value
            or Path(value).is_absolute()
            or ".." in Path(value).parts
        ):
            raise HygieneError("artifact category is invalid")

    aliases = policy.get("legacy_artifact_roots")
    if not isinstance(aliases, list):
        raise HygieneError("legacy_artifact_roots must be a list")
    alias_sources: set[str] = set()
    for index, item in enumerate(aliases):
        if not isinstance(item, dict) or set(item) != {
            "source",
            "category",
            "compatibility_symlink",
            "merge_existing",
            "allow_internal_symlinks",
        }:
            raise HygieneError(f"legacy_artifact_roots[{index}] is invalid")
        source = item["source"]
        if (
            not isinstance(source, str)
            or not source
            or "/" in source
            or source.startswith(".")
            or source in alias_sources
        ):
            raise HygieneError(f"legacy alias source is invalid: {source!r}")
        alias_sources.add(source)
        if item["category"] not in categories:
            raise HygieneError(f"legacy alias category is unknown: {item['category']}")
        for flag in ("compatibility_symlink", "merge_existing", "allow_internal_symlinks"):
            if not isinstance(item[flag], bool):
                raise HygieneError(f"{flag} must be boolean")

    loose = policy.get("loose_file_rules")
    if not isinstance(loose, dict):
        raise HygieneError("loose_file_rules must be an object")
    for field in (
        "minimum_age_seconds",
        "max_candidates_per_plan",
        "max_bytes_per_plan",
        "full_hash_max_bytes",
    ):
        minimum = 1 if field == "max_candidates_per_plan" else 0
        _required_int(loose.get(field), label=f"loose_file_rules.{field}", minimum=minimum)
    patterns = loose.get("patterns")
    if not isinstance(patterns, list) or not patterns:
        raise HygieneError("loose_file_rules.patterns must be non-empty")
    for pattern in patterns:
        if not isinstance(pattern, str):
            raise HygieneError("loose file pattern must be text")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise HygieneError(f"invalid loose file pattern: {pattern}") from exc
    never = loose.get("never_quarantine")
    if not isinstance(never, list) or any(not isinstance(item, str) for item in never):
        raise HygieneError("never_quarantine must be a text list")

    coredumps = policy.get("coredumps")
    if not isinstance(coredumps, dict):
        raise HygieneError("coredumps must be an object")
    core_directory = _expand_home(coredumps.get("directory"), home, label="coredumps.directory")
    if core_directory == home:
        raise HygieneError("coredump directory must be below HOME")
    kernel_pattern = coredumps.get("kernel_pattern")
    if not isinstance(kernel_pattern, str) or not kernel_pattern.startswith("${HOME}/"):
        raise HygieneError("coredumps.kernel_pattern must be HOME-rooted")
    _expand_home(kernel_pattern.split("%", 1)[0].rstrip("."), home, label="coredumps.kernel_pattern")
    for field in (
        "per_file_limit_bytes",
        "max_total_bytes",
        "minimum_settled_seconds",
        "retention_seconds",
    ):
        _required_int(coredumps.get(field), label=f"coredumps.{field}", minimum=1)
    if coredumps.get("automatic_retention_authorized") is not True:
        raise HygieneError("automatic core retention must be explicitly authorized")
    if not isinstance(coredumps.get("cleanup_confirmation"), str) or not coredumps["cleanup_confirmation"]:
        raise HygieneError("coredumps.cleanup_confirmation is required")

    safety = policy.get("safety")
    expected_safety = {
        "automatic_home_root_mutation": False,
        "automatic_quarantine": False,
        "automatic_alias_migration": False,
        "weekly_inventory_read_only": True,
        "require_same_filesystem_moves": True,
        "reject_symlinks": True,
        "reject_open_process_references": True,
    }
    if not isinstance(safety, dict):
        raise HygieneError("safety must be an object")
    for key, expected in expected_safety.items():
        if safety.get(key) is not expected:
            raise HygieneError(f"safety.{key} must remain {str(expected).lower()}")

    policy["_resolved"] = {
        "home": home,
        "state_root": state_root,
        "artifact_root": artifact_root,
        "core_directory": core_directory,
    }
    policy["_policy_sha256"] = _sha256_json(
        {key: value for key, value in policy.items() if not key.startswith("_")}
    )
    return policy


def _ensure_owned_directory(path: Path, *, home: Path, create: bool) -> None:
    if not _path_within(path, home) or path == home:
        raise HygieneError(f"directory is outside the permitted HOME subtree: {path}")
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise HygieneError(f"directory is not owner-controlled: {path}")


def _file_observation(path: Path, *, hash_limit: int) -> dict[str, Any]:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise HygieneError(f"candidate is not a regular non-symlink file: {path}")
    observation: dict[str, Any] = {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size_bytes": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "mode": stat.S_IMODE(metadata.st_mode),
    }
    observation["content_sha256"] = (
        _sha256_file(path) if metadata.st_size <= hash_limit else None
    )
    observation["identity_sha256"] = _sha256_json(observation)
    return observation


def _safe_internal_symlink_observation(
    path: Path, *, root: Path, allow_absolute: bool = False
) -> dict[str, Any]:
    metadata = path.lstat()
    if not stat.S_ISLNK(metadata.st_mode):
        raise HygieneError(f"legacy artifact entry is not a symlink: {path}")
    target = os.readlink(path)
    target_is_absolute = os.path.isabs(target)
    if target_is_absolute and not allow_absolute:
        raise HygieneError(f"legacy artifact symlink is absolute: {path}")
    try:
        root_resolved = root.resolve(strict=True)
        resolved = path.resolve(strict=True)
    except (FileNotFoundError, RuntimeError, OSError) as exc:
        raise HygieneError(f"legacy artifact symlink is dangling or unresolvable: {path}") from exc
    if not _path_within(resolved, root_resolved):
        raise HygieneError(f"legacy artifact symlink escapes its root: {path}")
    root_device = root.lstat().st_dev
    if resolved.stat().st_dev != root_device:
        raise HygieneError(f"legacy artifact symlink crosses a device boundary: {path}")
    observation: dict[str, Any] = {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size_bytes": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "mode": stat.S_IMODE(metadata.st_mode),
        "target": target,
        "target_is_absolute": target_is_absolute,
        "resolved_relative": resolved.relative_to(root_resolved).as_posix(),
    }
    observation["identity_sha256"] = _sha256_json(observation)
    return observation


def _tree_observation(
    path: Path,
    *,
    allow_internal_symlinks: bool = False,
    symlink_root: Path | None = None,
    allow_absolute_internal_symlinks: bool = False,
) -> dict[str, Any]:
    root_metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
        raise HygieneError(f"legacy artifact root is not a real directory: {path}")
    root_device = root_metadata.st_dev
    link_root = path if symlink_root is None else symlink_root
    if link_root.is_symlink() or not link_root.is_dir():
        raise HygieneError(f"legacy artifact symlink boundary is unsafe: {link_root}")
    rows: list[list[Any]] = []
    allocated = 0
    stack = [path]
    while stack:
        current = stack.pop()
        metadata = current.lstat()
        relative = "." if current == path else current.relative_to(path).as_posix()
        if metadata.st_dev != root_device:
            raise HygieneError(f"legacy artifact tree crosses a device boundary: {current}")
        if stat.S_ISLNK(metadata.st_mode):
            if not allow_internal_symlinks:
                raise HygieneError(f"legacy artifact tree contains a symlink: {current}")
            symlink_observation = _safe_internal_symlink_observation(
                current,
                root=link_root,
                allow_absolute=allow_absolute_internal_symlinks,
            )
            rows.append(
                [
                    relative,
                    stat.S_IFLNK,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    symlink_observation["target"],
                    symlink_observation["target_is_absolute"],
                    symlink_observation["resolved_relative"],
                ]
            )
            if len(rows) > MAX_TREE_ENTRIES:
                raise HygieneError(f"legacy artifact tree exceeds {MAX_TREE_ENTRIES} entries")
            continue
        mode_type = stat.S_IFMT(metadata.st_mode)
        rows.append([relative, mode_type, metadata.st_size, metadata.st_mtime_ns])
        if len(rows) > MAX_TREE_ENTRIES:
            raise HygieneError(f"legacy artifact tree exceeds {MAX_TREE_ENTRIES} entries")
        if stat.S_ISREG(metadata.st_mode):
            allocated += metadata.st_blocks * 512
        elif stat.S_ISDIR(metadata.st_mode):
            with os.scandir(current) as entries:
                children = sorted((Path(entry.path) for entry in entries), reverse=True)
            stack.extend(children)
        else:
            raise HygieneError(f"legacy artifact tree contains an unsupported entry: {current}")
    return {
        "device": root_device,
        "inode": root_metadata.st_ino,
        "size_bytes": root_metadata.st_size,
        "mtime_ns": root_metadata.st_mtime_ns,
        "mode": stat.S_IMODE(root_metadata.st_mode),
        "entry_count": len(rows),
        "allocated_bytes": allocated,
        "tree_sha256": _sha256_json(rows),
    }


def _alias_entry_observation(
    path: Path,
    *,
    source_root: Path,
    allow_internal_symlinks: bool,
    allow_absolute_internal_symlinks: bool,
    hash_limit: int,
) -> dict[str, Any]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        if not allow_internal_symlinks:
            raise HygieneError(f"legacy artifact tree contains a symlink: {path}")
        return {
            "kind": "symlink",
            "observation": _safe_internal_symlink_observation(
                path,
                root=source_root,
                allow_absolute=allow_absolute_internal_symlinks,
            ),
        }
    if stat.S_ISREG(metadata.st_mode):
        return {"kind": "file", "observation": _file_observation(path, hash_limit=hash_limit)}
    if stat.S_ISDIR(metadata.st_mode):
        return {
            "kind": "directory",
            "observation": _tree_observation(
                path,
                allow_internal_symlinks=allow_internal_symlinks,
                symlink_root=source_root,
                allow_absolute_internal_symlinks=allow_absolute_internal_symlinks,
            ),
        }
    raise HygieneError(f"legacy artifact tree contains an unsupported entry: {path}")

def _alias_entry_lstat_matches(path: Path, planned: dict[str, Any]) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    observation = planned["observation"]
    actual = {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size_bytes": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "mode": stat.S_IMODE(metadata.st_mode),
    }
    if any(actual[key] != observation.get(key) for key in actual):
        return False
    kind = planned["kind"]
    if kind == "symlink":
        return stat.S_ISLNK(metadata.st_mode) and os.readlink(path) == observation.get("target")
    if kind == "file":
        return stat.S_ISREG(metadata.st_mode) and not path.is_symlink()
    if kind == "directory":
        return stat.S_ISDIR(metadata.st_mode) and not path.is_symlink()
    return False


def _mapped_file_targets(lines: Iterable[str]) -> list[Path]:
    targets: list[Path] = []
    for line in lines:
        fields = line.split(maxsplit=5)
        if len(fields) != 6:
            continue
        target_text = fields[5]
        if target_text.endswith(" (deleted)"):
            target_text = target_text[: -len(" (deleted)")]
        if target_text.startswith("/"):
            targets.append(Path(target_text))
    return targets


def _process_references(paths: Iterable[Path]) -> tuple[dict[str, list[int]], list[str]]:
    roots = {str(path): path for path in paths}
    references: dict[str, set[int]] = {key: set() for key in roots}
    errors: list[str] = []
    uid = os.getuid()
    try:
        processes = sorted(
            (item for item in Path("/proc").iterdir() if item.name.isdigit()),
            key=lambda item: int(item.name),
        )
    except OSError as exc:
        return {}, [f"cannot enumerate process table: {type(exc).__name__}"]

    def record_target(pid: int, target: Path) -> None:
        target_text = str(target)
        for key, root in roots.items():
            root_text = str(root)
            if target_text == root_text or target_text.startswith(root_text + os.sep):
                references[key].add(pid)

    for process in processes:
        try:
            if process.stat().st_uid != uid:
                continue
        except (FileNotFoundError, PermissionError):
            continue
        pid = int(process.name)
        for special in ("cwd", "root", "exe"):
            try:
                target = Path(os.readlink(process / special))
            except FileNotFoundError:
                continue
            except PermissionError:
                errors.append(f"cannot inspect {special} for same-user process {pid}")
                continue
            except OSError:
                continue
            record_target(pid, target)
        fd_root = process / "fd"
        try:
            descriptors = list(fd_root.iterdir())
        except FileNotFoundError:
            continue
        except PermissionError:
            errors.append(f"cannot inspect file descriptors for same-user process {pid}")
            descriptors = []
        except OSError:
            descriptors = []
        for descriptor in descriptors:
            try:
                target_text = os.readlink(descriptor)
            except OSError:
                continue
            if target_text.endswith(" (deleted)"):
                target_text = target_text[: -len(" (deleted)")]
            if target_text.startswith("/"):
                record_target(pid, Path(target_text))
        try:
            map_lines = (process / "maps").read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        except FileNotFoundError:
            continue
        except PermissionError:
            errors.append(f"cannot inspect memory maps for same-user process {pid}")
        except OSError:
            pass
        else:
            for target in _mapped_file_targets(map_lines):
                record_target(pid, target)
    return (
        {key: sorted(pids) for key, pids in references.items() if pids},
        sorted(set(errors)),
    )


def _matches_loose_rule(name: str, policy: dict[str, Any]) -> bool:
    loose = policy["loose_file_rules"]
    if name in set(loose["never_quarantine"]):
        return False
    return any(re.fullmatch(pattern, name) for pattern in loose["patterns"])


def inventory(
    policy: dict[str, Any], *, home: Path, now_unix: int | None = None
) -> dict[str, Any]:
    now = int(time.time()) if now_unix is None else now_unix
    _ensure_owned_directory(home, home=home.parent, create=False)
    allowed = set(policy["allowed_visible_top_level"])
    aliases = {item["source"] for item in policy["legacy_artifact_roots"]}
    hash_limit = policy["loose_file_rules"]["full_hash_max_bytes"]
    entries: list[dict[str, Any]] = []
    loose_candidates: list[dict[str, Any]] = []
    unexpected: list[dict[str, Any]] = []
    for path in sorted(home.iterdir(), key=lambda item: item.name.casefold()):
        name = path.name
        if name.startswith("."):
            continue
        metadata = path.lstat()
        entry_type = (
            "symlink"
            if path.is_symlink()
            else "directory"
            if stat.S_ISDIR(metadata.st_mode)
            else "file"
            if stat.S_ISREG(metadata.st_mode)
            else "other"
        )
        classification = "allowed" if name in allowed else "legacy_alias" if name in aliases else "unexpected"
        record: dict[str, Any] = {
            "name": name,
            "path": str(path),
            "type": entry_type,
            "classification": classification,
            "size_bytes": metadata.st_size,
            "mtime_ns": metadata.st_mtime_ns,
        }
        if entry_type == "file" and _matches_loose_rule(name, policy):
            record["classification"] = "loose_candidate"
            record["observation"] = _file_observation(path, hash_limit=hash_limit)
            loose_candidates.append(record)
        elif classification == "unexpected":
            unexpected.append(record)
        entries.append(record)

    core_directory: Path = policy["_resolved"]["core_directory"]
    core_entries: list[dict[str, Any]] = []
    core_observation_warnings: list[str] = []
    if core_directory.exists():
        _ensure_owned_directory(core_directory, home=home, create=False)
        for path in sorted(core_directory.iterdir(), key=lambda item: item.name):
            if not path.name.startswith("core."):
                continue
            try:
                observation = _file_observation(path, hash_limit=0)
            except FileNotFoundError:
                core_observation_warnings.append(
                    f"core dump disappeared during inventory observation: {path}"
                )
                continue
            except HygieneError:
                continue
            core_entries.append(
                {
                    "path": str(path),
                    "name": path.name,
                    "size_bytes": observation["size_bytes"],
                    "mtime_ns": observation["mtime_ns"],
                    "age_seconds": max(0, now - observation["mtime_ns"] // 1_000_000_000),
                    "identity_sha256": observation["identity_sha256"],
                }
            )
    payload: dict[str, Any] = {
        "schema_version": 1,
        "kind": INVENTORY_KIND,
        "observed_at_unix": now,
        "home": str(home),
        "policy_sha256": policy["_policy_sha256"],
        "entries": entries,
        "loose_candidates": loose_candidates,
        "unexpected": unexpected,
        "coredumps": {
            "directory": str(core_directory),
            "count": len(core_entries),
            "total_bytes": sum(item["size_bytes"] for item in core_entries),
            "entries": core_entries,
            "observation_warnings": core_observation_warnings,
        },
        "summary": {
            "visible_top_level_count": len(entries),
            "allowed_count": sum(item["classification"] == "allowed" for item in entries),
            "legacy_alias_count": sum(item["classification"] == "legacy_alias" for item in entries),
            "loose_candidate_count": len(loose_candidates),
            "unexpected_count": len(unexpected),
            "automatic_home_root_mutation": False,
        },
        "does_not_establish": [
            "permission_to_move_or_delete",
            "absence_of_hidden_runtime_state",
            "backup_or_restore_readiness",
            "that_unexpected_entries_are_unused",
        ],
    }
    payload["inventory_sha256"] = _sha256_json(payload)
    return payload


def build_quarantine_plan(
    policy: dict[str, Any], *, home: Path, now_unix: int | None = None
) -> dict[str, Any]:
    now = int(time.time()) if now_unix is None else now_unix
    current = inventory(policy, home=home, now_unix=now)
    loose = policy["loose_file_rules"]
    candidates = sorted(
        current["loose_candidates"],
        key=lambda item: (item["mtime_ns"], item["name"]),
    )
    refs, errors = _process_references(Path(item["path"]) for item in candidates)
    artifact_root: Path = policy["_resolved"]["artifact_root"]
    category = policy["artifact_categories"]["legacy_home_root"]
    target_root = artifact_root / category / time.strftime("%Y-%m-%d", time.gmtime(now))
    selected: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    selected_bytes = 0
    for item in candidates:
        source = Path(item["path"])
        age = max(0, now - item["mtime_ns"] // 1_000_000_000)
        reason: str | None = None
        if age < loose["minimum_age_seconds"]:
            reason = "minimum_age_not_met"
        elif str(source) in refs:
            reason = "live_process_reference"
        elif len(selected) >= loose["max_candidates_per_plan"]:
            reason = "candidate_limit"
        elif selected_bytes + item["observation"]["size_bytes"] > loose["max_bytes_per_plan"]:
            reason = "byte_limit"
        target = target_root / source.name
        if reason is None and (target.exists() or target.is_symlink()):
            reason = "target_exists"
        if reason is not None:
            skipped.append(
                {
                    "source": str(source),
                    "reason": reason,
                    "process_ids": refs.get(str(source), []),
                }
            )
            continue
        selected.append(
            {
                "source": str(source),
                "target": str(target),
                "observation": item["observation"],
                "age_seconds": age,
            }
        )
        selected_bytes += item["observation"]["size_bytes"]
    plan: dict[str, Any] = {
        "schema_version": 1,
        "kind": QUARANTINE_PLAN_KIND,
        "created_at_unix": now,
        "home": str(home),
        "policy_sha256": policy["_policy_sha256"],
        "inventory_sha256": current["inventory_sha256"],
        "target_root": str(target_root),
        "candidates": selected,
        "planned_bytes": selected_bytes,
        "skipped": skipped,
        "process_observation_warnings": errors,
        "applicable": bool(selected),
        "confirmation": QUARANTINE_CONFIRMATION,
        "automatic_quarantine": False,
    }
    plan["plan_sha256"] = _sha256_json(plan)
    return plan


def _read_hashed_plan(path: Path, *, expected_kind: str) -> tuple[dict[str, Any], str]:
    if path.is_symlink() or not path.is_file():
        raise HygieneError("plan must be a regular non-symlink file")
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HygieneError(f"cannot read plan: {exc}") from exc
    if plan.get("schema_version") != 1 or plan.get("kind") != expected_kind:
        raise HygieneError("plan contract is incompatible")
    reported = plan.get("plan_sha256")
    core = {key: value for key, value in plan.items() if key != "plan_sha256"}
    actual = _sha256_json(core)
    if reported != actual:
        raise HygieneError("plan_sha256 is invalid")
    return plan, actual


def _validate_file_observation(path: Path, expected: dict[str, Any], *, hash_limit: int) -> None:
    actual = _file_observation(path, hash_limit=hash_limit)
    if actual != expected:
        raise HygieneError(f"file changed after planning: {path}")


def apply_quarantine(
    policy: dict[str, Any],
    *,
    home: Path,
    plan_path: Path,
    expected_plan_sha256: str,
    confirmation: str,
) -> dict[str, Any]:
    if confirmation != QUARANTINE_CONFIRMATION:
        raise HygieneError("quarantine confirmation is invalid")
    plan, actual_sha = _read_hashed_plan(plan_path, expected_kind=QUARANTINE_PLAN_KIND)
    if expected_plan_sha256 != actual_sha:
        raise HygieneError("expected_plan_sha256 does not match plan")
    if plan.get("home") != str(home) or plan.get("policy_sha256") != policy["_policy_sha256"]:
        raise HygieneError("quarantine plan is not bound to current HOME and policy")
    if plan.get("applicable") is not True or not plan.get("candidates"):
        raise HygieneError("quarantine plan has no applicable candidates")
    candidates = plan["candidates"]
    sources = [Path(item["source"]) for item in candidates]
    refs, errors = _process_references(sources)
    process_observation_warnings = sorted(
        set(plan.get("process_observation_warnings", []) + errors)
    )
    if refs:
        raise HygieneError("candidate acquired a live process reference before quarantine")
    target_root = Path(plan["target_root"])
    artifact_root: Path = policy["_resolved"]["artifact_root"]
    if not _path_within(target_root, artifact_root):
        raise HygieneError("quarantine target escapes artifact root")
    _ensure_owned_directory(artifact_root, home=home, create=True)
    _ensure_owned_directory(target_root, home=home, create=True)
    hash_limit = policy["loose_file_rules"]["full_hash_max_bytes"]
    for item in candidates:
        source = Path(item["source"])
        target = Path(item["target"])
        if source.parent != home or target.parent != target_root:
            raise HygieneError("quarantine candidate path binding is invalid")
        if target.exists() or target.is_symlink():
            raise HygieneError(f"quarantine target already exists: {target}")
        _validate_file_observation(source, item["observation"], hash_limit=hash_limit)
        if policy["safety"]["require_same_filesystem_moves"] and source.stat().st_dev != target_root.stat().st_dev:
            raise HygieneError("quarantine move would cross a filesystem boundary")

    moved: list[dict[str, Any]] = []
    failure: str | None = None
    for item in candidates:
        source = Path(item["source"])
        target = Path(item["target"])
        try:
            _validate_file_observation(
                source, item["observation"], hash_limit=hash_limit
            )
            if target.exists() or target.is_symlink():
                raise HygieneError(f"quarantine target appeared before move: {target}")
            os.replace(source, target)
            if source.exists() or source.is_symlink() or not target.is_file():
                raise HygieneError(f"quarantine readback failed for {source}")
            moved.append(item)
        except (OSError, HygieneError) as exc:
            failure = f"{type(exc).__name__}: {exc}"
            break

    applied_at_ns = time.time_ns()
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "kind": QUARANTINE_RECEIPT_KIND,
        "status": "success" if failure is None else "partial_failure",
        "applied_at_unix_ns": applied_at_ns,
        "plan_sha256": actual_sha,
        "policy_sha256": policy["_policy_sha256"],
        "moved": moved,
        "moved_bytes": sum(item["observation"]["size_bytes"] for item in moved),
        "failure": failure,
        "process_observation_warnings": process_observation_warnings,
        "remaining_count": len(candidates) - len(moved),
        "restoration": "move each target back to its recorded source after verifying the receipt",
    }
    receipt["receipt_sha256"] = _sha256_json(receipt)
    state_root: Path = policy["_resolved"]["state_root"]
    receipt_path = state_root / "quarantine-receipts" / f"{applied_at_ns}-{actual_sha[:16]}.json"
    _atomic_json(receipt_path, receipt)
    result = {
        "receipt_path": str(receipt_path),
        "receipt_file_sha256": _sha256_file(receipt_path),
        "receipt": receipt,
    }
    if failure is not None:
        raise HygieneError(f"quarantine had a partial effect; receipt={receipt_path}; error={failure}")
    return result


def build_alias_plan(
    policy: dict[str, Any], *, home: Path, now_unix: int | None = None
) -> dict[str, Any]:
    now = int(time.time()) if now_unix is None else now_unix
    artifact_root: Path = policy["_resolved"]["artifact_root"]
    categories = policy["artifact_categories"]
    hash_limit = policy["loose_file_rules"]["full_hash_max_bytes"]
    candidates: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    candidate_roots: list[Path] = []
    for alias in policy["legacy_artifact_roots"]:
        source = home / alias["source"]
        target = artifact_root / categories[alias["category"]]
        if source.is_symlink():
            skipped.append({"source": str(source), "reason": "already_symlinked"})
            continue
        if not source.exists():
            skipped.append({"source": str(source), "reason": "source_absent"})
            continue
        if not source.is_dir():
            skipped.append({"source": str(source), "reason": "source_not_directory"})
            continue
        if target.is_symlink() or (target.exists() and not target.is_dir()):
            skipped.append(
                {"source": str(source), "target": str(target), "reason": "unsafe_target"}
            )
            continue
        try:
            observation = _tree_observation(
                source,
                allow_internal_symlinks=alias["allow_internal_symlinks"],
                symlink_root=source,
                allow_absolute_internal_symlinks=(
                    alias["allow_internal_symlinks"]
                    and alias["compatibility_symlink"]
                ),
            )
        except HygieneError as exc:
            skipped.append(
                {
                    "source": str(source),
                    "target": str(target),
                    "reason": "unsafe_source_tree",
                    "detail": str(exc),
                }
            )
            continue

        target_nonempty = target.exists() and any(target.iterdir())
        mode = "replace"
        merge_entries: list[dict[str, Any]] = []
        if target_nonempty:
            if not alias["merge_existing"]:
                skipped.append(
                    {"source": str(source), "target": str(target), "reason": "target_not_empty"}
                )
                continue
            collision: str | None = None
            for child in sorted(source.iterdir(), key=lambda value: value.name):
                destination = target / child.name
                if destination.exists() or destination.is_symlink():
                    collision = child.name
                    break
                try:
                    child_observation = _alias_entry_observation(
                        child,
                        source_root=source,
                        allow_internal_symlinks=alias["allow_internal_symlinks"],
                        allow_absolute_internal_symlinks=(
                            alias["allow_internal_symlinks"]
                            and alias["compatibility_symlink"]
                        ),
                        hash_limit=hash_limit,
                    )
                except HygieneError as exc:
                    collision = f"unsafe:{child.name}:{exc}"
                    break
                merge_entries.append(
                    {
                        "name": child.name,
                        "source": str(child),
                        "target": str(destination),
                        **child_observation,
                    }
                )
            if collision is not None:
                skipped.append(
                    {
                        "source": str(source),
                        "target": str(target),
                        "reason": "target_collision",
                        "detail": collision,
                    }
                )
                continue
            mode = "merge"

        candidates.append(
            {
                "source": str(source),
                "target": str(target),
                "mode": mode,
                "compatibility_symlink": alias["compatibility_symlink"],
                "allow_internal_symlinks": alias["allow_internal_symlinks"],
                "allow_absolute_internal_symlinks": (
                    alias["allow_internal_symlinks"]
                    and alias["compatibility_symlink"]
                ),
                "observation": observation,
                "merge_entries": merge_entries,
            }
        )
        candidate_roots.append(source)
    refs, errors = _process_references(candidate_roots)
    filtered: list[dict[str, Any]] = []
    for item in candidates:
        pids = refs.get(item["source"], [])
        if pids:
            skipped.append(
                {
                    "source": item["source"],
                    "target": item["target"],
                    "reason": "live_process_reference",
                    "process_ids": pids,
                }
            )
        else:
            filtered.append(item)
    plan: dict[str, Any] = {
        "schema_version": 1,
        "kind": ALIAS_PLAN_KIND,
        "created_at_unix": now,
        "home": str(home),
        "policy_sha256": policy["_policy_sha256"],
        "artifact_root": str(artifact_root),
        "candidates": filtered,
        "skipped": sorted(skipped, key=lambda item: item["source"]),
        "process_observation_warnings": errors,
        "applicable": bool(filtered),
        "confirmation": ALIAS_CONFIRMATION,
        "automatic_alias_migration": False,
    }
    plan["plan_sha256"] = _sha256_json(plan)
    return plan


def _current_alias_tree_observation(item: dict[str, Any], source: Path) -> dict[str, Any]:
    allow_internal = bool(item.get("allow_internal_symlinks"))
    allow_absolute = bool(item.get("allow_absolute_internal_symlinks"))
    if not allow_internal and not allow_absolute:
        return _tree_observation(source)
    return _tree_observation(
        source,
        allow_internal_symlinks=allow_internal,
        symlink_root=source,
        allow_absolute_internal_symlinks=allow_absolute,
    )


def apply_alias_plan(
    policy: dict[str, Any],
    *,
    home: Path,
    plan_path: Path,
    expected_plan_sha256: str,
    confirmation: str,
) -> dict[str, Any]:
    if confirmation != ALIAS_CONFIRMATION:
        raise HygieneError("alias migration confirmation is invalid")
    plan, actual_sha = _read_hashed_plan(plan_path, expected_kind=ALIAS_PLAN_KIND)
    if expected_plan_sha256 != actual_sha:
        raise HygieneError("expected_plan_sha256 does not match alias plan")
    if plan.get("home") != str(home) or plan.get("policy_sha256") != policy["_policy_sha256"]:
        raise HygieneError("alias plan is not bound to current HOME and policy")
    if plan.get("applicable") is not True or not plan.get("candidates"):
        raise HygieneError("alias plan has no applicable candidates")
    candidates = plan["candidates"]
    refs, errors = _process_references(Path(item["source"]) for item in candidates)
    process_observation_warnings = sorted(
        set(plan.get("process_observation_warnings", []) + errors)
    )
    if refs:
        raise HygieneError("legacy artifact root acquired a live process reference")
    artifact_root: Path = policy["_resolved"]["artifact_root"]
    _ensure_owned_directory(artifact_root, home=home, create=True)

    for item in candidates:
        source = Path(item["source"])
        target = Path(item["target"])
        mode = item.get("mode", "replace")
        if source.parent != home or not _path_within(target, artifact_root):
            raise HygieneError("alias candidate path binding is invalid")
        if _current_alias_tree_observation(item, source) != item["observation"]:
            raise HygieneError(f"legacy artifact tree changed after planning: {source}")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if target.is_symlink() or (target.exists() and not target.is_dir()):
            raise HygieneError(f"alias target is unsafe: {target}")
        if mode == "replace":
            if target.exists() and any(target.iterdir()):
                raise HygieneError(f"alias target is no longer empty: {target}")
        elif mode == "merge":
            if not target.exists() or not target.is_dir():
                raise HygieneError(f"alias merge target disappeared: {target}")
            for entry in item.get("merge_entries", []):
                entry_source = Path(entry["source"])
                entry_target = Path(entry["target"])
                if entry_source.parent != source or entry_target.parent != target:
                    raise HygieneError("alias merge entry path binding is invalid")
                if entry_target.exists() or entry_target.is_symlink():
                    raise HygieneError(f"alias merge collision appeared: {entry_target}")
                if not _alias_entry_lstat_matches(entry_source, entry):
                    raise HygieneError(f"alias merge entry changed after planning: {entry_source}")
        else:
            raise HygieneError(f"unsupported alias migration mode: {mode}")
        if policy["safety"]["require_same_filesystem_moves"]:
            target_device = target.stat().st_dev if target.exists() else target.parent.stat().st_dev
            if source.stat().st_dev != target_device:
                raise HygieneError("alias migration would cross a filesystem boundary")

    migrated: list[dict[str, Any]] = []
    failure: str | None = None
    for item in candidates:
        source = Path(item["source"])
        target = Path(item["target"])
        mode = item.get("mode", "replace")
        moved_entries: list[dict[str, Any]] = []
        symlink_target: str | None = None
        replace_effect_started = False
        try:
            if _current_alias_tree_observation(item, source) != item["observation"]:
                raise HygieneError(
                    f"legacy artifact tree changed immediately before migration: {source}"
                )
            if mode == "replace":
                if target.exists():
                    if target.is_symlink() or not target.is_dir() or any(target.iterdir()):
                        raise HygieneError(f"alias target changed before migration: {target}")
                    target.rmdir()
                os.replace(source, target)
                replace_effect_started = True
                if item["compatibility_symlink"]:
                    symlink_target = os.path.relpath(target, source.parent)
                    source.symlink_to(symlink_target, target_is_directory=True)
                if not target.is_dir() or (
                    item["compatibility_symlink"] and not source.is_symlink()
                ):
                    raise HygieneError(f"alias migration readback failed for {source}")
                post_observation = _tree_observation(
                    target,
                    allow_internal_symlinks=bool(item.get("allow_internal_symlinks")),
                    symlink_root=target,
                    allow_absolute_internal_symlinks=bool(
                        item.get("allow_absolute_internal_symlinks")
                    ),
                )
                if post_observation["tree_sha256"] != item["observation"]["tree_sha256"]:
                    raise HygieneError(f"alias target content readback failed for {target}")
            else:
                for entry in item.get("merge_entries", []):
                    entry_source = Path(entry["source"])
                    entry_target = Path(entry["target"])
                    if entry_target.exists() or entry_target.is_symlink():
                        raise HygieneError(f"alias merge collision appeared: {entry_target}")
                    current = _alias_entry_observation(
                        entry_source,
                        source_root=source,
                        allow_internal_symlinks=bool(item.get("allow_internal_symlinks")),
                        allow_absolute_internal_symlinks=bool(
                            item.get("allow_absolute_internal_symlinks")
                        ),
                        hash_limit=policy["loose_file_rules"]["full_hash_max_bytes"],
                    )
                    if current != {"kind": entry["kind"], "observation": entry["observation"]}:
                        raise HygieneError(
                            f"alias merge entry changed immediately before migration: {entry_source}"
                        )
                    _rename_noreplace(entry_source, entry_target)
                    if entry_source.exists() or entry_source.is_symlink():
                        raise HygieneError(f"alias merge source still exists: {entry_source}")
                    if not (entry_target.exists() or entry_target.is_symlink()):
                        raise HygieneError(f"alias merge target missing after move: {entry_target}")
                    moved_entries.append(entry)
                if any(source.iterdir()):
                    raise HygieneError(f"alias merge source retained unexpected entries: {source}")
                source.rmdir()
                if item["compatibility_symlink"]:
                    symlink_target = os.path.relpath(target, source.parent)
                    source.symlink_to(symlink_target, target_is_directory=True)
            migrated.append(
                {
                    **item,
                    "moved_entries": moved_entries,
                    "symlink_target": symlink_target,
                }
            )
        except (OSError, HygieneError) as exc:
            failure = f"{type(exc).__name__}: {exc}"
            if moved_entries or replace_effect_started:
                migrated.append(
                    {
                        **item,
                        "moved_entries": moved_entries,
                        "symlink_target": symlink_target,
                        "partial": True,
                        "replace_effect_started": replace_effect_started,
                    }
                )
            break

    applied_at_ns = time.time_ns()
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "kind": ALIAS_RECEIPT_KIND,
        "status": "success" if failure is None else "partial_failure",
        "applied_at_unix_ns": applied_at_ns,
        "plan_sha256": actual_sha,
        "policy_sha256": policy["_policy_sha256"],
        "migrated": migrated,
        "failure": failure,
        "process_observation_warnings": process_observation_warnings,
        "remaining_count": len(candidates) - sum(
            1 for item in migrated if not item.get("partial")
        ),
        "restoration": (
            "for replace mode remove the recorded compatibility symlink and move target back; "
            "for merge mode recreate source and move each recorded moved_entries target back to source"
        ),
    }
    receipt["receipt_sha256"] = _sha256_json(receipt)
    state_root: Path = policy["_resolved"]["state_root"]
    receipt_path = state_root / "alias-receipts" / f"{applied_at_ns}-{actual_sha[:16]}.json"
    _atomic_json(receipt_path, receipt)
    result = {
        "receipt_path": str(receipt_path),
        "receipt_file_sha256": _sha256_file(receipt_path),
        "receipt": receipt,
    }
    if failure is not None:
        raise HygieneError(f"alias migration had a partial effect; receipt={receipt_path}; error={failure}")
    return result


def prune_coredumps(
    policy: dict[str, Any], *, home: Path, confirmation: str, now_unix: int | None = None
) -> dict[str, Any]:
    coredumps = policy["coredumps"]
    if confirmation != coredumps["cleanup_confirmation"]:
        raise HygieneError("core retention confirmation is invalid")
    if coredumps["automatic_retention_authorized"] is not True:
        raise HygieneError("core retention is not authorized")
    now = int(time.time()) if now_unix is None else now_unix
    directory: Path = policy["_resolved"]["core_directory"]
    _ensure_owned_directory(directory, home=home, create=True)
    files: list[dict[str, Any]] = []
    initial_observation_warnings: list[str] = []
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if not path.name.startswith("core."):
            continue
        try:
            observation = _file_observation(path, hash_limit=0)
        except FileNotFoundError:
            initial_observation_warnings.append(
                f"core dump disappeared during initial retention observation: {path}"
            )
            continue
        files.append(
            {
                "path": str(path),
                "size_bytes": observation["size_bytes"],
                "mtime_ns": observation["mtime_ns"],
                "age_seconds": max(0, now - observation["mtime_ns"] // 1_000_000_000),
                "observation": observation,
            }
        )
    refs, errors = _process_references(Path(item["path"]) for item in files)
    settled = [
        item
        for item in files
        if item["age_seconds"] >= coredumps["minimum_settled_seconds"]
    ]
    deferred_unsettled = [
        item
        for item in files
        if item["age_seconds"] < coredumps["minimum_settled_seconds"]
    ]
    selected: dict[str, dict[str, Any]] = {}
    for item in settled:
        if (
            item["age_seconds"] >= coredumps["retention_seconds"]
            or item["size_bytes"] > coredumps["per_file_limit_bytes"]
        ):
            selected[item["path"]] = item
    remaining_total = sum(
        item["size_bytes"] for item in files if item["path"] not in selected
    )
    for item in sorted(settled, key=lambda value: (value["mtime_ns"], value["path"])):
        if remaining_total <= coredumps["max_total_bytes"]:
            break
        if item["path"] in selected:
            continue
        selected[item["path"]] = item
        remaining_total -= item["size_bytes"]
    removable = [item for item in selected.values() if item["path"] not in refs]
    blocked = [
        {"path": path, "process_ids": pids}
        for path, pids in sorted(refs.items())
        if path in selected
    ]
    removed: list[dict[str, Any]] = []
    concurrent_removal_warnings: list[str] = []
    for item in sorted(removable, key=lambda value: (value["mtime_ns"], value["path"])):
        path = Path(item["path"])
        try:
            _validate_file_observation(path, item["observation"], hash_limit=0)
            path.unlink()
        except FileNotFoundError:
            concurrent_removal_warnings.append(
                f"core dump disappeared immediately before retention removal: {path}"
            )
            continue
        if path.exists() or path.is_symlink():
            raise HygieneError(f"core dump still exists after removal: {path}")
        removed.append(item)
    applied_at_ns = time.time_ns()
    after_total = 0
    post_observation_warnings: list[str] = []
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if not path.name.startswith("core."):
            continue
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            post_observation_warnings.append(
                f"core dump disappeared during post-retention observation: {path}"
            )
            continue
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            continue
        after_total += metadata.st_size
    status = "success"
    if blocked:
        status = "blocked_references_remaining"
    elif after_total > coredumps["max_total_bytes"]:
        status = "deferred_unsettled_over_budget"
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "kind": CORE_RECEIPT_KIND,
        "status": status,
        "applied_at_unix_ns": applied_at_ns,
        "policy_sha256": policy["_policy_sha256"],
        "before_total_bytes": sum(item["size_bytes"] for item in files),
        "after_total_bytes": after_total,
        "removed": removed,
        "reclaimed_bytes": sum(item["size_bytes"] for item in removed),
        "blocked": blocked,
        "deferred_unsettled": [
            {
                "path": item["path"],
                "size_bytes": item["size_bytes"],
                "age_seconds": item["age_seconds"],
            }
            for item in deferred_unsettled
        ],
        "process_observation_warnings": errors,
        "initial_observation_warnings": initial_observation_warnings,
        "concurrent_removal_warnings": concurrent_removal_warnings,
        "post_observation_warnings": post_observation_warnings,
        "max_total_bytes": coredumps["max_total_bytes"],
        "minimum_settled_seconds": coredumps["minimum_settled_seconds"],
        "retention_seconds": coredumps["retention_seconds"],
    }
    receipt["receipt_sha256"] = _sha256_json(receipt)
    state_root: Path = policy["_resolved"]["state_root"]
    receipt_path = state_root / "coredump-receipts" / f"{applied_at_ns}.json"
    _atomic_json(receipt_path, receipt)
    return {
        "receipt_path": str(receipt_path),
        "receipt_file_sha256": _sha256_file(receipt_path),
        "receipt": receipt,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    parser.add_argument("--home", type=Path, default=Path.home())
    sub = parser.add_subparsers(dest="operation", required=True)
    inventory_parser = sub.add_parser("inventory")
    inventory_parser.add_argument("--output", type=Path)
    inventory_parser.add_argument("--now-unix", type=int)
    quarantine_plan = sub.add_parser("plan-quarantine")
    quarantine_plan.add_argument("--output", type=Path)
    quarantine_plan.add_argument("--now-unix", type=int)
    quarantine_apply = sub.add_parser("apply-quarantine")
    quarantine_apply.add_argument("--plan", type=Path, required=True)
    quarantine_apply.add_argument("--expected-plan-sha256", required=True)
    quarantine_apply.add_argument("--confirmation", required=True)
    alias_plan = sub.add_parser("plan-aliases")
    alias_plan.add_argument("--output", type=Path)
    alias_plan.add_argument("--now-unix", type=int)
    alias_apply = sub.add_parser("apply-aliases")
    alias_apply.add_argument("--plan", type=Path, required=True)
    alias_apply.add_argument("--expected-plan-sha256", required=True)
    alias_apply.add_argument("--confirmation", required=True)
    core = sub.add_parser("prune-coredumps")
    core.add_argument("--confirmation", required=True)
    core.add_argument("--now-unix", type=int)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    home = args.home.expanduser().resolve()
    try:
        policy = load_policy(args.policy, home=home)
        if args.operation == "inventory":
            result = inventory(policy, home=home, now_unix=args.now_unix)
            if args.output is not None:
                _atomic_json(args.output, result)
        elif args.operation == "plan-quarantine":
            result = build_quarantine_plan(policy, home=home, now_unix=args.now_unix)
            if args.output is not None:
                _atomic_json(args.output, result)
        elif args.operation == "apply-quarantine":
            result = apply_quarantine(
                policy,
                home=home,
                plan_path=args.plan,
                expected_plan_sha256=args.expected_plan_sha256,
                confirmation=args.confirmation,
            )
        elif args.operation == "plan-aliases":
            result = build_alias_plan(policy, home=home, now_unix=args.now_unix)
            if args.output is not None:
                _atomic_json(args.output, result)
        elif args.operation == "apply-aliases":
            result = apply_alias_plan(
                policy,
                home=home,
                plan_path=args.plan,
                expected_plan_sha256=args.expected_plan_sha256,
                confirmation=args.confirmation,
            )
        else:
            result = prune_coredumps(
                policy,
                home=home,
                confirmation=args.confirmation,
                now_unix=args.now_unix,
            )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    except (HygieneError, OSError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "heim_pc.home_hygiene_error",
                    "operation": getattr(args, "operation", None),
                    "error": str(exc),
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
