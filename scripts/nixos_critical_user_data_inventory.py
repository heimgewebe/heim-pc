#!/usr/bin/env python3
"""Deterministic read-only inventory for the Heim-PC critical-user-data scope."""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import sqlite3
import stat
import time
from pathlib import Path
from typing import Any

CONTRACT_KIND = "heim_pc.critical_user_data_scope_contract"
INVENTORY_KIND = "heim_pc.critical_user_data_inventory.v1"
OBSERVATION_KIND = "heim_pc.critical_user_data_inventory_observation.v1"
ALGORITHM = "canonical-record-stream-sha256-v1"
MAX_CONTRACT_BYTES = 256 * 1024
DEFAULT_EXCLUSION_SAMPLES = 64
SQLITE_FAMILY_COMPANION_SUFFIXES = ("-journal", "-wal")
SQLITE_FAMILY_MAX_ATTEMPTS = 8
SQLITE_FAMILY_RETRY_BASE_SECONDS = 0.01


class InventoryError(ValueError):
    pass


class _RetrySqliteFamily(RuntimeError):
    pass


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_line(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def _require_utf8(value: str, label: str) -> str:
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise InventoryError(f"{label} is not canonical UTF-8") from exc
    return value


def _canonical_absolute(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise InventoryError(f"{label} must be an absolute path")
    _require_utf8(value, label)
    path = Path(value)
    if not path.is_absolute() or os.path.normpath(value) != value:
        raise InventoryError(f"{label} must be canonical and absolute")
    return path


def _under(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _validate_contract(value: dict[str, Any]) -> dict[str, Any]:
    scope = value.get("scope")
    scope_semantics = value.get("scope_semantics")
    expected_inventory = {
        "schema": INVENTORY_KIND,
        "algorithm": ALGORITHM,
        "same_filesystem_only": True,
        "follow_symlinks": False,
        "regular_file_content_sha256": True,
        "directory_mode_bound": True,
        "regular_file_mode_bound": True,
        "uid_gid_bound": True,
        "symlink_target_bound": True,
        "special_files": "excluded-runtime-only",
        "unreadable_included_path": "fail",
        "changed_during_hash": "fail",
    }
    explicit_path_set = (
        scope == "critical-user-data-home"
        and scope_semantics == "explicit-path-set"
    )
    allowed_scopes = {
        "critical-user-data": "whole-home-by-default",
        "critical-user-data-home": "whole-home-by-default",
        "critical-user-data-docker-volumes": "whole-root-by-default",
    }
    if (
        value.get("schema_version") != 1
        or value.get("kind") != CONTRACT_KIND
        or not (explicit_path_set or allowed_scopes.get(scope) == scope_semantics)
    ):
        raise InventoryError("critical-user-data contract identity is invalid")

    root = _canonical_absolute(value.get("root"), "contract root")
    logical_root = _canonical_absolute(value.get("logical_root"), "logical root")
    if root != logical_root:
        raise InventoryError("critical-user-data root/logical_root mismatch")

    inventory = value.get("inventory")
    if inventory != expected_inventory:
        raise InventoryError("critical-user-data inventory policy is invalid")

    if explicit_path_set:
        includes = value.get("includes")
        if not isinstance(includes, list) or not includes:
            raise InventoryError("explicit path set is empty")
        parsed_includes: list[dict[str, Any]] = []
        for index, item in enumerate(includes):
            if (
                not isinstance(item, dict)
                or set(item) != {"path", "class", "rationale", "capture", "restore_mode"}
            ):
                raise InventoryError("explicit include entry is malformed")
            included = _canonical_absolute(item["path"], "included path")
            if included == root or not _under(included, root):
                raise InventoryError("included path must be strictly beneath contract root")
            capture = item["capture"]
            if capture not in {"tree", "file", "sqlite-family"}:
                raise InventoryError("included path capture mode is invalid")
            parsed_includes.append(
                {
                    "rule": f"includes:{index}",
                    "path": included,
                    "class": _require_utf8(item["class"], "included path class"),
                    "rationale": _require_utf8(item["rationale"], "included path rationale"),
                    "capture": capture,
                    "restore_mode": _require_utf8(
                        item["restore_mode"], "included path restore mode"
                    ),
                }
            )
        paths = [item["path"] for item in parsed_includes]
        if len(set(paths)) != len(paths):
            raise InventoryError("explicit include paths must be unique")
        for index, first in enumerate(paths):
            for second in paths[index + 1 :]:
                if _under(first, second) or _under(second, first):
                    raise InventoryError("explicit include paths must not overlap")
        return {
            "scope": scope,
            "scope_semantics": scope_semantics,
            "root": root,
            "include_paths": tuple(
                sorted(parsed_includes, key=lambda item: str(item["path"]))
            ),
            "top_level_prefixes": (),
            "roots": (),
            "roots_by_top_level": {},
            "file_name_prefixes_under": (),
            "file_name_prefixes_by_top_level": {},
            "file_name_prefix_suffixes_under": (),
            "file_name_prefix_suffixes_by_top_level": {},
            "directory_names_under": (),
            "directory_names_by_top_level": {},
            "directory_names_global_fallback": False,
        }

    exclusions = value.get("exclusions")
    if not isinstance(exclusions, dict) or set(exclusions) != {
        "top_level_prefixes",
        "roots",
        "file_name_prefixes_under",
        "file_name_prefix_suffixes_under",
        "directory_names_under",
    }:
        raise InventoryError("critical-user-data exclusions are invalid")

    top_prefixes: list[dict[str, str]] = []
    for index, item in enumerate(exclusions["top_level_prefixes"]):
        if not isinstance(item, dict) or set(item) != {"prefix", "class", "rationale"}:
            raise InventoryError("top-level exclusion is malformed")
        prefix = item["prefix"]
        if (
            not isinstance(prefix, str)
            or not prefix
            or "/" in prefix
            or "\x00" in prefix
        ):
            raise InventoryError("top-level exclusion prefix is invalid")
        top_prefixes.append(
            {
                "rule": f"top_level_prefixes:{index}",
                "prefix": _require_utf8(prefix, "top-level exclusion prefix"),
                "class": _require_utf8(item["class"], "top-level exclusion class"),
                "rationale": _require_utf8(
                    item["rationale"], "top-level exclusion rationale"
                ),
            }
        )

    roots: list[dict[str, Any]] = []
    for index, item in enumerate(exclusions["roots"]):
        if not isinstance(item, dict) or set(item) != {"path", "class", "rationale"}:
            raise InventoryError("root exclusion is malformed")
        excluded = _canonical_absolute(item["path"], "excluded root")
        if excluded == root or not _under(excluded, root):
            raise InventoryError("excluded root must be strictly beneath contract root")
        roots.append(
            {
                "rule": f"roots:{index}",
                "path": excluded,
                "class": _require_utf8(item["class"], "root exclusion class"),
                "rationale": _require_utf8(item["rationale"], "root exclusion rationale"),
            }
        )

    file_name_prefixes_under: list[dict[str, Any]] = []
    for index, item in enumerate(exclusions["file_name_prefixes_under"]):
        if (
            not isinstance(item, dict)
            or set(item)
            != {
                "root",
                "prefixes",
                "required_size_bytes",
                "required_mode",
                "class",
                "rationale",
            }
        ):
            raise InventoryError("file-name-prefix exclusion is malformed")
        under_root = _canonical_absolute(
            item["root"], "file-name-prefix exclusion root"
        )
        if under_root == root or not _under(under_root, root):
            raise InventoryError(
                "file-name-prefix exclusion root must be strictly beneath contract root"
            )
        prefixes = item["prefixes"]
        if (
            not isinstance(prefixes, list)
            or not prefixes
            or any(
                not isinstance(prefix, str)
                or not prefix
                or "/" in prefix
                or "\x00" in prefix
                for prefix in prefixes
            )
            or len(set(prefixes)) != len(prefixes)
        ):
            raise InventoryError("file-name-prefix exclusion prefixes are invalid")
        required_size = item["required_size_bytes"]
        required_mode = item["required_mode"]
        if (
            isinstance(required_size, bool)
            or not isinstance(required_size, int)
            or required_size < 0
        ):
            raise InventoryError(
                "file-name-prefix exclusion required_size_bytes is invalid"
            )
        if (
            isinstance(required_mode, bool)
            or not isinstance(required_mode, int)
            or not 0 <= required_mode <= 0o777
        ):
            raise InventoryError("file-name-prefix exclusion required_mode is invalid")
        file_name_prefixes_under.append(
            {
                "rule": f"file_name_prefixes_under:{index}",
                "root": under_root,
                "prefixes": tuple(
                    _require_utf8(prefix, "file-name-prefix exclusion")
                    for prefix in prefixes
                ),
                "required_size_bytes": required_size,
                "required_mode": required_mode,
                "class": _require_utf8(
                    item["class"], "file-name-prefix exclusion class"
                ),
                "rationale": _require_utf8(
                    item["rationale"], "file-name-prefix exclusion rationale"
                ),
            }
        )

    file_name_prefix_suffixes_under: list[dict[str, Any]] = []
    for index, item in enumerate(exclusions["file_name_prefix_suffixes_under"]):
        if (
            not isinstance(item, dict)
            or set(item) != {"root", "prefixes", "suffixes", "class", "rationale"}
        ):
            raise InventoryError("file-name-prefix-suffix exclusion is malformed")
        under_root = _canonical_absolute(
            item["root"], "file-name-prefix-suffix exclusion root"
        )
        if under_root == root or not _under(under_root, root):
            raise InventoryError(
                "file-name-prefix-suffix exclusion root must be strictly beneath contract root"
            )
        prefixes = item["prefixes"]
        suffixes = item["suffixes"]
        if (
            not isinstance(prefixes, list)
            or not prefixes
            or any(
                not isinstance(prefix, str)
                or not prefix
                or "/" in prefix
                or "\x00" in prefix
                for prefix in prefixes
            )
            or len(set(prefixes)) != len(prefixes)
        ):
            raise InventoryError(
                "file-name-prefix-suffix exclusion prefixes are invalid"
            )
        if (
            not isinstance(suffixes, list)
            or not suffixes
            or any(
                not isinstance(suffix, str)
                or not suffix
                or "/" in suffix
                or "\x00" in suffix
                for suffix in suffixes
            )
            or len(set(suffixes)) != len(suffixes)
        ):
            raise InventoryError(
                "file-name-prefix-suffix exclusion suffixes are invalid"
            )
        file_name_prefix_suffixes_under.append(
            {
                "rule": f"file_name_prefix_suffixes_under:{index}",
                "root": under_root,
                "prefixes": tuple(
                    _require_utf8(prefix, "file-name-prefix-suffix exclusion prefix")
                    for prefix in prefixes
                ),
                "suffixes": tuple(
                    _require_utf8(suffix, "file-name-prefix-suffix exclusion suffix")
                    for suffix in suffixes
                ),
                "class": _require_utf8(
                    item["class"], "file-name-prefix-suffix exclusion class"
                ),
                "rationale": _require_utf8(
                    item["rationale"], "file-name-prefix-suffix exclusion rationale"
                ),
            }
        )

    directory_names_under: list[dict[str, Any]] = []
    for index, item in enumerate(exclusions["directory_names_under"]):
        if (
            not isinstance(item, dict)
            or set(item) != {"root", "names", "class", "rationale"}
        ):
            raise InventoryError("directory-name exclusion is malformed")
        under_root = _canonical_absolute(item["root"], "directory-name exclusion root")
        if not _under(under_root, root):
            raise InventoryError(
                "directory-name exclusion root must be beneath contract root"
            )
        names = item["names"]
        if (
            not isinstance(names, list)
            or not names
            or any(
                not isinstance(name, str)
                or not name
                or "/" in name
                or "\x00" in name
                for name in names
            )
            or len(set(names)) != len(names)
        ):
            raise InventoryError("directory-name exclusion names are invalid")
        directory_names_under.append(
            {
                "rule": f"directory_names_under:{index}",
                "root": under_root,
                "names": frozenset(
                    _require_utf8(name, "directory-name exclusion") for name in names
                ),
                "class": _require_utf8(
                    item["class"], "directory-name exclusion class"
                ),
                "rationale": _require_utf8(
                    item["rationale"], "directory-name exclusion rationale"
                ),
            }
        )

    roots_by_top_level: dict[str, list[dict[str, Any]]] = {}
    for rule in roots:
        top_level = rule["path"].relative_to(root).parts[0]
        roots_by_top_level.setdefault(top_level, []).append(rule)

    file_name_prefixes_by_top_level: dict[str, list[dict[str, Any]]] = {}
    for rule in file_name_prefixes_under:
        top_level = rule["root"].relative_to(root).parts[0]
        file_name_prefixes_by_top_level.setdefault(top_level, []).append(rule)

    file_name_prefix_suffixes_by_top_level: dict[str, list[dict[str, Any]]] = {}
    for rule in file_name_prefix_suffixes_under:
        top_level = rule["root"].relative_to(root).parts[0]
        file_name_prefix_suffixes_by_top_level.setdefault(top_level, []).append(rule)

    directory_names_by_top_level: dict[str, list[dict[str, Any]]] = {}
    directory_names_global_fallback = False
    for rule in directory_names_under:
        if rule["root"] == root:
            directory_names_global_fallback = True
            continue
        top_level = rule["root"].relative_to(root).parts[0]
        directory_names_by_top_level.setdefault(top_level, []).append(rule)

    return {
        "scope": scope,
        "scope_semantics": scope_semantics,
        "root": root,
        "top_level_prefixes": top_prefixes,
        "roots": roots,
        "roots_by_top_level": {
            key: tuple(value) for key, value in roots_by_top_level.items()
        },
        "file_name_prefixes_under": file_name_prefixes_under,
        "file_name_prefixes_by_top_level": {
            key: tuple(value)
            for key, value in file_name_prefixes_by_top_level.items()
        },
        "file_name_prefix_suffixes_under": file_name_prefix_suffixes_under,
        "file_name_prefix_suffixes_by_top_level": {
            key: tuple(value)
            for key, value in file_name_prefix_suffixes_by_top_level.items()
        },
        "directory_names_under": directory_names_under,
        "directory_names_by_top_level": {
            key: tuple(value) for key, value in directory_names_by_top_level.items()
        },
        "directory_names_global_fallback": directory_names_global_fallback,
    }


def load_contract(path: Path) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    path = Path(path)
    try:
        info = path.lstat()
    except OSError as exc:
        raise InventoryError("critical-user-data contract is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise InventoryError("critical-user-data contract must be a regular file")
    if info.st_size <= 0 or info.st_size > MAX_CONTRACT_BYTES:
        raise InventoryError("critical-user-data contract size is invalid")
    try:
        payload = path.read_bytes()
        value = json.loads(payload.decode("utf-8", "strict"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError("critical-user-data contract is invalid JSON") from exc
    if not isinstance(value, dict):
        raise InventoryError("critical-user-data contract must be an object")
    normalized = _validate_contract(value)
    return value, payload, normalized


def _relative(path: Path, root: Path) -> str:
    if path == root:
        return "."
    try:
        value = path.relative_to(root).as_posix()
    except ValueError as exc:
        raise InventoryError("inventory path escaped contract root") from exc
    return _require_utf8(value, "inventory path")


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _path_binding_identity(info: os.stat_result) -> tuple[int, int, int]:
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))


def _hash_fd(fd: int) -> str:
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _sqlite_family_companions(name: str, names: frozenset[str]) -> tuple[str, ...]:
    if name.endswith(SQLITE_FAMILY_COMPANION_SUFFIXES + ("-shm",)):
        return ()
    candidates = tuple(f"{name}{suffix}" for suffix in SQLITE_FAMILY_COMPANION_SUFFIXES)
    if ".sqlite3" in name or any(candidate in names for candidate in candidates):
        return candidates
    return ()


def _open_stable_regular_at(
    directory_fd: int,
    name: str,
    *,
    relative_path: str,
) -> tuple[int, os.stat_result] | None:
    try:
        observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InventoryError(f"included path cannot be read: {relative_path}") from exc
    if not stat.S_ISREG(observed.st_mode):
        raise InventoryError(
            f"SQLite family companion is not a regular file: {relative_path}"
        )

    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError as exc:
        raise _RetrySqliteFamily(
            f"SQLite family path vanished during open: {relative_path}"
        ) from exc
    except OSError as exc:
        raise InventoryError(
            f"included regular file cannot be opened safely: {relative_path}"
        ) from exc
    try:
        opened = os.fstat(fd)
        if _identity(opened) != _identity(observed):
            raise _RetrySqliteFamily(
                f"SQLite family path changed during open: {relative_path}"
            )
        return fd, opened
    except BaseException:
        os.close(fd)
        raise


def _sqlite_read_guard(
    directory_fd: int,
    name: str,
    *,
    relative_path: str,
) -> sqlite3.Connection | None:
    connection: sqlite3.Connection | None = None
    anchored = Path(f"/proc/self/fd/{directory_fd}") / name
    try:
        connection = sqlite3.connect(
            f"{anchored.as_uri()}?mode=ro",
            uri=True,
            timeout=0.25,
            isolation_level=None,
        )
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        connection.execute("SELECT rootpage FROM sqlite_schema LIMIT 1").fetchone()
        return connection
    except sqlite3.DatabaseError:
        if connection is not None:
            connection.close()
        return None


def _family_regular_record(
    fd: int,
    *,
    relative_path: str,
    opened: os.stat_result,
    classification_only: bool,
) -> tuple[dict[str, Any], os.stat_result]:
    if classification_only:
        content_sha256 = None
    else:
        content_sha256 = _hash_fd(fd)
    after = os.fstat(fd)
    if _identity(after) != _identity(opened):
        raise _RetrySqliteFamily(
            f"SQLite family file changed during hashing: {relative_path}"
        )
    record: dict[str, Any] = {
        "path": relative_path,
        "type": "regular",
        "mode": stat.S_IMODE(after.st_mode),
        "uid": after.st_uid,
        "gid": after.st_gid,
        "size_bytes": after.st_size,
    }
    if content_sha256 is not None:
        record["sha256"] = content_sha256
    return record, after


def _capture_sqlite_family(
    directory_fd: int,
    directory_path: Path,
    *,
    main_name: str,
    companion_names: tuple[str, ...],
    root: Path,
    classification_only: bool,
    require_read_guard: bool = False,
) -> tuple[dict[str, Any], dict[str, dict[str, Any] | None]]:
    main_path = directory_path / main_name
    main_relative = _relative(main_path, root)

    for attempt in range(SQLITE_FAMILY_MAX_ATTEMPTS):
        opened_fds: list[int] = []
        guard: sqlite3.Connection | None = None
        try:
            main = _open_stable_regular_at(
                directory_fd,
                main_name,
                relative_path=main_relative,
            )
            if main is None:
                raise _RetrySqliteFamily(
                    f"SQLite family main vanished: {main_relative}"
                )
            main_fd, main_opened = main
            opened_fds.append(main_fd)

            guard = _sqlite_read_guard(
                directory_fd,
                main_name,
                relative_path=main_relative,
            )
            if require_read_guard and guard is None:
                raise _RetrySqliteFamily(
                    f"SQLite read guard unavailable: {main_relative}"
                )
            try:
                current_main = os.stat(
                    main_name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise _RetrySqliteFamily(
                    f"SQLite family main changed while acquiring read guard: {main_relative}"
                ) from exc
            if _identity(current_main) != _identity(main_opened):
                raise _RetrySqliteFamily(
                    f"SQLite family main changed while acquiring read guard: {main_relative}"
                )

            companions: dict[str, tuple[int, os.stat_result] | None] = {}
            for companion_name in companion_names:
                companion_relative = _relative(
                    directory_path / companion_name,
                    root,
                )
                companion = _open_stable_regular_at(
                    directory_fd,
                    companion_name,
                    relative_path=companion_relative,
                )
                companions[companion_name] = companion
                if companion is not None:
                    opened_fds.append(companion[0])

            main_record, main_after = _family_regular_record(
                main_fd,
                relative_path=main_relative,
                opened=main_opened,
                classification_only=classification_only,
            )
            companion_records: dict[str, dict[str, Any] | None] = {}
            companion_after: dict[str, os.stat_result | None] = {}
            for companion_name in companion_names:
                companion = companions[companion_name]
                if companion is None:
                    companion_records[companion_name] = None
                    companion_after[companion_name] = None
                    continue
                companion_fd, companion_opened = companion
                companion_relative = _relative(
                    directory_path / companion_name,
                    root,
                )
                record, after = _family_regular_record(
                    companion_fd,
                    relative_path=companion_relative,
                    opened=companion_opened,
                    classification_only=classification_only,
                )
                companion_records[companion_name] = record
                companion_after[companion_name] = after

            try:
                final_main = os.stat(
                    main_name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise _RetrySqliteFamily(
                    f"SQLite family main changed after read: {main_relative}"
                ) from exc
            if _identity(final_main) != _identity(main_after):
                raise _RetrySqliteFamily(
                    f"SQLite family main changed after read: {main_relative}"
                )

            for companion_name in companion_names:
                expected = companion_after[companion_name]
                companion_relative = _relative(
                    directory_path / companion_name,
                    root,
                )
                try:
                    current = os.stat(
                        companion_name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    current = None
                except OSError as exc:
                    raise InventoryError(
                        f"included path cannot be read: {companion_relative}"
                    ) from exc
                if expected is None:
                    if current is not None:
                        raise _RetrySqliteFamily(
                            f"SQLite family companion appeared during read: {companion_relative}"
                        )
                elif current is None or _identity(current) != _identity(expected):
                    raise _RetrySqliteFamily(
                        f"SQLite family companion changed during read: {companion_relative}"
                    )

            return main_record, companion_records
        except _RetrySqliteFamily:
            if attempt + 1 >= SQLITE_FAMILY_MAX_ATTEMPTS:
                raise InventoryError(
                    f"SQLite family did not stabilize: {main_relative}"
                )
        finally:
            if guard is not None:
                guard.close()
            for fd in reversed(opened_fds):
                os.close(fd)

        time.sleep(SQLITE_FAMILY_RETRY_BASE_SECONDS * (attempt + 1))

    raise AssertionError("unreachable SQLite family retry state")


def _match_lexical_exclusion(
    path: Path,
    *,
    policy: dict[str, Any],
    relative_path: str | None = None,
) -> dict[str, str] | None:
    root: Path = policy["root"]
    if path == root:
        return None
    relative = relative_path if relative_path is not None else _relative(path, root)
    top_level = relative.split("/", 1)[0]
    if path.parent == root:
        for rule in policy["top_level_prefixes"]:
            if path.name.startswith(rule["prefix"]):
                return {
                    "rule": rule["rule"],
                    "class": rule["class"],
                    "rationale": rule["rationale"],
                }
    for rule in policy["roots_by_top_level"].get(top_level, ()):
        if _under(path, rule["path"]):
            return {
                "rule": rule["rule"],
                "class": rule["class"],
                "rationale": rule["rationale"],
            }
    return None


def _match_vanished_file_exclusion(
    path: Path,
    *,
    policy: dict[str, Any],
    relative_path: str | None = None,
) -> dict[str, str] | None:
    root: Path = policy["root"]
    if path == root:
        return None
    relative = relative_path if relative_path is not None else _relative(path, root)
    top_level = relative.split("/", 1)[0]
    for rule in policy["file_name_prefix_suffixes_by_top_level"].get(top_level, ()):
        if (
            path.parent == rule["root"]
            and any(path.name.startswith(prefix) for prefix in rule["prefixes"])
            and any(path.name.endswith(suffix) for suffix in rule["suffixes"])
        ):
            return {
                "rule": rule["rule"],
                "class": rule["class"],
                "rationale": rule["rationale"],
            }
    return None


def _match_exclusion(
    path: Path,
    *,
    is_directory: bool,
    observed: os.stat_result,
    policy: dict[str, Any],
    relative_path: str | None = None,
) -> dict[str, str] | None:
    root: Path = policy["root"]
    if path == root:
        return None
    relative = relative_path if relative_path is not None else _relative(path, root)
    top_level = relative.split("/", 1)[0]
    lexical = _match_lexical_exclusion(
        path,
        policy=policy,
        relative_path=relative,
    )
    if lexical is not None:
        return lexical
    if not is_directory and stat.S_ISREG(observed.st_mode):
        for rule in policy["file_name_prefixes_by_top_level"].get(top_level, ()):
            if (
                path.parent == rule["root"]
                and any(path.name.startswith(prefix) for prefix in rule["prefixes"])
                and observed.st_size == rule["required_size_bytes"]
                and stat.S_IMODE(observed.st_mode) == rule["required_mode"]
            ):
                return {
                    "rule": rule["rule"],
                    "class": rule["class"],
                    "rationale": rule["rationale"],
                }
        for rule in policy["file_name_prefix_suffixes_by_top_level"].get(
            top_level, ()
        ):
            if (
                path.parent == rule["root"]
                and any(path.name.startswith(prefix) for prefix in rule["prefixes"])
                and any(path.name.endswith(suffix) for suffix in rule["suffixes"])
            ):
                return {
                    "rule": rule["rule"],
                    "class": rule["class"],
                    "rationale": rule["rationale"],
                }
    if is_directory:
        directory_rules = (
            policy["directory_names_under"]
            if policy["directory_names_global_fallback"]
            else policy["directory_names_by_top_level"].get(top_level, ())
        )
        for rule in directory_rules:
            if _under(path, rule["root"]) and path.name in rule["names"]:
                return {
                    "rule": rule["rule"],
                    "class": rule["class"],
                    "rationale": rule["rationale"],
                }
    return None


class _Accumulator:
    def __init__(self, *, authoritative: bool, max_exclusion_samples: int):
        self.authoritative = authoritative
        self.digest = hashlib.sha256() if authoritative else None
        self.record_count = 0
        self.type_counts = {"directory": 0, "regular": 0, "symlink": 0}
        self.regular_bytes = 0
        self.exclusion_digest = hashlib.sha256()
        self.exclusion_count = 0
        self.exclusion_classes: dict[str, int] = {}
        self.exclusion_samples: list[dict[str, str]] = []
        self.max_exclusion_samples = max_exclusion_samples

    def record(self, value: dict[str, Any]) -> None:
        self.record_count += 1
        self.type_counts[value["type"]] += 1
        if value["type"] == "regular":
            self.regular_bytes += value["size_bytes"]
        if self.digest is not None:
            self.digest.update(_canonical_line(value))

    def exclude(
        self,
        *,
        path: str,
        rule: str,
        klass: str,
        rationale: str,
    ) -> None:
        value = {
            "path": path,
            "rule": rule,
            "class": klass,
            "rationale": rationale,
        }
        self.exclusion_count += 1
        self.exclusion_classes[klass] = self.exclusion_classes.get(klass, 0) + 1
        self.exclusion_digest.update(_canonical_line(value))
        if len(self.exclusion_samples) < self.max_exclusion_samples:
            self.exclusion_samples.append(value)


def collect_inventory(
    contract_path: Path,
    *,
    classification_only: bool = False,
    max_exclusion_samples: int = DEFAULT_EXCLUSION_SAMPLES,
) -> dict[str, Any]:
    if isinstance(max_exclusion_samples, bool) or max_exclusion_samples < 0:
        raise InventoryError("max exclusion samples is invalid")
    _contract, contract_bytes, policy = load_contract(contract_path)
    root: Path = policy["root"]
    try:
        linked = root.lstat()
    except OSError as exc:
        raise InventoryError("critical-user-data root is unavailable") from exc
    if stat.S_ISLNK(linked.st_mode) or not stat.S_ISDIR(linked.st_mode):
        raise InventoryError("critical-user-data root must be a real directory")

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        root_fd = os.open(root, flags)
    except OSError as exc:
        raise InventoryError("critical-user-data root cannot be opened safely") from exc
    accumulator = _Accumulator(
        authoritative=not classification_only,
        max_exclusion_samples=max_exclusion_samples,
    )

    def walk(directory_fd: int, directory_path: Path, root_device: int) -> None:
        try:
            names = sorted(
                _require_utf8(entry.name, "directory entry name")
                for entry in os.scandir(directory_fd)
            )
            initial_names = tuple(names)
            names_set = frozenset(names)
            known_names = set(names)
        except OSError as exc:
            raise InventoryError(
                f"included directory cannot be read: {_relative(directory_path, root)}"
            ) from exc
        pending_sqlite_records: dict[str, dict[str, Any] | None] = {}
        for name in names:
            if name in pending_sqlite_records:
                pending = pending_sqlite_records.pop(name)
                if pending is not None:
                    accumulator.record(pending)
                continue

            full = directory_path / name
            rel = _relative(full, root)
            lexical_exclusion = _match_lexical_exclusion(
                full,
                policy=policy,
                relative_path=rel,
            )
            if lexical_exclusion is not None:
                accumulator.exclude(
                    path=rel,
                    rule=lexical_exclusion["rule"],
                    klass=lexical_exclusion["class"],
                    rationale=lexical_exclusion["rationale"],
                )
                continue
            try:
                observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError as exc:
                vanished_exclusion = _match_vanished_file_exclusion(
                    full,
                    policy=policy,
                    relative_path=rel,
                )
                if vanished_exclusion is not None:
                    accumulator.exclude(
                        path=rel,
                        rule=vanished_exclusion["rule"],
                        klass=vanished_exclusion["class"],
                        rationale=vanished_exclusion["rationale"],
                    )
                    continue
                raise InventoryError(f"included path cannot be read: {rel}") from exc
            except OSError as exc:
                raise InventoryError(f"included path cannot be read: {rel}") from exc

            is_directory = stat.S_ISDIR(observed.st_mode)
            exclusion = _match_exclusion(
                full,
                is_directory=is_directory,
                observed=observed,
                policy=policy,
                relative_path=rel,
            )
            if exclusion is not None:
                accumulator.exclude(
                    path=rel,
                    rule=exclusion["rule"],
                    klass=exclusion["class"],
                    rationale=exclusion["rationale"],
                )
                continue

            if observed.st_dev != root_device:
                accumulator.exclude(
                    path=rel,
                    rule="same_filesystem_only",
                    klass="foreign-filesystem",
                    rationale="same_filesystem_only excludes mounted or foreign filesystem entries",
                )
                continue

            if is_directory:
                dir_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
                if hasattr(os, "O_NOFOLLOW"):
                    dir_flags |= os.O_NOFOLLOW
                try:
                    child_fd = os.open(name, dir_flags, dir_fd=directory_fd)
                except OSError as exc:
                    raise InventoryError(
                        f"included directory cannot be opened safely: {rel}"
                    ) from exc
                try:
                    opened = os.fstat(child_fd)
                    if _identity(opened) != _identity(observed):
                        raise InventoryError(f"included directory changed during open: {rel}")
                    accumulator.record(
                        {
                            "path": rel,
                            "type": "directory",
                            "mode": stat.S_IMODE(opened.st_mode),
                            "uid": opened.st_uid,
                            "gid": opened.st_gid,
                        }
                    )
                    walk(child_fd, full, root_device)
                finally:
                    os.close(child_fd)
                continue

            if stat.S_ISREG(observed.st_mode):
                if classification_only:
                    accumulator.record(
                        {
                            "path": rel,
                            "type": "regular",
                            "mode": stat.S_IMODE(observed.st_mode),
                            "uid": observed.st_uid,
                            "gid": observed.st_gid,
                            "size_bytes": observed.st_size,
                        }
                    )
                    continue
                sqlite_companions = _sqlite_family_companions(name, names_set)
                if sqlite_companions:
                    main_record, companion_records = _capture_sqlite_family(
                        directory_fd,
                        directory_path,
                        main_name=name,
                        companion_names=sqlite_companions,
                        root=root,
                        classification_only=classification_only,
                    )
                    accumulator.record(main_record)
                    pending_sqlite_records.update(companion_records)
                    for companion_name, companion_record in companion_records.items():
                        if companion_record is not None and companion_name not in known_names:
                            bisect.insort(names, companion_name)
                            known_names.add(companion_name)
                    continue

                file_flags = os.O_RDONLY | os.O_CLOEXEC
                if hasattr(os, "O_NOFOLLOW"):
                    file_flags |= os.O_NOFOLLOW
                try:
                    fd = os.open(name, file_flags, dir_fd=directory_fd)
                except OSError as exc:
                    raise InventoryError(
                        f"included regular file cannot be opened safely: {rel}"
                    ) from exc
                try:
                    opened = os.fstat(fd)
                    if _identity(opened) != _identity(observed):
                        raise InventoryError(
                            f"included regular file changed before hashing: {rel}"
                        )
                    if classification_only:
                        content_sha256 = None
                    else:
                        content_sha256 = _hash_fd(fd)
                    after = os.fstat(fd)
                    if _identity(after) != _identity(opened):
                        raise InventoryError(
                            f"included regular file changed during hashing: {rel}"
                        )
                    record: dict[str, Any] = {
                        "path": rel,
                        "type": "regular",
                        "mode": stat.S_IMODE(after.st_mode),
                        "uid": after.st_uid,
                        "gid": after.st_gid,
                        "size_bytes": after.st_size,
                    }
                    if content_sha256 is not None:
                        record["sha256"] = content_sha256
                    accumulator.record(record)
                finally:
                    os.close(fd)
                continue

            if stat.S_ISLNK(observed.st_mode):
                try:
                    target = os.readlink(name, dir_fd=directory_fd)
                    after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError as exc:
                    raise InventoryError(f"included symlink cannot be read: {rel}") from exc
                if _identity(after) != _identity(observed):
                    raise InventoryError(f"included symlink changed during read: {rel}")
                accumulator.record(
                    {
                        "path": rel,
                        "type": "symlink",
                        "uid": after.st_uid,
                        "gid": after.st_gid,
                        "target": _require_utf8(target, "symlink target"),
                    }
                )
                continue

            if stat.S_ISSOCK(observed.st_mode) or stat.S_ISFIFO(observed.st_mode):
                special_type = (
                    "socket" if stat.S_ISSOCK(observed.st_mode) else "fifo"
                )
                accumulator.exclude(
                    path=rel,
                    rule=f"special_files:{special_type}",
                    klass="transient-runtime-special",
                    rationale=(
                        f"{special_type} inode is a live IPC endpoint and carries "
                        "no restorable file content"
                    ),
                )
                continue

            raise InventoryError(
                f"included special file is not runtime-excluded: {rel}"
            )

        try:
            final_names = tuple(
                sorted(
                    _require_utf8(entry.name, "directory entry name")
                    for entry in os.scandir(directory_fd)
                )
            )
        except OSError as exc:
            raise InventoryError(
                f"included directory cannot be reread: {_relative(directory_path, root)}"
            ) from exc
        if final_names != initial_names:
            raise InventoryError(
                f"included directory membership changed during hashing: "
                f"{_relative(directory_path, root)}"
            )

    def open_explicit_parent(
        selected: Path,
        *,
        relative_path: str,
        root_device: int,
    ) -> tuple[int, str, tuple[tuple[str, tuple[int, int, int]], ...]]:
        try:
            parts = selected.relative_to(root).parts
        except ValueError as exc:
            raise InventoryError(
                f"included path is outside contract root: {relative_path}"
            ) from exc
        if not parts:
            raise InventoryError(
                f"included path must be beneath contract root: {relative_path}"
            )

        parent_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            parent_flags |= os.O_NOFOLLOW

        current_fd = os.dup(root_fd)
        ancestor_bindings: list[tuple[str, tuple[int, int, int]]] = []
        try:
            for component in parts[:-1]:
                try:
                    next_fd = os.open(
                        component,
                        parent_flags,
                        dir_fd=current_fd,
                    )
                except OSError as exc:
                    raise InventoryError(
                        f"included path ancestor cannot be opened safely: {relative_path}"
                    ) from exc
                try:
                    opened = os.fstat(next_fd)
                    if opened.st_dev != root_device:
                        raise InventoryError(
                            f"included path ancestor is on a foreign filesystem: "
                            f"{relative_path}"
                        )
                    ancestor_bindings.append(
                        (component, _path_binding_identity(opened))
                    )
                except BaseException:
                    os.close(next_fd)
                    raise
                os.close(current_fd)
                current_fd = next_fd
            return current_fd, parts[-1], tuple(ancestor_bindings)
        except BaseException:
            os.close(current_fd)
            raise

    def revalidate_explicit_binding(
        *,
        relative_path: str,
        ancestor_bindings: tuple[tuple[str, tuple[int, int, int]], ...],
        selected_name: str,
        selected_binding: tuple[int, int, int],
        root_binding: tuple[int, int, int],
        root_device: int,
    ) -> None:
        parent_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            parent_flags |= os.O_NOFOLLOW
        try:
            current_fd = os.open(root, parent_flags)
        except OSError as exc:
            raise InventoryError(
                f"contract root cannot be revalidated after capture: {relative_path}"
            ) from exc
        try:
            current_root = os.fstat(current_fd)
            if (
                current_root.st_dev != root_device
                or _path_binding_identity(current_root) != root_binding
            ):
                raise InventoryError(
                    f"contract root binding changed during capture: {relative_path}"
                )
            for component, expected_binding in ancestor_bindings:
                try:
                    next_fd = os.open(
                        component,
                        parent_flags,
                        dir_fd=current_fd,
                    )
                except OSError as exc:
                    raise InventoryError(
                        f"included path ancestor binding changed during capture: "
                        f"{relative_path}"
                    ) from exc
                try:
                    current = os.fstat(next_fd)
                    if (
                        current.st_dev != root_device
                        or _path_binding_identity(current) != expected_binding
                    ):
                        raise InventoryError(
                            f"included path ancestor binding changed during capture: "
                            f"{relative_path}"
                        )
                except BaseException:
                    os.close(next_fd)
                    raise
                os.close(current_fd)
                current_fd = next_fd
            try:
                current_selected = os.stat(
                    selected_name,
                    dir_fd=current_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise InventoryError(
                    f"included path binding changed during capture: {relative_path}"
                ) from exc
            if (
                current_selected.st_dev != root_device
                or _path_binding_identity(current_selected) != selected_binding
            ):
                raise InventoryError(
                    f"included path binding changed during capture: {relative_path}"
                )
        finally:
            os.close(current_fd)

    def record_explicit_path(
        entry: dict[str, Any],
        root_device: int,
        root_binding: tuple[int, int, int],
    ) -> None:
        selected: Path = entry["path"]
        rel = _relative(selected, root)
        parent_fd, selected_name, ancestor_bindings = open_explicit_parent(
            selected,
            relative_path=rel,
            root_device=root_device,
        )
        try:
            try:
                observed = os.stat(
                    selected_name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise InventoryError(f"included path cannot be read: {rel}") from exc
            if observed.st_dev != root_device:
                raise InventoryError(f"included path is on a foreign filesystem: {rel}")

            capture = entry["capture"]
            if capture == "tree":
                if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
                    raise InventoryError(f"included tree is not a real directory: {rel}")
                flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    fd = os.open(selected_name, flags, dir_fd=parent_fd)
                except OSError as exc:
                    raise InventoryError(
                        f"included tree cannot be opened safely: {rel}"
                    ) from exc
                try:
                    opened = os.fstat(fd)
                    if _identity(opened) != _identity(observed):
                        raise InventoryError(f"included tree changed during open: {rel}")
                    if opened.st_dev != root_device:
                        raise InventoryError(
                            f"included tree is on a foreign filesystem: {rel}"
                        )
                    accumulator.record(
                        {
                            "path": rel,
                            "type": "directory",
                            "mode": stat.S_IMODE(opened.st_mode),
                            "uid": opened.st_uid,
                            "gid": opened.st_gid,
                        }
                    )
                    walk(fd, selected, root_device)
                    revalidate_explicit_binding(
                        relative_path=rel,
                        ancestor_bindings=ancestor_bindings,
                        selected_name=selected_name,
                        selected_binding=_path_binding_identity(opened),
                        root_binding=root_binding,
                        root_device=root_device,
                    )
                finally:
                    os.close(fd)
                return

            if capture == "sqlite-family":
                if not stat.S_ISREG(observed.st_mode):
                    raise InventoryError(
                        f"included SQLite family main is not regular: {rel}"
                    )
                companions = tuple(
                    f"{selected.name}{suffix}"
                    for suffix in SQLITE_FAMILY_COMPANION_SUFFIXES
                )
                if classification_only:
                    accumulator.record(
                        {
                            "path": rel,
                            "type": "regular",
                            "mode": stat.S_IMODE(observed.st_mode),
                            "uid": observed.st_uid,
                            "gid": observed.st_gid,
                            "size_bytes": observed.st_size,
                        }
                    )
                    for companion_name in companions:
                        companion_path = selected.parent / companion_name
                        companion_rel = _relative(companion_path, root)
                        try:
                            companion = os.stat(
                                companion_name,
                                dir_fd=parent_fd,
                                follow_symlinks=False,
                            )
                        except FileNotFoundError:
                            continue
                        except OSError as exc:
                            raise InventoryError(
                                f"included path cannot be read: {companion_rel}"
                            ) from exc
                        if not stat.S_ISREG(companion.st_mode):
                            raise InventoryError(
                                f"SQLite family companion is not a regular file: "
                                f"{companion_rel}"
                            )
                        if companion.st_dev != root_device:
                            raise InventoryError(
                                f"SQLite family companion is on a foreign filesystem: "
                                f"{companion_rel}"
                            )
                        accumulator.record(
                            {
                                "path": companion_rel,
                                "type": "regular",
                                "mode": stat.S_IMODE(companion.st_mode),
                                "uid": companion.st_uid,
                                "gid": companion.st_gid,
                                "size_bytes": companion.st_size,
                            }
                        )
                    return
                main_record, companion_records = _capture_sqlite_family(
                    parent_fd,
                    selected.parent,
                    main_name=selected.name,
                    companion_names=companions,
                    root=root,
                    classification_only=False,
                    require_read_guard=True,
                )
                accumulator.record(main_record)
                for companion_name in companions:
                    companion_record = companion_records.get(companion_name)
                    if companion_record is not None:
                        accumulator.record(companion_record)
                revalidate_explicit_binding(
                    relative_path=rel,
                    ancestor_bindings=ancestor_bindings,
                    selected_name=selected_name,
                    selected_binding=_path_binding_identity(observed),
                    root_binding=root_binding,
                    root_device=root_device,
                )
                return

            if capture != "file" or not stat.S_ISREG(observed.st_mode):
                raise InventoryError(f"included file is not a regular file: {rel}")
            if classification_only:
                accumulator.record(
                    {
                        "path": rel,
                        "type": "regular",
                        "mode": stat.S_IMODE(observed.st_mode),
                        "uid": observed.st_uid,
                        "gid": observed.st_gid,
                        "size_bytes": observed.st_size,
                    }
                )
                revalidate_explicit_binding(
                    relative_path=rel,
                    ancestor_bindings=ancestor_bindings,
                    selected_name=selected_name,
                    selected_binding=_path_binding_identity(observed),
                    root_binding=root_binding,
                    root_device=root_device,
                )
                return
            flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                fd = os.open(selected_name, flags, dir_fd=parent_fd)
            except OSError as exc:
                raise InventoryError(
                    f"included file cannot be opened safely: {rel}"
                ) from exc
            try:
                opened = os.fstat(fd)
                if _identity(opened) != _identity(observed):
                    raise InventoryError(f"included file changed during open: {rel}")
                content_sha256 = _hash_fd(fd)
                after = os.fstat(fd)
                if _identity(after) != _identity(opened):
                    raise InventoryError(f"included file changed during hashing: {rel}")
                accumulator.record(
                    {
                        "path": rel,
                        "type": "regular",
                        "mode": stat.S_IMODE(after.st_mode),
                        "uid": after.st_uid,
                        "gid": after.st_gid,
                        "size_bytes": after.st_size,
                        "sha256": content_sha256,
                    }
                )
                revalidate_explicit_binding(
                    relative_path=rel,
                    ancestor_bindings=ancestor_bindings,
                    selected_name=selected_name,
                    selected_binding=_path_binding_identity(after),
                    root_binding=root_binding,
                    root_device=root_device,
                )
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)

    try:
        root_info = os.fstat(root_fd)
        if _identity(root_info) != _identity(linked):
            raise InventoryError("critical-user-data root changed during open")
        if policy["scope_semantics"] == "explicit-path-set":
            root_binding = _path_binding_identity(root_info)
            for entry in policy["include_paths"]:
                record_explicit_path(entry, root_info.st_dev, root_binding)
        else:
            accumulator.record(
                {
                    "path": ".",
                    "type": "directory",
                    "mode": stat.S_IMODE(root_info.st_mode),
                    "uid": root_info.st_uid,
                    "gid": root_info.st_gid,
                }
            )
            walk(root_fd, root, root_info.st_dev)
    finally:
        os.close(root_fd)

    contract_sha256 = _sha256_bytes(contract_bytes)
    return {
        "schema_version": 1,
        "kind": OBSERVATION_KIND if classification_only else INVENTORY_KIND,
        "scope": policy["scope"],
        "root": str(root),
        "algorithm": ALGORITHM,
        "critical_scope_sha256": contract_sha256,
        "contract_sha256": contract_sha256,
        "authoritative_inventory": not classification_only,
        "inventory_sha256": (
            accumulator.digest.hexdigest() if accumulator.digest is not None else None
        ),
        "record_count": accumulator.record_count,
        "type_counts": dict(sorted(accumulator.type_counts.items())),
        "regular_file_bytes": accumulator.regular_bytes,
        "exclusion_boundary_count": accumulator.exclusion_count,
        "exclusion_boundary_sha256": accumulator.exclusion_digest.hexdigest(),
        "exclusion_class_counts": dict(sorted(accumulator.exclusion_classes.items())),
        "exclusion_samples": accumulator.exclusion_samples,
        "production_effects_authorized": False,
    }


def _default_contract() -> Path:
    return (
        Path(__file__).resolve().parents[1]
        / "nixos"
        / "production"
        / "critical-user-home-data-contract-v1.json"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, default=_default_contract())
    parser.add_argument("--classification-only", action="store_true")
    parser.add_argument("--expected-script-sha256")
    parser.add_argument("--expected-contract-sha256")
    parser.add_argument(
        "--max-exclusion-samples",
        type=int,
        default=DEFAULT_EXCLUSION_SAMPLES,
    )
    args = parser.parse_args(argv)

    original_load_contract = load_contract
    pinned_contract: tuple[dict[str, Any], bytes, dict[str, Any]] | None = None
    try:
        pin_values = (
            args.expected_script_sha256,
            args.expected_contract_sha256,
        )
        if any(pin_values) and not all(pin_values):
            raise InventoryError("source pinning requires both expected SHA-256 values")
        if all(pin_values):
            expected_script = str(args.expected_script_sha256)
            expected_contract = str(args.expected_contract_sha256)
            if (
                len(expected_script) != 64
                or len(expected_contract) != 64
                or any(character not in "0123456789abcdef" for character in expected_script)
                or any(character not in "0123456789abcdef" for character in expected_contract)
            ):
                raise InventoryError("source pinning SHA-256 value is invalid")
            try:
                script_payload = Path(__file__).read_bytes()
            except OSError as exc:
                raise InventoryError("inventory script source cannot be pinned") from exc
            if _sha256_bytes(script_payload) != expected_script:
                raise InventoryError("inventory script source digest mismatch")
            pinned_contract = original_load_contract(args.contract)
            if _sha256_bytes(pinned_contract[1]) != expected_contract:
                raise InventoryError("critical-user-data contract digest mismatch")

            def pinned_load_contract(
                path: Path,
            ) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
                if Path(path) == args.contract:
                    assert pinned_contract is not None
                    return pinned_contract
                return original_load_contract(path)

            globals()["load_contract"] = pinned_load_contract

        result = collect_inventory(
            args.contract,
            classification_only=args.classification_only,
            max_exclusion_samples=args.max_exclusion_samples,
        )
    except InventoryError:
        print("critical-user-data inventory blocked by a safety check", file=os.sys.stderr)
        return 2
    finally:
        globals()["load_contract"] = original_load_contract
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())