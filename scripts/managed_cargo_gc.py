#!/usr/bin/env python3
"""Inventory and reclaim managed Cargo build identities through a guarded lifecycle."""

from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

try:
    from scripts import managed_build as mb
except ImportError:  # Direct execution from scripts/.
    import managed_build as mb


CACHE_KEY_RE = re.compile(r"[0-9a-f]{64}\Z")
EVIDENCE_KIND = "grabowski.managed_cargo_cache_evidence"
PLAN_KIND = "heim_pc.managed_cargo_gc_plan"
RECEIPT_KIND = "heim_pc.managed_cargo_gc_receipt"
CONFIRMATION = "apply-managed-cargo-gc"


class CargoGcError(RuntimeError):
    """Raised when Cargo cache lifecycle evidence is incomplete or changed."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expand_home(template: str, home: Path) -> Path:
    if not template.startswith("${HOME}/"):
        raise CargoGcError("managed path is not HOME-rooted")
    return home / template.removeprefix("${HOME}/")


def _retention_policy(policy: dict[str, Any]) -> dict[str, int]:
    value = policy.get("cargo_cache_retention")
    if not isinstance(value, dict):
        raise CargoGcError("cargo_cache_retention policy is required")
    names = (
        "minimum_unused_seconds",
        "target_total_bytes",
        "max_total_bytes",
        "max_cleanup_per_run_bytes",
        "max_cleanup_candidates_per_run",
    )
    result: dict[str, int] = {}
    for name in names:
        item = value.get(name)
        minimum = 1 if name == "max_cleanup_candidates_per_run" else 0
        if not isinstance(item, int) or isinstance(item, bool) or item < minimum:
            requirement = "positive" if minimum else "non-negative"
            raise CargoGcError(
                f"cargo_cache_retention.{name} must be {requirement} integer"
            )
        result[name] = item
    if result["target_total_bytes"] > result["max_total_bytes"]:
        raise CargoGcError("cargo cache target_total_bytes must not exceed max_total_bytes")
    return result


def _tree_observation(path: Path) -> dict[str, Any]:
    """Return allocated bytes plus strict and touch-stable tree fingerprints.

    Symlinks are recorded as leaf entries and are never traversed. Cross-device or
    nested mount points are rejected because recursive deletion must not cross a
    managed identity filesystem boundary.
    """
    strict_rows: list[list[Any]] = []
    stable_rows: list[list[Any]] = []
    allocated = 0
    root_info = path.lstat()
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise CargoGcError(f"managed cache root is not a real directory: {path}")
    root_device = root_info.st_dev
    stack = [path]
    while stack:
        current = stack.pop()
        info = current.lstat()
        relative = "." if current == path else current.relative_to(path).as_posix()
        mode_type = stat.S_IFMT(info.st_mode)
        strict_rows.append([relative, mode_type, info.st_size, info.st_mtime_ns])
        stable_rows.append([relative, mode_type, info.st_size])
        if stat.S_ISLNK(info.st_mode):
            continue
        if current != path and (info.st_dev != root_device or os.path.ismount(current)):
            raise CargoGcError(f"managed cache crosses a filesystem or mount boundary: {current}")
        if stat.S_ISREG(info.st_mode):
            allocated += info.st_blocks * 512
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise CargoGcError(f"managed cache contains unsupported filesystem entry: {current}")
        with os.scandir(current) as entries:
            children = sorted((Path(entry.path) for entry in entries), reverse=True)
        stack.extend(children)
    strict_fingerprint = _sha256_json(strict_rows)
    return {
        "allocated_bytes": allocated,
        "entry_count": len(strict_rows),
        "tree_fingerprint_sha256": strict_fingerprint,
        "strict_tree_fingerprint_sha256": strict_fingerprint,
        "stable_tree_fingerprint_sha256": _sha256_json(stable_rows),
    }


def _cache_lock_path(state_root: Path, cache_key: str) -> Path:
    if CACHE_KEY_RE.fullmatch(cache_key) is None:
        raise CargoGcError("managed Cargo cache key is invalid for lifecycle lock")
    return state_root / "cache-locks" / "cargo" / f"{cache_key}.lock"


@contextmanager
def _exclusive_cache_lock(state_root: Path, cache_key: str, *, home: Path):
    lock_path = _cache_lock_path(state_root, cache_key)
    lock_root = lock_path.parent
    try:
        mb._ensure_secure_directory(lock_root, home)
    except mb.ManagedBuildError as exc:
        raise CargoGcError("managed Cargo lifecycle lock root is unsafe") from exc
    try:
        resolved_root = lock_root.resolve(strict=True)
        resolved_root.relative_to(home.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise CargoGcError("managed Cargo lifecycle lock root is unsafe") from exc
    if resolved_root != lock_root or lock_root.is_symlink() or not lock_root.is_dir():
        raise CargoGcError("managed Cargo lifecycle lock root is unsafe")
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise CargoGcError(f"cannot open managed Cargo lifecycle lock: {cache_key}") from exc
    handle = os.fdopen(fd, "r+")
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CargoGcError(f"managed Cargo lifecycle lock is held: {cache_key}") from exc
        yield lock_path
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def _parse_iso_epoch(value: Any) -> int | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def _load_local_usage(state_root: Path, cache_root: Path) -> tuple[dict[str, dict[str, Any]], str]:
    usage: dict[str, dict[str, Any]] = {}
    digest_rows: list[list[Any]] = []
    sources = (
        (state_root / "receipts", {"heim_pc.managed_build_receipt"}),
        (state_root / "binding-receipts", {"heim_pc.managed_build_binding_receipt"}),
        (state_root / "usage-receipts", {"heim_pc.managed_cargo_usage_receipt"}),
    )
    for receipts, accepted_kinds in sources:
        if not receipts.exists():
            continue
        if receipts.is_symlink() or not receipts.is_dir():
            raise CargoGcError(f"managed-build receipt path is unsafe: {receipts}")
        for path in sorted(receipts.glob("*.json")):
            if path.is_symlink() or not path.is_file():
                raise CargoGcError(f"managed-build receipt is not a regular file: {path}")
            digest = _sha256_file(path)
            digest_rows.append([receipts.name, path.name, digest])
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise CargoGcError(f"cannot read managed-build receipt {path}: {exc}") from exc
            if payload.get("kind") not in accepted_kinds or payload.get("tool") != "cargo":
                continue
            key = payload.get("cache_key")
            raw_path = payload.get("cache_path")
            repo_id = payload.get("repository_identity_sha256")
            if not isinstance(key, str) or CACHE_KEY_RE.fullmatch(key) is None:
                continue
            expected = cache_root / key
            if raw_path != str(expected):
                raise CargoGcError(f"Cargo receipt cache path does not match cache key: {path}")
            if repo_id is not None and (
                not isinstance(repo_id, str) or CACHE_KEY_RE.fullmatch(repo_id) is None
            ):
                raise CargoGcError(f"Cargo receipt repository identity is invalid: {path}")
            if payload.get("kind") != "heim_pc.managed_cargo_usage_receipt" and repo_id is None:
                raise CargoGcError(f"Cargo receipt repository identity is missing: {path}")
            used = payload.get("last_used_at_unix")
            if not isinstance(used, int) or isinstance(used, bool) or used < 0:
                used = (
                    _parse_iso_epoch(payload.get("finished_at"))
                    or _parse_iso_epoch(payload.get("started_at"))
                    or _parse_iso_epoch(payload.get("observed_at"))
                )
            if used is None:
                used = int(path.stat().st_mtime)
            current = usage.setdefault(
                key,
                {
                    "repository_identity_sha256": repo_id,
                    "last_used_at_unix": used,
                    "receipt_count": 0,
                },
            )
            known_repo = current["repository_identity_sha256"]
            if known_repo is not None and repo_id is not None and known_repo != repo_id:
                raise CargoGcError(f"Cargo cache key has conflicting repository provenance: {key}")
            if known_repo is None and repo_id is not None:
                current["repository_identity_sha256"] = repo_id
            current["last_used_at_unix"] = max(current["last_used_at_unix"], used)
            current["receipt_count"] += 1
    return usage, _sha256_json(digest_rows)


def _load_external_evidence(path: Path | None, cache_root: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    if path is None:
        return {}, {
            "present": False,
            "complete": False,
            "sha256": None,
            "observation_errors": ["external task protection evidence is required for cleanup"],
        }
    if path.is_symlink() or not path.is_file():
        raise CargoGcError("external evidence must be a regular non-symlink file")
    digest = _sha256_file(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CargoGcError(f"cannot read external Cargo evidence: {exc}") from exc
    if payload.get("schema_version") != 1 or payload.get("kind") != EVIDENCE_KIND:
        raise CargoGcError("external Cargo evidence contract is incompatible")
    reported_evidence_sha = payload.get("evidence_sha256")
    evidence_core = {
        key: value for key, value in payload.items() if key != "evidence_sha256"
    }
    if (
        not isinstance(reported_evidence_sha, str)
        or not CACHE_KEY_RE.fullmatch(reported_evidence_sha)
        or reported_evidence_sha != _sha256_json(evidence_core)
    ):
        raise CargoGcError("external Cargo evidence hash is invalid")
    complete = payload.get("complete") is True
    errors = payload.get("observation_errors", [])
    entries = payload.get("entries")
    if not isinstance(errors, list) or any(not isinstance(item, str) for item in errors):
        raise CargoGcError("external Cargo evidence observation_errors are invalid")
    if not isinstance(entries, list):
        raise CargoGcError("external Cargo evidence entries must be a list")
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise CargoGcError("external Cargo evidence entry must be an object")
        key = entry.get("cache_key")
        raw_path = entry.get("cache_path")
        if not isinstance(key, str) or CACHE_KEY_RE.fullmatch(key) is None:
            raise CargoGcError("external Cargo evidence cache_key is invalid")
        if raw_path != str(cache_root / key):
            raise CargoGcError("external Cargo evidence cache_path escapes or mismatches cache root")
        if key in result:
            raise CargoGcError(f"external Cargo evidence duplicates cache key: {key}")
        protected = entry.get("protected")
        last_used = entry.get("last_used_at_unix")
        repo_id = entry.get("repository_identity_sha256")
        reasons = entry.get("reasons", [])
        task_refs = entry.get("task_refs", [])
        if not isinstance(protected, bool):
            raise CargoGcError("external Cargo evidence protected must be boolean")
        if last_used is not None and (not isinstance(last_used, int) or isinstance(last_used, bool) or last_used < 0):
            raise CargoGcError("external Cargo evidence last_used_at_unix is invalid")
        if repo_id is not None and (not isinstance(repo_id, str) or CACHE_KEY_RE.fullmatch(repo_id) is None):
            raise CargoGcError("external Cargo evidence repository identity is invalid")
        if not isinstance(reasons, list) or any(not isinstance(item, str) for item in reasons):
            raise CargoGcError("external Cargo evidence reasons are invalid")
        if not isinstance(task_refs, list):
            raise CargoGcError("external Cargo evidence task_refs must be a list")
        result[key] = {
            "protected": protected,
            "last_used_at_unix": last_used,
            "repository_identity_sha256": repo_id,
            "reasons": sorted(set(reasons)),
            "task_refs": task_refs,
        }
    return result, {
        "present": True,
        "complete": complete and not errors,
        "sha256": digest,
        "evidence_sha256": reported_evidence_sha,
        "observation_errors": errors,
    }


def _process_may_reference_managed_cargo(process: Path, cache_root: Path) -> bool:
    build_process_names = {
        "cargo",
        "rustc",
        "rustdoc",
        "clippy-driver",
        "sccache",
        "build-script-build",
    }
    try:
        comm = (process / "comm").read_text(encoding="utf-8").strip()
    except OSError:
        comm = ""
    if comm in build_process_names:
        return True
    try:
        cwd = (process / "cwd").resolve()
        cwd.relative_to(cache_root)
        return True
    except (OSError, ValueError):
        pass
    try:
        cmdline = (process / "cmdline").read_bytes()
    except OSError:
        cmdline = b""
    return str(cache_root).encode("utf-8") in cmdline


def _live_process_references(
    cache_root: Path, proc_root: Path = Path("/proc")
) -> tuple[dict[str, list[int]], list[str]]:
    refs: dict[str, list[int]] = {}
    errors: list[str] = []
    uid = os.getuid()
    try:
        processes = sorted(
            (item for item in proc_root.iterdir() if item.name.isdigit()),
            key=lambda item: int(item.name),
        )
    except OSError as exc:
        return {}, [f"cannot enumerate process table: {type(exc).__name__}"]
    for process in processes:
        try:
            if process.stat().st_uid != uid:
                continue
            environ = (process / "environ").read_bytes()
        except FileNotFoundError:
            continue
        except PermissionError:
            if _process_may_reference_managed_cargo(process, cache_root):
                errors.append(
                    f"cannot inspect environment for possible Cargo process {process.name}"
                )
            continue
        except OSError as exc:
            if _process_may_reference_managed_cargo(process, cache_root):
                errors.append(
                    f"cannot inspect environment for possible Cargo process {process.name}: {type(exc).__name__}"
                )
            continue
        values = [
            item.removeprefix(b"CARGO_TARGET_DIR=")
            for item in environ.split(b"\0")
            if item.startswith(b"CARGO_TARGET_DIR=")
        ]
        for raw in values:
            try:
                target = Path(raw.decode("utf-8"))
            except UnicodeDecodeError:
                errors.append(f"same-user process {process.name} has non-UTF8 CARGO_TARGET_DIR")
                continue
            if not target.is_absolute() or ".." in target.parts:
                errors.append(f"same-user process {process.name} has non-normalized CARGO_TARGET_DIR")
                continue
            try:
                relative = target.relative_to(cache_root)
            except ValueError:
                continue
            if len(relative.parts) != 2 or relative.parts[1] != "target":
                errors.append(f"same-user process {process.name} has unsupported managed Cargo target shape")
                continue
            key = relative.parts[0]
            if CACHE_KEY_RE.fullmatch(key) is None:
                continue
            refs.setdefault(key, []).append(int(process.name))
    return {key: sorted(set(pids)) for key, pids in sorted(refs.items())}, sorted(set(errors))


def _active_cargo_pins(state_root: Path, now_unix: int) -> dict[str, dict[str, Any]]:
    pins_root = state_root / "pins"
    result: dict[str, dict[str, Any]] = {}
    if not pins_root.exists():
        return result
    if pins_root.is_symlink() or not pins_root.is_dir():
        raise CargoGcError("managed-build pins path is unsafe")
    for path in sorted(pins_root.glob("*-cargo.json")):
        if path.is_symlink() or not path.is_file():
            raise CargoGcError(f"managed-build pin is not a regular file: {path}")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CargoGcError(f"cannot read managed-build pin {path}: {exc}") from exc
        repo_id = payload.get("repository_identity_sha256")
        expires = payload.get("expires_at_unix")
        valid = (
            payload.get("schema_version") == 1
            and payload.get("tool") == "cargo"
            and isinstance(repo_id, str)
            and CACHE_KEY_RE.fullmatch(repo_id) is not None
            and isinstance(payload.get("reason"), str)
            and bool(payload["reason"].strip())
            and isinstance(expires, int)
            and not isinstance(expires, bool)
            and expires >= 0
        )
        if not valid:
            raise CargoGcError(f"managed-build Cargo pin is malformed: {path}")
        if expires > now_unix:
            result[repo_id] = {
                "path": str(path),
                "reason": payload["reason"],
                "expires_at_unix": expires,
                "sha256": _sha256_file(path),
            }
    return result


def _pin_for_identity(
    active_pins: dict[str, dict[str, Any]], repo_id: str | None
) -> dict[str, Any] | None:
    if repo_id is None:
        return None
    return active_pins.get(repo_id)


def inventory(
    policy: dict[str, Any],
    *,
    home: Path,
    evidence_path: Path | None = None,
    now_unix: int | None = None,
) -> dict[str, Any]:
    now = int(time.time()) if now_unix is None else now_unix
    cache_root = _expand_home(policy["cache_root"], home) / "cargo"
    state_root = _expand_home(policy["state_root"], home)
    local_usage, local_usage_sha = _load_local_usage(state_root, cache_root)
    external, external_meta = _load_external_evidence(evidence_path, cache_root)
    active_cargo_pins = _active_cargo_pins(state_root, now)
    process_refs, process_errors = _live_process_references(cache_root)
    process_meta = {
        "complete": not process_errors,
        "observation_errors": process_errors,
        "referenced_cache_count": len(process_refs),
    }
    managed: list[dict[str, Any]] = []
    unclassified: list[dict[str, Any]] = []
    total = 0
    if cache_root.exists():
        if cache_root.is_symlink() or not cache_root.is_dir():
            raise CargoGcError("managed Cargo cache root is unsafe")
        for child in sorted(cache_root.iterdir(), key=lambda item: item.name):
            try:
                info = child.lstat()
            except OSError as exc:
                raise CargoGcError(f"cannot inspect Cargo cache child {child}: {exc}") from exc
            if CACHE_KEY_RE.fullmatch(child.name) is None:
                unclassified.append({"path": str(child), "name": child.name, "reason": "non_identity_name"})
                continue
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                unclassified.append({"path": str(child), "name": child.name, "reason": "identity_path_not_real_directory"})
                continue
            try:
                observation = _tree_observation(child)
            except CargoGcError as exc:
                unclassified.append({"path": str(child), "name": child.name, "reason": str(exc)})
                continue
            total += observation["allocated_bytes"]
            local = local_usage.get(child.name)
            ext = external.get(child.name)
            repo_ids = {
                item
                for item in (
                    local.get("repository_identity_sha256") if local else None,
                    ext.get("repository_identity_sha256") if ext else None,
                )
                if item is not None
            }
            provenance_conflict = len(repo_ids) > 1
            repo_id = next(iter(repo_ids)) if len(repo_ids) == 1 else None
            used_values = [
                value
                for value in (
                    local.get("last_used_at_unix") if local else None,
                    ext.get("last_used_at_unix") if ext else None,
                )
                if isinstance(value, int)
            ]
            last_used = max(used_values) if used_values else None
            reasons: list[str] = []
            protected = False
            if not external_meta["complete"]:
                protected = True
                reasons.append("external_protection_evidence_incomplete")
            if not process_meta["complete"]:
                protected = True
                reasons.append("process_observation_incomplete")
            live_pids = process_refs.get(child.name, [])
            if live_pids:
                protected = True
                reasons.append("live_process_reference")
            if provenance_conflict:
                protected = True
                reasons.append("repository_provenance_conflict")
            if repo_id is None and active_cargo_pins:
                protected = True
                reasons.append("repository_provenance_unknown_with_active_pins")
            if last_used is None:
                protected = True
                reasons.append("usage_provenance_unknown")
            if ext and ext["protected"]:
                protected = True
                reasons.extend(ext["reasons"] or ["task_lifecycle_protection"])
            pin = _pin_for_identity(active_cargo_pins, repo_id)
            if pin is not None:
                protected = True
                reasons.append("unexpired_pin")
            managed.append(
                {
                    "cache_key": child.name,
                    "cache_path": str(child),
                    **observation,
                    "repository_identity_sha256": repo_id,
                    "last_used_at_unix": last_used,
                    "local_receipt_count": local.get("receipt_count", 0) if local else 0,
                    "external_task_refs": ext.get("task_refs", []) if ext else [],
                    "live_process_pids": live_pids,
                    "protected": protected,
                    "protection_reasons": sorted(set(reasons)),
                    "pin": pin,
                }
            )
    return {
        "schema_version": 1,
        "kind": "heim_pc.managed_cargo_cache_inventory",
        "cache_root": str(cache_root),
        "state_root": str(state_root),
        "observed_at_unix": now,
        "total_managed_allocated_bytes": total,
        "managed": managed,
        "unclassified": unclassified,
        "local_usage_sha256": local_usage_sha,
        "external_evidence": external_meta,
        "process_observation": process_meta,
        "does_not_establish": [
            "permission to delete unclassified paths",
            "permission to delete a protected cache identity",
            "absence of active consumers when external evidence is incomplete",
        ],
    }


def build_plan(
    policy: dict[str, Any],
    *,
    home: Path,
    evidence_path: Path | None,
    now_unix: int | None = None,
) -> dict[str, Any]:
    current = inventory(policy, home=home, evidence_path=evidence_path, now_unix=now_unix)
    retention = _retention_policy(policy)
    now = current["observed_at_unix"]
    candidates_pool: list[dict[str, Any]] = []
    protected: list[dict[str, Any]] = []
    for entry in current["managed"]:
        reasons = list(entry["protection_reasons"])
        last_used = entry["last_used_at_unix"]
        if not entry["protected"] and last_used is not None:
            age = max(0, now - last_used)
            if age < retention["minimum_unused_seconds"]:
                reasons.append("minimum_unused_age_not_reached")
        else:
            age = None if last_used is None else max(0, now - last_used)
        projected = {**entry, "unused_seconds": age, "selection_reasons": sorted(set(reasons))}
        if reasons:
            protected.append(projected)
        else:
            candidates_pool.append(projected)
    total = current["total_managed_allocated_bytes"]
    required_reclaim = max(0, total - retention["target_total_bytes"])
    over_limit = total > retention["max_total_bytes"]
    selected: list[dict[str, Any]] = []
    selected_bytes = 0
    oversized_eligible: list[dict[str, Any]] = []
    candidate_limit_reached = False
    if (
        over_limit
        and current["external_evidence"]["complete"]
        and current["process_observation"]["complete"]
    ):
        for entry in sorted(
            candidates_pool,
            key=lambda item: (-item["allocated_bytes"], item["cache_key"]),
        ):
            if selected_bytes >= required_reclaim:
                break
            if entry["allocated_bytes"] > retention["max_cleanup_per_run_bytes"]:
                oversized_eligible.append(
                    {
                        **entry,
                        "selection_blocker": "identity_exceeds_max_cleanup_per_run_bytes",
                        "required_max_cleanup_per_run_bytes": entry["allocated_bytes"],
                    }
                )
                continue
            if len(selected) >= retention["max_cleanup_candidates_per_run"]:
                candidate_limit_reached = True
                break
            proposed = selected_bytes + entry["allocated_bytes"]
            if proposed > retention["max_cleanup_per_run_bytes"]:
                continue
            selected.append(entry)
            selected_bytes = proposed
    oversized_keys = {entry["cache_key"] for entry in oversized_eligible}
    convergence_blockers: list[dict[str, Any]] = []
    if oversized_eligible and selected_bytes < required_reclaim:
        convergence_blockers.append(
            {
                "kind": "oversized_identity_requires_policy_override",
                "cache_keys": [entry["cache_key"] for entry in oversized_eligible],
                "minimum_required_max_cleanup_per_run_bytes": min(
                    entry["allocated_bytes"] for entry in oversized_eligible
                ),
            }
        )
    if candidate_limit_reached and selected_bytes < required_reclaim:
        convergence_blockers.append(
            {
                "kind": "candidate_count_limit_reached",
                "max_cleanup_candidates_per_run": retention[
                    "max_cleanup_candidates_per_run"
                ],
            }
        )
    core = {
        "schema_version": 1,
        "kind": PLAN_KIND,
        "cache_root": current["cache_root"],
        "state_root": current["state_root"],
        "evaluated_at_unix": now,
        "policy_sha256": _sha256_json(policy),
        "retention": retention,
        "total_managed_allocated_bytes": total,
        "over_max_total": over_limit,
        "required_reclaim_bytes": required_reclaim,
        "expected_reclaim_bytes": selected_bytes,
        "candidates": selected,
        "eligible_not_selected": [
            entry
            for entry in candidates_pool
            if entry not in selected and entry["cache_key"] not in oversized_keys
        ],
        "oversized_eligible": oversized_eligible,
        "convergence_blockers": convergence_blockers,
        "protected": protected,
        "unclassified": current["unclassified"],
        "local_usage_sha256": current["local_usage_sha256"],
        "external_evidence": current["external_evidence"],
        "process_observation": current["process_observation"],
        "safe_to_apply": (
            bool(selected)
            and current["external_evidence"]["complete"]
            and current["process_observation"]["complete"]
        ),
        "confirmation": CONFIRMATION,
        "does_not_establish": current["does_not_establish"] + [
            "automatic cleanup authorization",
            "permission to delete named legacy cache directories",
            "permission to exceed max_cleanup_per_run_bytes without an explicit policy change",
        ],
    }
    return {**core, "plan_sha256": _sha256_json(core)}


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def snapshot_external_usage(
    policy: dict[str, Any],
    *,
    home: Path,
    evidence_path: Path,
    now_unix: int | None = None,
) -> dict[str, Any]:
    now = int(time.time()) if now_unix is None else now_unix
    cache_root = _expand_home(policy["cache_root"], home) / "cargo"
    state_root = _expand_home(policy["state_root"], home)
    external, external_meta = _load_external_evidence(evidence_path, cache_root)
    if not external_meta["complete"]:
        raise CargoGcError("external task evidence is incomplete and cannot be snapshotted")
    local_usage, _ = _load_local_usage(state_root, cache_root)
    receipt_root = state_root / "usage-receipts"
    written: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for key, entry in sorted(external.items()):
        cache_path = cache_root / key
        try:
            info = cache_path.lstat()
        except FileNotFoundError:
            skipped.append({"cache_key": key, "reason": "cache_identity_not_present"})
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            skipped.append({"cache_key": key, "reason": "cache_identity_not_real_directory"})
            continue
        external_last_used = entry.get("last_used_at_unix")
        if not isinstance(external_last_used, int):
            skipped.append({"cache_key": key, "reason": "external_last_used_unknown"})
            continue
        existing = local_usage.get(key)
        last_used = max(
            external_last_used,
            int(existing["last_used_at_unix"]) if existing is not None else 0,
        )
        external_repo = entry.get("repository_identity_sha256")
        existing_repo = (
            existing.get("repository_identity_sha256") if existing is not None else None
        )
        if (
            external_repo is not None
            and existing_repo is not None
            and external_repo != existing_repo
        ):
            raise CargoGcError(f"Cargo cache key has conflicting repository provenance: {key}")
        repo_id = external_repo or existing_repo
        receipt = {
            "schema_version": 1,
            "kind": "heim_pc.managed_cargo_usage_receipt",
            "tool": "cargo",
            "observed_at_unix": now,
            "cache_key": key,
            "cache_path": str(cache_path),
            "repository_identity_sha256": repo_id,
            "last_used_at_unix": last_used,
            "source_evidence_sha256": external_meta["evidence_sha256"],
            "source_evidence_file_sha256": external_meta["sha256"],
            "task_ref_count": len(entry.get("task_refs", [])),
        }
        receipt_path = receipt_root / f"{key}.json"
        _atomic_json(receipt_path, receipt)
        written.append(
            {
                "cache_key": key,
                "receipt_path": str(receipt_path),
                "receipt_sha256": _sha256_file(receipt_path),
                "last_used_at_unix": last_used,
            }
        )
    return {
        "schema_version": 1,
        "kind": "heim_pc.managed_cargo_usage_snapshot",
        "observed_at_unix": now,
        "source_evidence_sha256": external_meta["evidence_sha256"],
        "source_evidence_file_sha256": external_meta["sha256"],
        "written": written,
        "skipped": skipped,
        "does_not_establish": [
            "cache deletion authority",
            "repository identity when historical task evidence did not persist it",
            "absence of active consumers after the evidence snapshot time",
        ],
    }


def apply_plan(
    policy: dict[str, Any],
    *,
    home: Path,
    plan_path: Path,
    evidence_path: Path,
    expected_plan_sha256: str,
    confirmation: str,
) -> dict[str, Any]:
    if confirmation != CONFIRMATION:
        raise CargoGcError(f"confirmation must be exactly {CONFIRMATION!r}")
    if plan_path.is_symlink() or not plan_path.is_file():
        raise CargoGcError("plan must be a regular non-symlink file")
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CargoGcError(f"cannot read Cargo GC plan: {exc}") from exc
    stored_sha = plan.get("plan_sha256")
    core = {key: value for key, value in plan.items() if key != "plan_sha256"}
    actual_sha = _sha256_json(core)
    if stored_sha != actual_sha or expected_plan_sha256 != actual_sha:
        raise CargoGcError("Cargo GC plan hash does not match expected plan")
    if plan.get("kind") != PLAN_KIND or plan.get("schema_version") != 1:
        raise CargoGcError("Cargo GC plan contract is incompatible")
    if not plan.get("safe_to_apply") or not plan.get("candidates"):
        raise CargoGcError("Cargo GC plan has no safe cleanup candidates")
    if plan.get("policy_sha256") != _sha256_json(policy):
        raise CargoGcError("Cargo GC policy changed after planning")
    retention = _retention_policy(policy)
    candidates = plan.get("candidates")
    if not isinstance(candidates, list):
        raise CargoGcError("Cargo GC plan candidates are invalid")
    if len(candidates) > retention["max_cleanup_candidates_per_run"]:
        raise CargoGcError("Cargo GC plan exceeds max_cleanup_candidates_per_run")
    planned_bytes = 0
    candidate_keys: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise CargoGcError("Cargo GC plan candidate is invalid")
        key = candidate.get("cache_key")
        if not isinstance(key, str) or CACHE_KEY_RE.fullmatch(key) is None:
            raise CargoGcError("Cargo GC plan candidate cache_key is invalid")
        if key in candidate_keys:
            raise CargoGcError(f"Cargo GC plan duplicates candidate cache_key: {key}")
        candidate_keys.add(key)
        value = candidate.get("allocated_bytes")
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise CargoGcError("Cargo GC plan candidate allocated_bytes is invalid")
        planned_bytes += value
    if planned_bytes > retention["max_cleanup_per_run_bytes"]:
        raise CargoGcError("Cargo GC plan exceeds max_cleanup_per_run_bytes")
    if not getattr(shutil.rmtree, "avoids_symlink_attacks", False):
        raise CargoGcError("platform rmtree is not symlink-attack resistant")
    current = inventory(
        policy,
        home=home,
        evidence_path=evidence_path,
        now_unix=int(time.time()),
    )
    if current["local_usage_sha256"] != plan.get("local_usage_sha256"):
        raise CargoGcError("managed-build usage receipts changed after planning")
    if current["external_evidence"].get("sha256") != plan.get("external_evidence", {}).get("sha256"):
        raise CargoGcError("external task evidence changed after planning")
    if not current["external_evidence"]["complete"]:
        raise CargoGcError("external task evidence is incomplete at apply time")
    by_key = {entry["cache_key"]: entry for entry in current["managed"]}
    before_bytes = current["total_managed_allocated_bytes"]
    root = Path(current["cache_root"])
    state_root = Path(current["state_root"])
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise CargoGcError("managed Cargo cache root is unavailable at apply time") from exc
    if resolved_root != root or root.is_symlink():
        raise CargoGcError("managed Cargo cache root contains a symlink boundary")

    prepared_candidates: list[dict[str, Any]] = []
    for candidate in candidates:
        key = candidate["cache_key"]
        observed = by_key.get(key)
        if observed is None:
            raise CargoGcError(f"candidate disappeared before apply: {key}")
        if observed["protected"] or observed["protection_reasons"]:
            raise CargoGcError(f"candidate became protected before apply: {key}")
        path = Path(observed["cache_path"])
        if path.parent != root or path.name != key:
            raise CargoGcError(f"candidate path is not one exact managed identity: {key}")
        try:
            resolved_path = path.resolve(strict=True)
        except OSError as exc:
            raise CargoGcError(f"candidate path is unavailable before apply: {key}") from exc
        if resolved_path.parent != resolved_root:
            raise CargoGcError(f"candidate path escapes managed Cargo root: {key}")
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise CargoGcError(f"candidate path type changed before apply: {key}")
        expected_strict = candidate.get(
            "strict_tree_fingerprint_sha256",
            candidate.get("tree_fingerprint_sha256"),
        )
        if not isinstance(expected_strict, str) or CACHE_KEY_RE.fullmatch(expected_strict) is None:
            raise CargoGcError(f"candidate strict tree fingerprint is invalid: {key}")
        prepared_candidates.append(
            {
                "candidate": candidate,
                "key": key,
                "path": path,
                "expected_strict": expected_strict,
            }
        )

    removed: list[dict[str, Any]] = []
    effect_started = False
    failure: str | None = None
    failed_candidate_cache_key: str | None = None
    post_observation_error: str | None = None
    after: dict[str, Any] | None = None
    receipt_path: Path | None = None
    receipt: dict[str, Any] | None = None

    with ExitStack() as stack:
        lock_paths: dict[str, Path] = {}
        for item in sorted(prepared_candidates, key=lambda value: value["key"]):
            lock_paths[item["key"]] = stack.enter_context(
                _exclusive_cache_lock(state_root, item["key"], home=home)
            )

        # Validate every candidate while all managed producers are fenced, before
        # the first destructive effect.
        for item in prepared_candidates:
            latest_observation = _tree_observation(item["path"])
            if (
                latest_observation["strict_tree_fingerprint_sha256"]
                != item["expected_strict"]
            ):
                raise CargoGcError(
                    f"candidate tree changed after planning: {item['key']}"
                )

        initial_process_refs, initial_process_errors = _live_process_references(root)
        if initial_process_errors:
            raise CargoGcError("process observation became incomplete before apply")
        initially_referenced = sorted(
            item["key"]
            for item in prepared_candidates
            if initial_process_refs.get(item["key"])
        )
        if initially_referenced:
            raise CargoGcError(
                "candidates acquired live process references before apply: "
                + ",".join(initially_referenced)
            )

        for item in prepared_candidates:
            key = item["key"]
            path = item["path"]
            # Recheck drift and non-cooperating processes immediately before each
            # rmtree. Managed Grabowski producers cannot enter because all candidate
            # locks remain exclusively held until the final receipt is written.
            try:
                latest_observation = _tree_observation(path)
                if (
                    latest_observation["strict_tree_fingerprint_sha256"]
                    != item["expected_strict"]
                ):
                    raise CargoGcError(f"candidate tree changed before deletion: {key}")
                latest_process_refs, latest_process_errors = _live_process_references(root)
                if latest_process_errors:
                    raise CargoGcError(
                        "process observation became incomplete before deletion"
                    )
                if latest_process_refs.get(key):
                    raise CargoGcError(
                        f"candidate acquired a live process reference before deletion: {key}"
                    )
            except (CargoGcError, OSError) as exc:
                if not effect_started:
                    raise
                failure = str(exc)
                failed_candidate_cache_key = key
                break

            effect_started = True
            try:
                shutil.rmtree(path)
                if path.exists() or path.is_symlink():
                    raise CargoGcError(
                        f"candidate still exists after locked deletion: {key}"
                    )
            except (CargoGcError, OSError) as exc:
                failure = f"candidate deletion failed for {key}: {exc}"
                failed_candidate_cache_key = key
                break
            removed.append(
                {
                    "cache_key": key,
                    "cache_path": str(path),
                    "planned_bytes": item["candidate"]["allocated_bytes"],
                    "lifecycle_lock_path": str(lock_paths[key]),
                }
            )

        if effect_started:
            try:
                after = inventory(
                    policy,
                    home=home,
                    evidence_path=evidence_path,
                    now_unix=int(time.time()),
                )
            except (CargoGcError, OSError) as exc:
                post_observation_error = f"{type(exc).__name__}: {exc}"

            reappeared_while_locked: list[str] = []
            if after is not None:
                remaining_keys = {entry["cache_key"] for entry in after["managed"]}
                reappeared_while_locked = sorted(
                    item["cache_key"]
                    for item in removed
                    if item["cache_key"] in remaining_keys
                )
                if reappeared_while_locked and failure is None:
                    failure = (
                        "removed cache identities reappeared while lifecycle locks were held: "
                        + ",".join(reappeared_while_locked)
                    )

            applied_at_unix_ns = time.time_ns()
            applied_at = applied_at_unix_ns // 1_000_000_000
            status = "success"
            if failure is not None:
                status = "partial_failure"
            elif post_observation_error is not None:
                status = "post_observation_incomplete"
            receipt = {
                "schema_version": 1,
                "kind": RECEIPT_KIND,
                "status": status,
                "applied_at_unix": applied_at,
                "applied_at_unix_ns": applied_at_unix_ns,
                "plan_sha256": actual_sha,
                "policy_sha256": _sha256_json(policy),
                "external_evidence_sha256": current["external_evidence"]["sha256"],
                "before_allocated_bytes": before_bytes,
                "after_allocated_bytes": (
                    after["total_managed_allocated_bytes"] if after is not None else None
                ),
                "reclaimed_bytes": (
                    max(0, before_bytes - after["total_managed_allocated_bytes"])
                    if after is not None
                    else None
                ),
                "removed": removed,
                "reappeared_while_locked": reappeared_while_locked,
                "failure": failure,
                "failed_candidate_cache_key": failed_candidate_cache_key,
                "post_observation_error": post_observation_error,
                "remaining_managed_count": (len(after["managed"]) if after is not None else None),
                "remaining_unclassified_count": (
                    len(after["unclassified"]) if after is not None else None
                ),
            }
            receipt_path = (
                state_root
                / "gc-receipts"
                / f"{applied_at_unix_ns}-{actual_sha[:16]}.json"
            )
            _atomic_json(receipt_path, receipt)
            mb._trim_receipts(receipt_path.parent, int(policy["max_receipts"]))

    if not effect_started:
        raise CargoGcError("Cargo GC apply produced no effect")
    if receipt_path is None or receipt is None:
        raise CargoGcError("Cargo GC apply effect was not receipted")
    result = {
        "receipt_path": str(receipt_path),
        "receipt_sha256": _sha256_file(receipt_path),
        "receipt": receipt,
    }
    if failure is not None or post_observation_error is not None:
        detail = failure or post_observation_error or "unknown post-effect failure"
        raise CargoGcError(
            f"Cargo GC apply had a partial or unverified effect; receipt={receipt_path}; error={detail}"
        )
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=mb.DEFAULT_POLICY_PATH)
    sub = parser.add_subparsers(dest="operation", required=True)
    inventory_parser = sub.add_parser("inventory")
    inventory_parser.add_argument("--evidence", type=Path)
    inventory_parser.add_argument("--now-unix", type=int)
    plan_parser = sub.add_parser("plan")
    plan_parser.add_argument("--evidence", type=Path)
    plan_parser.add_argument("--now-unix", type=int)
    plan_parser.add_argument("--output", type=Path)
    snapshot_parser = sub.add_parser("snapshot-evidence")
    snapshot_parser.add_argument("--evidence", type=Path, required=True)
    snapshot_parser.add_argument("--now-unix", type=int)
    apply_parser = sub.add_parser("apply")
    apply_parser.add_argument("--plan", type=Path, required=True)
    apply_parser.add_argument("--evidence", type=Path, required=True)
    apply_parser.add_argument("--expected-plan-sha256", required=True)
    apply_parser.add_argument("--confirmation", required=True)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    try:
        policy = mb.load_policy(args.policy)
        home = Path(os.environ.get("HOME", "~")).expanduser().resolve()
        if args.operation == "inventory":
            result = inventory(policy, home=home, evidence_path=args.evidence, now_unix=args.now_unix)
        elif args.operation == "plan":
            result = build_plan(policy, home=home, evidence_path=args.evidence, now_unix=args.now_unix)
            if args.output is not None:
                _atomic_json(args.output, result)
        elif args.operation == "snapshot-evidence":
            result = snapshot_external_usage(
                policy,
                home=home,
                evidence_path=args.evidence,
                now_unix=args.now_unix,
            )
        else:
            result = apply_plan(
                policy,
                home=home,
                plan_path=args.plan,
                evidence_path=args.evidence,
                expected_plan_sha256=args.expected_plan_sha256,
                confirmation=args.confirmation,
            )
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        return 0
    except (CargoGcError, mb.PolicyError, mb.ManagedBuildError, OSError) as exc:
        print(json.dumps({"schema_version": 1, "kind": "heim_pc.managed_cargo_gc_error", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
