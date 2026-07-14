#!/usr/bin/env python3
"""Read-only storage lifecycle inventory for heim-pc."""

from __future__ import annotations

import argparse
from fnmatch import fnmatch
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
from typing import Any, Iterable

SCHEMA_VERSION = 1
KIND = "heim_pc.storage_inventory"


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class ScanResult:
    size_bytes: int
    apparent_size_bytes: int
    file_count: int
    directory_count: int
    error_count: int
    oldest_mtime: float | None
    newest_mtime: float | None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _iso_mtime(value: float | None) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


def _expand_path(raw: str, home: Path) -> Path:
    return Path(raw.replace("${HOME}", str(home), 1)).expanduser()


def load_policy(path: Path) -> dict[str, Any]:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"cannot read policy {path}: {exc}") from exc
    if policy.get("schema_version") != 1:
        raise PolicyError("unsupported policy schema_version")
    if policy.get("kind") != "heim_pc.storage_lifecycle_policy":
        raise PolicyError("unexpected policy kind")
    producers = policy.get("producers")
    if not isinstance(producers, list) or not producers:
        raise PolicyError("policy producers must be a non-empty list")
    seen: set[str] = set()
    for producer in producers:
        if not isinstance(producer, dict):
            raise PolicyError("producer must be an object")
        producer_id = producer.get("id")
        if not isinstance(producer_id, str) or not producer_id or producer_id in seen:
            raise PolicyError("producer ids must be unique non-empty strings")
        seen.add(producer_id)
        if producer.get("class") not in policy.get("classes", {}):
            raise PolicyError(f"unknown storage class for {producer_id}")
        if not isinstance(producer.get("owner"), str) or not producer["owner"]:
            raise PolicyError(f"producer {producer_id} requires owner")
        if not isinstance(producer.get("paths"), list) or not producer["paths"]:
            raise PolicyError(f"producer {producer_id} requires paths")
        budget = producer.get("budget_bytes", {})
        warning = budget.get("warning")
        hard = budget.get("hard")
        if not isinstance(warning, int) or not isinstance(hard, int) or warning < 0 or hard < warning:
            raise PolicyError(f"invalid budget for {producer_id}")
    discovery = policy.get("unowned_discovery")
    if discovery is not None:
        if not isinstance(discovery, dict):
            raise PolicyError("unowned_discovery must be an object")
        minimum = discovery.get("minimum_bytes")
        roots = discovery.get("roots")
        if not isinstance(minimum, int) or minimum < 0:
            raise PolicyError("unowned_discovery minimum_bytes must be a non-negative integer")
        if not isinstance(roots, list):
            raise PolicyError("unowned_discovery roots must be a list")
        for root in roots:
            if not isinstance(root, dict) or not isinstance(root.get("path"), str):
                raise PolicyError("unowned discovery root requires path")
            if root.get("max_depth") != 1:
                raise PolicyError("unowned discovery currently requires max_depth=1")
            globs = root.get("name_globs")
            if not isinstance(globs, list) or not globs or not all(isinstance(item, str) and item for item in globs):
                raise PolicyError("unowned discovery root requires non-empty name_globs")
    return policy


def _allocated_bytes(stat_result: os.stat_result) -> int:
    blocks = getattr(stat_result, "st_blocks", None)
    if isinstance(blocks, int) and blocks >= 0:
        return blocks * 512
    return stat_result.st_size


def _merge_mtime(current: float | None, candidate: float, *, oldest: bool) -> float:
    if current is None:
        return candidate
    return min(current, candidate) if oldest else max(current, candidate)


def scan_path(path: Path, *, cross_filesystems: bool = False) -> ScanResult:
    """Measure one path without following symlinks."""
    try:
        root_stat = path.lstat()
    except FileNotFoundError:
        return ScanResult(0, 0, 0, 0, 0, None, None)
    except OSError:
        return ScanResult(0, 0, 0, 0, 1, None, None)

    if path.is_symlink():
        return ScanResult(_allocated_bytes(root_stat), root_stat.st_size, 1, 0, 0, root_stat.st_mtime, root_stat.st_mtime)
    if path.is_file():
        return ScanResult(_allocated_bytes(root_stat), root_stat.st_size, 1, 0, 0, root_stat.st_mtime, root_stat.st_mtime)

    root_device = root_stat.st_dev
    size = _allocated_bytes(root_stat)
    apparent_size = root_stat.st_size
    files = 0
    directories = 1
    errors = 0
    oldest = root_stat.st_mtime
    newest = root_stat.st_mtime
    seen_inodes = {(root_stat.st_dev, root_stat.st_ino)}
    stack = [path]

    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        stat_result = entry.stat(follow_symlinks=False)
                    except OSError:
                        errors += 1
                        continue
                    inode_key = (stat_result.st_dev, stat_result.st_ino)
                    if inode_key not in seen_inodes:
                        seen_inodes.add(inode_key)
                        size += _allocated_bytes(stat_result)
                        apparent_size += stat_result.st_size
                    oldest = _merge_mtime(oldest, stat_result.st_mtime, oldest=True)
                    newest = _merge_mtime(newest, stat_result.st_mtime, oldest=False)
                    if entry.is_symlink():
                        files += 1
                    elif entry.is_dir(follow_symlinks=False):
                        directories += 1
                        if cross_filesystems or stat_result.st_dev == root_device:
                            stack.append(Path(entry.path))
                    else:
                        files += 1
        except OSError:
            errors += 1

    return ScanResult(size, apparent_size, files, directories, errors, oldest, newest)


def _is_covered(candidate: Path, known_paths: list[Path]) -> bool:
    candidate_text = os.path.abspath(candidate)
    for known in known_paths:
        known_text = os.path.abspath(known)
        try:
            if os.path.commonpath([candidate_text, known_text]) == known_text:
                return True
        except ValueError:
            continue
    return False


def discover_unowned(
    policy: dict[str, Any],
    *,
    home: Path,
    known_paths: list[Path],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    discovery = policy.get("unowned_discovery")
    if not discovery:
        return [], []
    minimum = discovery["minimum_bytes"]
    cross_filesystems = bool(policy["safety"].get("cross_filesystems", False))
    candidates: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    seen: set[str] = set()
    for root_spec in discovery["roots"]:
        root = _expand_path(root_spec["path"], home)
        try:
            root_stat = root.lstat()
            if root.is_symlink() or not root.is_dir():
                errors.append({"path": str(root), "error": "discovery_root_not_directory"})
                continue
            with os.scandir(root) as entries:
                for entry in entries:
                    if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                        continue
                    if not any(fnmatch(entry.name, pattern) for pattern in root_spec["name_globs"]):
                        continue
                    candidate = Path(entry.path)
                    candidate_key = os.path.abspath(candidate)
                    if candidate_key in seen or _is_covered(candidate, known_paths):
                        continue
                    seen.add(candidate_key)
                    result = scan_path(candidate, cross_filesystems=cross_filesystems)
                    if result.size_bytes < minimum:
                        continue
                    candidates.append({
                        "path": str(candidate),
                        "size_bytes": result.size_bytes,
                        "apparent_size_bytes": result.apparent_size_bytes,
                        "file_count": result.file_count,
                        "directory_count": result.directory_count,
                        "error_count": result.error_count,
                        "classification": "unowned_temporary_candidate",
                        "automatic_cleanup_authorized": False,
                    })
        except FileNotFoundError:
            errors.append({"path": str(root), "error": "discovery_root_missing"})
        except OSError as exc:
            errors.append({"path": str(root), "error": f"discovery_failed:{exc.errno}"})
    candidates.sort(key=lambda item: (-item["size_bytes"], item["path"]))
    errors.sort(key=lambda item: item["path"])
    return candidates, errors


def _producer_status(size: int, warning: int, hard: int, missing: bool, errors: int) -> str:
    if errors:
        return "degraded"
    if missing:
        return "missing"
    if size >= hard:
        return "hard_limit"
    if size >= warning:
        return "warning"
    return "ok"


def collect(policy: dict[str, Any], *, home: Path, filesystem_root: Path = Path("/")) -> dict[str, Any]:
    fs = os.statvfs(filesystem_root)
    total = fs.f_blocks * fs.f_frsize
    free = fs.f_bfree * fs.f_frsize
    available = fs.f_bavail * fs.f_frsize
    used = total - free
    used_percent = round((used / total * 100), 2) if total else 0.0

    records: list[dict[str, Any]] = []
    class_totals: dict[str, int] = {}
    for producer in policy["producers"]:
        paths = [_expand_path(raw, home) for raw in producer["paths"]]
        aggregate = ScanResult(0, 0, 0, 0, 0, None, None)
        existing = 0
        path_records: list[dict[str, Any]] = []
        for path in paths:
            exists = path.exists() or path.is_symlink()
            existing += int(exists)
            result = scan_path(path, cross_filesystems=bool(policy["safety"].get("cross_filesystems", False)))
            aggregate = ScanResult(
                aggregate.size_bytes + result.size_bytes,
                aggregate.apparent_size_bytes + result.apparent_size_bytes,
                aggregate.file_count + result.file_count,
                aggregate.directory_count + result.directory_count,
                aggregate.error_count + result.error_count,
                min(v for v in (aggregate.oldest_mtime, result.oldest_mtime) if v is not None)
                if aggregate.oldest_mtime is not None or result.oldest_mtime is not None else None,
                max(v for v in (aggregate.newest_mtime, result.newest_mtime) if v is not None)
                if aggregate.newest_mtime is not None or result.newest_mtime is not None else None,
            )
            path_records.append({
                "path": str(path),
                "exists": exists,
                "size_bytes": result.size_bytes,
                "apparent_size_bytes": result.apparent_size_bytes,
                "file_count": result.file_count,
                "directory_count": result.directory_count,
                "error_count": result.error_count,
            })
        budget = producer["budget_bytes"]
        status = _producer_status(
            aggregate.size_bytes,
            budget["warning"],
            budget["hard"],
            existing == 0,
            aggregate.error_count,
        )
        record = {
            "id": producer["id"],
            "class": producer["class"],
            "owner": producer["owner"],
            "cleanup_strategy": producer["cleanup_strategy"],
            "size_bytes": aggregate.size_bytes,
            "apparent_size_bytes": aggregate.apparent_size_bytes,
            "budget_bytes": budget,
            "status": status,
            "file_count": aggregate.file_count,
            "directory_count": aggregate.directory_count,
            "error_count": aggregate.error_count,
            "oldest_mtime": _iso_mtime(aggregate.oldest_mtime),
            "newest_mtime": _iso_mtime(aggregate.newest_mtime),
            "paths": path_records,
            "automatic_cleanup_authorized": False,
        }
        records.append(record)
        class_totals[producer["class"]] = class_totals.get(producer["class"], 0) + aggregate.size_bytes

    known_paths = [
        _expand_path(raw, home)
        for producer in policy["producers"]
        for raw in producer["paths"]
    ]
    unowned_candidates, discovery_errors = discover_unowned(
        policy, home=home, known_paths=known_paths
    )

    fs_thresholds = policy["filesystem_thresholds_percent"]
    if used_percent >= fs_thresholds["critical"]:
        filesystem_status = "critical"
    elif used_percent >= fs_thresholds["warning"]:
        filesystem_status = "warning"
    elif used_percent >= fs_thresholds["notice"]:
        filesystem_status = "notice"
    else:
        filesystem_status = "ok"

    temporary_total = sum(
        size for class_name, size in class_totals.items()
        if class_name in {"temporary_workspace", "regenerable_cache"}
    )
    temporary_budget = policy["global_temporary_budget_bytes"]
    if temporary_total >= temporary_budget["hard"]:
        temporary_status = "hard_limit"
    elif temporary_total >= temporary_budget["warning"]:
        temporary_status = "warning"
    else:
        temporary_status = "ok"

    payload = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "policy_id": policy["policy_id"],
        "generated_at": _utc_now(),
        "host": socket.gethostname(),
        "filesystem": {
            "path": str(filesystem_root),
            "total_bytes": total,
            "used_bytes": used,
            "free_bytes": free,
            "available_bytes": available,
            "reserved_bytes": max(free - available, 0),
            "used_percent": used_percent,
            "status": filesystem_status,
        },
        "class_totals_bytes": class_totals,
        "temporary_total_bytes": temporary_total,
        "temporary_status": temporary_status,
        "producers": records,
        "unowned_candidates": unowned_candidates,
        "unowned_discovery_errors": discovery_errors,
        "summary": {
            "producer_count": len(records),
            "warning_count": sum(r["status"] == "warning" for r in records),
            "hard_limit_count": sum(r["status"] == "hard_limit" for r in records),
            "degraded_count": sum(r["status"] in {"degraded", "missing"} for r in records),
            "unowned_candidate_count": len(unowned_candidates),
            "unowned_discovery_error_count": len(discovery_errors),
        },
        "does_not_establish": policy["safety"]["does_not_establish"],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["inventory_sha256"] = hashlib.sha256(canonical).hexdigest()
    return payload


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _owned_snapshot(path: Path, *, policy_id: str) -> bool:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            return False
        if metadata.st_uid != os.getuid() or metadata.st_nlink != 1:
            return False
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return value.get("kind") == KIND and value.get("policy_id") == policy_id


def publish_snapshot(state_dir: Path, payload: dict[str, Any], *, max_count: int) -> list[Path]:
    if max_count < 1:
        raise ValueError("max_count must be at least 1")
    state_dir.mkdir(parents=True, exist_ok=True)
    directory_metadata = state_dir.lstat()
    if state_dir.is_symlink() or not stat.S_ISDIR(directory_metadata.st_mode):
        raise ValueError("state_dir must be a real directory")
    if directory_metadata.st_uid != os.getuid():
        raise ValueError("state_dir must be owned by the current user")
    stamp = payload["generated_at"].replace(":", "").replace("-", "")
    snapshot = state_dir / f"storage-{stamp}.json"
    _atomic_write_json(snapshot, payload)
    _atomic_write_json(state_dir / "latest.json", payload)
    snapshots = sorted(
        (
            path for path in state_dir.glob("storage-*.json")
            if _owned_snapshot(path, policy_id=payload["policy_id"])
        ),
        key=lambda path: path.name,
        reverse=True,
    )
    for stale in snapshots[max_count:]:
        stale.unlink()
    return snapshots[:max_count]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=Path(__file__).resolve().parents[1] / "config/storage-lifecycle.v1.json")
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--filesystem-root", type=Path, default=Path("/"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--retention-count", type=int)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    policy = load_policy(args.policy)
    payload = collect(policy, home=args.home, filesystem_root=args.filesystem_root)
    if args.output:
        _atomic_write_json(args.output, payload)
    if args.state_dir:
        keep = args.retention_count or policy["snapshot_retention"]["max_count"]
        publish_snapshot(args.state_dir, payload, max_count=keep)
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
