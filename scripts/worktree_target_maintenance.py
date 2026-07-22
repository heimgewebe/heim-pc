#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Any, Callable, Iterable
import uuid

SCHEMA_VERSION = 1
PLAN_KIND = "heim_pc_worktree_target_plan"
RECEIPT_KIND = "heim_pc_worktree_target_receipt"
OBSERVATION_KIND = "grabowski_process_reference_observation"
PROCESS_ACTION = "observe_process_references"
DEFAULT_POLICY = Path(__file__).resolve().parents[1] / "config" / "worktree-target-policy.v1.json"
DEFAULT_STATE_ROOT = Path.home() / ".local/state/heim-pc/worktree-target-maintenance"
DEFAULT_BROKER_CLIENT = Path("/usr/local/bin/grabowski-privileged-request")
MAX_OBSERVER_ROOTS = 256
BROKER_TIMEOUT_SECONDS = 45


class MaintenanceError(RuntimeError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_json(path: Path, value: Any, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_metadata = path.parent.lstat()
    if path.parent.is_symlink() or not stat.S_ISDIR(parent_metadata.st_mode) or parent_metadata.st_uid != os.getuid() or parent_metadata.st_mode & 0o077:
        raise MaintenanceError(f"unsafe private state directory: {path.parent}")
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8"))
            handle.write(b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def path_inside(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((str(path), str(root))) == str(root)
    except ValueError:
        return False


def canonical_existing_directory(raw: Any, *, label: str, owner_uid: int) -> Path:
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise MaintenanceError(f"{label} is invalid")
    path = Path(raw)
    if not path.is_absolute() or os.path.normpath(raw) != raw:
        raise MaintenanceError(f"{label} must be canonical and absolute")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise MaintenanceError(f"{label} cannot be inspected: {path}") from exc
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or path.resolve(strict=True) != path:
        raise MaintenanceError(f"{label} is not a canonical directory: {path}")
    if metadata.st_uid != owner_uid:
        raise MaintenanceError(f"{label} owner mismatch: {path}")
    return path


def bounded_int(value: Any, *, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise MaintenanceError(f"{label} is invalid")
    return value


def load_policy(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    try:
        value = json.loads(data)
    except json.JSONDecodeError as exc:
        raise MaintenanceError("policy JSON is invalid") from exc
    required = {
        "schema_version", "kind", "owner_uid", "automatic_apply",
        "warning_bytes", "hard_bytes", "warning_min_age_seconds",
        "hard_min_age_seconds", "max_candidates_per_run",
        "max_remove_bytes_per_run", "max_tree_entries", "repositories",
        "quarantine_root",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise MaintenanceError("policy keys are invalid")
    if value["schema_version"] != 1 or value["kind"] != "heim_pc.worktree_target_policy":
        raise MaintenanceError("policy contract is unsupported")
    owner_uid = bounded_int(value["owner_uid"], label="owner_uid", minimum=0, maximum=2**31 - 1)
    if not isinstance(value["automatic_apply"], bool):
        raise MaintenanceError("automatic_apply is invalid")
    warning = bounded_int(value["warning_bytes"], label="warning_bytes", minimum=1, maximum=2**63 - 1)
    hard = bounded_int(value["hard_bytes"], label="hard_bytes", minimum=warning + 1, maximum=2**63 - 1)
    repositories = value["repositories"]
    if not isinstance(repositories, list) or not repositories:
        raise MaintenanceError("repositories must be non-empty")
    normalized_repositories = []
    seen_repositories: set[str] = set()
    for record in repositories:
        if not isinstance(record, dict) or set(record) != {"repository", "worktree_roots"}:
            raise MaintenanceError("repository policy record is invalid")
        repository = canonical_existing_directory(record["repository"], label="repository", owner_uid=owner_uid)
        if not (repository / ".git").exists():
            raise MaintenanceError(f"repository has no Git metadata: {repository}")
        roots_value = record["worktree_roots"]
        if not isinstance(roots_value, list) or not roots_value:
            raise MaintenanceError("worktree_roots must be non-empty")
        roots = [canonical_existing_directory(item, label="worktree_root", owner_uid=owner_uid) for item in roots_value]
        if str(repository) in seen_repositories:
            raise MaintenanceError("repository is duplicated")
        seen_repositories.add(str(repository))
        normalized_repositories.append({"repository": str(repository), "worktree_roots": sorted({str(item) for item in roots})})
    quarantine = Path(value["quarantine_root"])
    if not quarantine.is_absolute() or os.path.normpath(str(quarantine)) != str(quarantine):
        raise MaintenanceError("quarantine_root must be canonical and absolute")
    if not path_inside(quarantine, Path.home() / "repos"):
        raise MaintenanceError("quarantine_root is outside the repository filesystem")
    normalized = {
        **value,
        "owner_uid": owner_uid,
        "warning_bytes": warning,
        "hard_bytes": hard,
        "warning_min_age_seconds": bounded_int(value["warning_min_age_seconds"], label="warning_min_age_seconds", minimum=0, maximum=365 * 86400),
        "hard_min_age_seconds": bounded_int(value["hard_min_age_seconds"], label="hard_min_age_seconds", minimum=0, maximum=365 * 86400),
        "max_candidates_per_run": bounded_int(value["max_candidates_per_run"], label="max_candidates_per_run", minimum=1, maximum=128),
        "max_remove_bytes_per_run": bounded_int(value["max_remove_bytes_per_run"], label="max_remove_bytes_per_run", minimum=1, maximum=2**63 - 1),
        "max_tree_entries": bounded_int(value["max_tree_entries"], label="max_tree_entries", minimum=1, maximum=10_000_000),
        "repositories": normalized_repositories,
        "quarantine_root": str(quarantine),
        "policy_sha256": hashlib.sha256(data).hexdigest(),
    }
    if normalized["hard_min_age_seconds"] > normalized["warning_min_age_seconds"]:
        raise MaintenanceError("hard_min_age_seconds must not exceed warning_min_age_seconds")
    return normalized


def tree_snapshot(root: Path, *, owner_uid: int, max_entries: int) -> dict[str, Any]:
    metadata = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != owner_uid:
        raise MaintenanceError(f"unsafe target root: {root}")
    root_device = metadata.st_dev
    identity = {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mtime_ns": metadata.st_mtime_ns,
    }
    tree_hasher = hashlib.sha256()
    identity_bytes = canonical_bytes(identity)
    tree_hasher.update(len(identity_bytes).to_bytes(8, "big"))
    tree_hasher.update(identity_bytes)
    total_bytes = metadata.st_blocks * 512
    newest_mtime_ns = metadata.st_mtime_ns
    entry_count = 0
    stack = [(root, Path("."))]
    while stack:
        directory, relative = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise MaintenanceError(f"target tree cannot be scanned: {directory}") from exc
        child_directories = []
        for entry in entries:
            entry_count += 1
            if entry_count > max_entries:
                raise MaintenanceError(f"target tree entry limit exceeded: {root}")
            item_path = Path(entry.path)
            item_relative = relative / entry.name
            item = entry.stat(follow_symlinks=False)
            if item.st_uid != owner_uid or item.st_dev != root_device:
                raise MaintenanceError(f"target tree ownership or filesystem boundary changed: {item_path}")
            mode = stat.S_IFMT(item.st_mode)
            record = (
                str(item_relative), item.st_dev, item.st_ino, mode,
                stat.S_IMODE(item.st_mode), item.st_uid, item.st_gid,
                item.st_size, item.st_mtime_ns,
            )
            record_bytes = canonical_bytes(record)
            tree_hasher.update(len(record_bytes).to_bytes(8, "big"))
            tree_hasher.update(record_bytes)
            total_bytes += item.st_blocks * 512
            newest_mtime_ns = max(newest_mtime_ns, item.st_mtime_ns)
            if stat.S_ISDIR(item.st_mode):
                child_directories.append((item_path, item_relative))
        stack.extend(reversed(child_directories))
    return {
        "path": str(root),
        "identity": identity,
        "entry_count": entry_count,
        "size_bytes": total_bytes,
        "newest_mtime_ns": newest_mtime_ns,
        "tree_sha256": tree_hasher.hexdigest(),
    }


def create_reference(action: str, target: str, justification: str) -> dict[str, Any]:
    now = int(time.time())
    value = {
        "schema_version": 1,
        "execution": "unprivileged-reference-only",
        "may_execute": False,
        "requires_external_privileged_agent": True,
        "replay_policy": "single-use-external-broker",
        "action": action,
        "target": target,
        "justification": justification,
        "request_id": uuid.uuid4().hex,
        "created_at_unix": now,
        "expires_at_unix": now + 300,
    }
    value["reference_sha256"] = canonical_sha256(value)
    return value


def validate_observation(value: Any, *, roots: list[str], owner_uid: int, max_processes: int, max_fds: int) -> dict[str, Any]:
    required = {"kind", "schema_version", "complete", "target_uid", "roots", "process_count", "open_file_descriptors_checked", "path_references", "errors", "observation_sha256"}
    if not isinstance(value, dict) or set(value) != required:
        raise MaintenanceError("process observation keys are invalid")
    material = dict(value)
    digest = material.pop("observation_sha256")
    if not isinstance(digest, str) or digest != canonical_sha256(material):
        raise MaintenanceError("process observation hash is invalid")
    if value["kind"] != OBSERVATION_KIND or value["schema_version"] != 1:
        raise MaintenanceError("process observation contract is invalid")
    if value["target_uid"] != owner_uid or value["roots"] != roots or not isinstance(value["complete"], bool):
        raise MaintenanceError("process observation request binding is invalid")
    process_count = value["process_count"]
    descriptor_count = value["open_file_descriptors_checked"]
    if isinstance(process_count, bool) or not isinstance(process_count, int) or not 0 <= process_count <= max_processes:
        raise MaintenanceError("process observation count is invalid")
    if isinstance(descriptor_count, bool) or not isinstance(descriptor_count, int) or not 0 <= descriptor_count <= max_fds:
        raise MaintenanceError("process observation descriptor count is invalid")
    errors = value["errors"]
    if not isinstance(errors, list) or errors != sorted(set(errors)) or not all(isinstance(item, str) and item for item in errors):
        raise MaintenanceError("process observation errors are invalid")
    if value["complete"] != (not errors):
        raise MaintenanceError("process observation completeness conflicts with errors")
    references = value["path_references"]
    if not isinstance(references, list) or len(references) > 64:
        raise MaintenanceError("process observation references are invalid")
    tuples = []
    for item in references:
        if not isinstance(item, dict) or set(item) != {"pid", "uid", "kind", "root", "path"}:
            raise MaintenanceError("process observation item is invalid")
        pid = item["pid"]
        uid = item["uid"]
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise MaintenanceError("process observation pid is invalid")
        if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
            raise MaintenanceError("process observation uid is invalid")
        if item["root"] not in roots or item["kind"] not in {"cwd", "exe", "root", "fd"}:
            raise MaintenanceError("process observation item binding is invalid")
        path = item["path"]
        if not isinstance(path, str) or os.path.normpath(path) != path or not path_inside(Path(path), Path(item["root"])):
            raise MaintenanceError("process observation path escapes root")
        tuples.append((pid, uid, item["kind"], item["root"], path))
    if tuples != sorted(set(tuples)):
        raise MaintenanceError("process observation items are not stable and unique")
    return value


def observe_processes(roots: list[Path], *, owner_uid: int, state_root: Path, client: Path = DEFAULT_BROKER_CLIENT, max_processes: int = 8192, max_fds: int = 131072) -> dict[str, Any]:
    normalized = sorted(str(root) for root in roots)
    target = json.dumps({"schema_version": 1, "target_uid": owner_uid, "roots": normalized, "max_processes": max_processes, "max_file_descriptors": max_fds}, sort_keys=True, separators=(",", ":"))
    reference = create_reference(PROCESS_ACTION, target, "Observe process references before bounded worktree target cleanup")
    reference_root = state_root / "references"
    reference_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = reference_root / f"{reference['request_id']}.json"
    atomic_json(path, reference)
    try:
        completed = subprocess.run([str(client), str(path)], cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=BROKER_TIMEOUT_SECONDS, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    finally:
        path.unlink(missing_ok=True)
    if completed.returncode != 0:
        raise MaintenanceError("process observation broker request failed")
    try:
        outer = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MaintenanceError("process observation broker response is invalid") from exc
    if not isinstance(outer, dict) or outer.get("returncode") != 0 or outer.get("timed_out") is not False or not isinstance(outer.get("stdout"), str):
        raise MaintenanceError("process observation broker execution failed")
    try:
        inner = json.loads(outer["stdout"])
    except json.JSONDecodeError as exc:
        raise MaintenanceError("process observer output is invalid") from exc
    return validate_observation(inner, roots=normalized, owner_uid=owner_uid, max_processes=max_processes, max_fds=max_fds)


def default_inventory(repository: str) -> dict[str, Any]:
    try:
        import grabowski_checkouts
    except ModuleNotFoundError as exc:
        raise MaintenanceError("Grabowski runtime modules are unavailable") from exc
    return grabowski_checkouts.checkout_inventory(repository, include_processes=False, include_tasks=True, include_resources=True)


def worktree_allowed(path: Path, roots: Iterable[Path]) -> bool:
    return any(path_inside(path, root) for root in roots)


def lifecycle_reason(record: dict[str, Any]) -> str | None:
    if record.get("is_main") is True:
        return "main-worktree"
    if record.get("exists") is not True or record.get("prunable") is True:
        return "missing-or-prunable"
    status = record.get("status")
    if not isinstance(status, dict) or status.get("dirty") is not False:
        return "dirty-or-unknown"
    decision = record.get("lifecycle_decision")
    if not isinstance(decision, dict) or decision.get("state") != "unclassified_clean":
        return "retained-archived-or-classified"
    coordination = record.get("coordination")
    if not isinstance(coordination, dict) or coordination.get("blocking") is not False:
        return "active-lease-task-or-process"
    return None


def collect_plan(policy: dict[str, Any], *, state_root: Path, inventory_provider: Callable[[str], dict[str, Any]] = default_inventory, observer: Callable[..., dict[str, Any]] = observe_processes, now: int | None = None) -> dict[str, Any]:
    current = int(time.time()) if now is None else now
    all_targets: list[dict[str, Any]] = []
    exclusions: list[dict[str, str]] = []
    observer_roots: list[Path] = []
    eligible_by_path: dict[str, dict[str, Any]] = {}
    for repository_policy in policy["repositories"]:
        repository = repository_policy["repository"]
        roots = [Path(item) for item in repository_policy["worktree_roots"]]
        inventory = inventory_provider(repository)
        records = inventory.get("worktrees") if isinstance(inventory, dict) else None
        if not isinstance(records, list):
            raise MaintenanceError(f"checkout inventory is invalid: {repository}")
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("path"), str):
                continue
            worktree = Path(record["path"])
            if not worktree_allowed(worktree, roots):
                continue
            target = worktree / "target"
            if not target.exists():
                continue
            try:
                snapshot = tree_snapshot(target, owner_uid=policy["owner_uid"], max_entries=policy["max_tree_entries"])
            except (MaintenanceError, OSError) as exc:
                exclusions.append({"path": str(target), "reason": f"unsafe-target:{exc}"})
                continue
            item = {"repository": repository, "worktree": str(worktree), "head": record.get("head"), "branch": record.get("branch"), "target": str(target), "snapshot": snapshot}
            all_targets.append(item)
            reason = lifecycle_reason(record)
            if reason is not None:
                exclusions.append({"path": str(target), "reason": reason})
                continue
            eligible_by_path[str(target)] = item
            observer_roots.append(target)
    total = sum(item["snapshot"]["size_bytes"] for item in all_targets)
    threshold, min_age = threshold_for_total(policy, total)
    observation: dict[str, Any] | None = None
    eligible: list[dict[str, Any]] = []
    if observer_roots:
        if len(observer_roots) > MAX_OBSERVER_ROOTS:
            observation = {
                "complete": False,
                "path_references": [],
                "observation_sha256": None,
            }
            for target in sorted(eligible_by_path):
                exclusions.append({"path": target, "reason": "process-observer-root-limit"})
        else:
            observation = observer(observer_roots, owner_uid=policy["owner_uid"], state_root=state_root)
        references = {item["root"] for item in observation["path_references"]}
        for target, item in sorted(eligible_by_path.items()):
            if not observation["complete"]:
                exclusions.append({"path": target, "reason": "process-observation-incomplete"})
                continue
            if target in references:
                exclusions.append({"path": target, "reason": "active-process-reference"})
                continue
            age = current - item["snapshot"]["newest_mtime_ns"] // 1_000_000_000
            if age < min_age:
                exclusions.append({"path": target, "reason": "younger-than-threshold"})
                continue
            candidate_id = canonical_sha256({"repository": item["repository"], "worktree": item["worktree"], "target": target, "head": item["head"], "branch": item["branch"], "tree_sha256": item["snapshot"]["tree_sha256"]})[:24]
            eligible.append({**item, "candidate_id": candidate_id, "age_seconds": age})
    eligible.sort(key=lambda item: (item["snapshot"]["newest_mtime_ns"], -item["snapshot"]["size_bytes"], item["target"]))
    selected = []
    selected_bytes = 0
    projected = total
    if threshold != "ok":
        for item in eligible:
            size = item["snapshot"]["size_bytes"]
            if len(selected) >= policy["max_candidates_per_run"] or selected_bytes + size > policy["max_remove_bytes_per_run"]:
                exclusions.append({"path": item["target"], "reason": "per-run-budget"})
                continue
            selected.append(item)
            selected_bytes += size
            projected -= size
            if projected < policy["warning_bytes"]:
                break
    material = {
        "schema_version": SCHEMA_VERSION,
        "kind": PLAN_KIND,
        "generated_at_unix": current,
        "policy_sha256": policy["policy_sha256"],
        "threshold": threshold,
        "total_target_bytes": total,
        "projected_target_bytes": projected,
        "selected_bytes": selected_bytes,
        "selected": selected,
        "exclusions": sorted(exclusions, key=lambda item: (item["path"], item["reason"])),
        "process_observation_sha256": observation.get("observation_sha256") if observation else None,
        "process_observation_complete": observation.get("complete") if observation else True,
        "automatic_apply_authorized": policy["automatic_apply"],
    }
    plan_id = canonical_sha256(material)
    return {**material, "plan_id": plan_id, "plan_sha256": canonical_sha256({**material, "plan_id": plan_id})}


def write_plan(plan: dict[str, Any], state_root: Path) -> Path:
    path = state_root / "plans" / f"{plan['plan_id']}.json"
    atomic_json(path, plan)
    return path


def load_plan(path: Path, expected_sha256: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise MaintenanceError("expected plan hash is invalid")
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise MaintenanceError("plan path is not a regular non-symlink file")
    if metadata.st_uid != os.getuid() or metadata.st_nlink != 1 or metadata.st_mode & 0o077:
        raise MaintenanceError("plan file ownership or mode is unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise MaintenanceError("plan JSON is not an object")
    supplied = value.get("plan_sha256")
    material = dict(value)
    material.pop("plan_sha256", None)
    if supplied != expected_sha256 or canonical_sha256(material) != expected_sha256:
        raise MaintenanceError("plan hash is invalid")
    if value.get("kind") != PLAN_KIND or value.get("schema_version") != 1:
        raise MaintenanceError("plan contract is invalid")
    plan_id = material.pop("plan_id", None)
    if not isinstance(plan_id, str) or plan_id != canonical_sha256(material):
        raise MaintenanceError("plan id is invalid")
    return value


def current_record_map(policy: dict[str, Any], inventory_provider: Callable[[str], dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for repo_policy in policy["repositories"]:
        repository = repo_policy["repository"]
        inventory = inventory_provider(repository)
        records = inventory.get("worktrees") if isinstance(inventory, dict) else None
        if not isinstance(records, list):
            raise MaintenanceError(f"checkout inventory is invalid: {repository}")
        for record in records:
            if isinstance(record, dict) and isinstance(record.get("path"), str):
                result[(repository, record["path"])] = record
    return result


def threshold_for_total(policy: dict[str, Any], total_bytes: int) -> tuple[str, int]:
    if total_bytes >= policy["hard_bytes"]:
        return "hard", policy["hard_min_age_seconds"]
    if total_bytes >= policy["warning_bytes"]:
        return "warning", policy["warning_min_age_seconds"]
    return "ok", policy["warning_min_age_seconds"]


def current_budget_state(
    policy: dict[str, Any],
    inventory_provider: Callable[[str], dict[str, Any]],
) -> tuple[dict[tuple[str, str], dict[str, Any]], dict[tuple[str, str], dict[str, Any]], int]:
    records: dict[tuple[str, str], dict[str, Any]] = {}
    snapshots: dict[tuple[str, str], dict[str, Any]] = {}
    total_bytes = 0
    for repo_policy in policy["repositories"]:
        repository = repo_policy["repository"]
        roots = [Path(item) for item in repo_policy["worktree_roots"]]
        inventory = inventory_provider(repository)
        raw_records = inventory.get("worktrees") if isinstance(inventory, dict) else None
        if not isinstance(raw_records, list):
            raise MaintenanceError(f"checkout inventory is invalid: {repository}")
        for record in raw_records:
            if not isinstance(record, dict) or not isinstance(record.get("path"), str):
                continue
            worktree = Path(record["path"])
            records[(repository, str(worktree))] = record
            if not worktree_allowed(worktree, roots):
                continue
            target = worktree / "target"
            if not target.exists():
                continue
            try:
                snapshot = tree_snapshot(
                    target,
                    owner_uid=policy["owner_uid"],
                    max_entries=policy["max_tree_entries"],
                )
            except (MaintenanceError, OSError):
                continue
            snapshots[(repository, str(worktree))] = snapshot
            total_bytes += snapshot["size_bytes"]
    return records, snapshots, total_bytes


def validate_plan_candidate(item: Any, policy: dict[str, Any]) -> tuple[Path, Path]:
    required = {
        "repository", "worktree", "head", "branch", "target", "snapshot",
        "candidate_id", "age_seconds",
    }
    if not isinstance(item, dict) or set(item) != required:
        raise MaintenanceError("plan candidate keys are invalid")
    repository = item.get("repository")
    worktree_raw = item.get("worktree")
    target_raw = item.get("target")
    candidate_id = item.get("candidate_id")
    if not isinstance(repository, str) or not isinstance(worktree_raw, str) or not isinstance(target_raw, str):
        raise MaintenanceError("plan candidate paths are invalid")
    if not isinstance(candidate_id, str) or not re.fullmatch(r"[0-9a-f]{24}", candidate_id):
        raise MaintenanceError("plan candidate id is invalid")
    repository_policy = next(
        (record for record in policy["repositories"] if record["repository"] == repository),
        None,
    )
    if repository_policy is None:
        raise MaintenanceError("plan candidate repository is outside policy")
    worktree = Path(worktree_raw)
    target = Path(target_raw)
    if not worktree.is_absolute() or os.path.normpath(worktree_raw) != worktree_raw:
        raise MaintenanceError("plan candidate worktree is not canonical")
    roots = [Path(raw) for raw in repository_policy["worktree_roots"]]
    if not worktree_allowed(worktree, roots):
        raise MaintenanceError("plan candidate worktree is outside policy roots")
    expected_target = worktree / "target"
    if target != expected_target or os.path.normpath(target_raw) != target_raw:
        raise MaintenanceError("plan candidate target is not the worktree target")
    snapshot = item.get("snapshot")
    if not isinstance(snapshot, dict) or set(snapshot) != {
        "path", "identity", "entry_count", "size_bytes", "newest_mtime_ns", "tree_sha256"
    }:
        raise MaintenanceError("plan candidate snapshot is invalid")
    if snapshot.get("path") != target_raw or not re.fullmatch(r"[0-9a-f]{64}", str(snapshot.get("tree_sha256", ""))):
        raise MaintenanceError("plan candidate snapshot binding is invalid")
    if not isinstance(snapshot.get("identity"), dict) or set(snapshot["identity"]) != {
        "device", "inode", "mode", "uid", "gid", "mtime_ns"
    }:
        raise MaintenanceError("plan candidate identity is invalid")
    if isinstance(item.get("age_seconds"), bool) or not isinstance(item.get("age_seconds"), int) or item["age_seconds"] < 0:
        raise MaintenanceError("plan candidate age is invalid")
    expected_candidate_id = canonical_sha256({
        "repository": repository,
        "worktree": worktree_raw,
        "target": target_raw,
        "head": item.get("head"),
        "branch": item.get("branch"),
        "tree_sha256": snapshot["tree_sha256"],
    })[:24]
    if candidate_id != expected_candidate_id:
        raise MaintenanceError("plan candidate identity hash is invalid")
    return worktree, target


def ensure_quarantine(path: Path, *, owner_uid: int) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != owner_uid or metadata.st_mode & 0o077:
        raise MaintenanceError("quarantine root is unsafe")


def apply_plan(plan_path: Path, *, expected_sha256: str, confirmation: str, policy_path: Path, state_root: Path, inventory_provider: Callable[[str], dict[str, Any]] = default_inventory, observer: Callable[..., dict[str, Any]] = observe_processes) -> dict[str, Any]:
    policy = load_policy(policy_path)
    plan = load_plan(plan_path, expected_sha256)
    if confirmation != f"APPLY:{plan['plan_id']}":
        raise MaintenanceError("apply confirmation is invalid")
    if plan["policy_sha256"] != policy["policy_sha256"]:
        raise MaintenanceError("policy changed after plan")
    selected = plan.get("selected")
    if not isinstance(selected, list) or not selected:
        raise MaintenanceError("plan has no selected candidates")
    validated_candidates = []
    seen_targets: set[str] = set()
    for item in selected:
        worktree, target = validate_plan_candidate(item, policy)
        if str(target) in seen_targets:
            raise MaintenanceError("plan contains duplicate targets")
        seen_targets.add(str(target))
        validated_candidates.append((item, worktree, target))
    if plan.get("selected_bytes") != sum(item["snapshot"]["size_bytes"] for item, _, _ in validated_candidates):
        raise MaintenanceError("plan selected byte total is invalid")
    lock_path = state_root / "apply.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise MaintenanceError("another maintenance instance is currently applying a plan") from exc
        receipt_path = state_root / "receipts" / f"{plan['plan_id']}.json"
        if receipt_path.exists():
            existing = json.loads(receipt_path.read_text(encoding="utf-8"))
            if existing.get("success") is True and existing.get("plan_sha256") == expected_sha256:
                return existing
            raise MaintenanceError("an incomplete receipt already exists")
        records, current_snapshots, current_total_bytes = current_budget_state(
            policy, inventory_provider
        )
        current_threshold, current_min_age = threshold_for_total(
            policy, current_total_bytes
        )
        if current_threshold == "ok":
            raise MaintenanceError("current target budget no longer authorizes cleanup")
        plan_total_bytes = plan.get("total_target_bytes")
        plan_projected_bytes = plan.get("projected_target_bytes")
        if (
            isinstance(plan_total_bytes, bool)
            or not isinstance(plan_total_bytes, int)
            or plan_total_bytes < 0
            or plan.get("threshold") != current_threshold
            or plan_total_bytes > current_total_bytes
            or plan.get("automatic_apply_authorized") != policy["automatic_apply"]
        ):
            raise MaintenanceError("target budget state changed after plan")
        if (
            len(validated_candidates) > policy["max_candidates_per_run"]
            or plan["selected_bytes"] > policy["max_remove_bytes_per_run"]
            or isinstance(plan_projected_bytes, bool)
            or not isinstance(plan_projected_bytes, int)
            or plan_projected_bytes != plan_total_bytes - plan["selected_bytes"]
        ):
            raise MaintenanceError("plan exceeds target cleanup budget")
        generated_at = plan.get("generated_at_unix")
        if (
            isinstance(generated_at, bool)
            or not isinstance(generated_at, int)
            or generated_at > int(time.time())
        ):
            raise MaintenanceError("plan generation time is invalid")
        targets = [target for _, _, target in validated_candidates]
        fresh_observation = observer(targets, owner_uid=policy["owner_uid"], state_root=state_root)
        if not fresh_observation["complete"] or fresh_observation["path_references"]:
            raise MaintenanceError("fresh process observation blocks apply")
        prepared = []
        for item, worktree, target in validated_candidates:
            record = records.get((item["repository"], str(worktree)))
            if record is None or lifecycle_reason(record) is not None or record.get("head") != item["head"] or record.get("branch") != item["branch"]:
                raise MaintenanceError(f"worktree lifecycle changed: {item['worktree']}")
            snapshot = current_snapshots.get((item["repository"], str(worktree)))
            if snapshot is None or snapshot != item["snapshot"]:
                raise MaintenanceError(f"target changed after plan: {target}")
            current_age = int(time.time()) - snapshot["newest_mtime_ns"] // 1_000_000_000
            planned_age = generated_at - snapshot["newest_mtime_ns"] // 1_000_000_000
            if item["age_seconds"] != planned_age or current_age < current_min_age:
                raise MaintenanceError(f"target age no longer satisfies policy: {target}")
            prepared.append((item, snapshot))
        quarantine_root = Path(policy["quarantine_root"]) / plan["plan_id"]
        ensure_quarantine(quarantine_root, owner_uid=policy["owner_uid"])
        quarantine_device = quarantine_root.stat().st_dev
        outcomes = []
        success = False
        try:
            for item, snapshot in prepared:
                target = Path(item["target"])
                destination = quarantine_root / item["candidate_id"]
                if destination.exists():
                    raise MaintenanceError(f"quarantine destination exists: {destination}")
                if target.stat().st_dev != quarantine_device:
                    raise MaintenanceError(
                        f"quarantine root is on a different filesystem than target: {target}"
                    )
                pending = {
                    "candidate_id": item["candidate_id"],
                    "target": str(target),
                    "destination": str(destination),
                    "snapshot": snapshot,
                }
                atomic_json(receipt_path, {
                    "schema_version": 1,
                    "kind": RECEIPT_KIND,
                    "success": False,
                    "state": "prepared",
                    "plan_id": plan["plan_id"],
                    "plan_sha256": expected_sha256,
                    "policy_sha256": policy["policy_sha256"],
                    "outcomes": outcomes,
                    "pending": pending,
                    "process_observation_sha256": fresh_observation["observation_sha256"],
                })
                os.rename(target, destination)
                try:
                    moved = tree_snapshot(destination, owner_uid=policy["owner_uid"], max_entries=policy["max_tree_entries"])
                    if moved["tree_sha256"] != snapshot["tree_sha256"] or moved["identity"] != snapshot["identity"]:
                        raise MaintenanceError(f"target identity changed during quarantine move: {target}")
                    post_move_observation = observer(
                        [destination], owner_uid=policy["owner_uid"], state_root=state_root
                    )
                    if not post_move_observation["complete"] or post_move_observation["path_references"]:
                        raise MaintenanceError(f"post-move process observation blocks removal: {target}")
                    final_snapshot = tree_snapshot(
                        destination,
                        owner_uid=policy["owner_uid"],
                        max_entries=policy["max_tree_entries"],
                    )
                    if (
                        final_snapshot["tree_sha256"] != snapshot["tree_sha256"]
                        or final_snapshot["identity"] != snapshot["identity"]
                    ):
                        raise MaintenanceError(
                            f"target changed during post-move verification: {target}"
                        )
                except Exception:
                    if destination.exists() and not target.exists():
                        os.rename(destination, target)
                    atomic_json(receipt_path, {
                        "schema_version": 1,
                        "kind": RECEIPT_KIND,
                        "success": False,
                        "state": "rolled-back" if target.exists() and not destination.exists() else "recovery-required",
                        "plan_id": plan["plan_id"],
                        "plan_sha256": expected_sha256,
                        "policy_sha256": policy["policy_sha256"],
                        "outcomes": outcomes,
                        "pending": pending,
                        "process_observation_sha256": fresh_observation["observation_sha256"],
                    })
                    raise
                try:
                    shutil.rmtree(destination)
                except Exception:
                    atomic_json(receipt_path, {
                        "schema_version": 1,
                        "kind": RECEIPT_KIND,
                        "success": False,
                        "state": "recovery-required",
                        "plan_id": plan["plan_id"],
                        "plan_sha256": expected_sha256,
                        "policy_sha256": policy["policy_sha256"],
                        "outcomes": outcomes,
                        "pending": pending,
                        "process_observation_sha256": fresh_observation["observation_sha256"],
                    })
                    raise
                outcomes.append({
                    "candidate_id": item["candidate_id"],
                    "target": str(target),
                    "removed_bytes": snapshot["size_bytes"],
                    "result": "removed",
                    "post_move_tree_sha256": final_snapshot["tree_sha256"],
                    "post_move_observation_sha256": post_move_observation["observation_sha256"],
                })
                atomic_json(receipt_path, {"schema_version": 1, "kind": RECEIPT_KIND, "success": False, "plan_id": plan["plan_id"], "plan_sha256": expected_sha256, "policy_sha256": policy["policy_sha256"], "outcomes": outcomes, "current_candidate": item["candidate_id"], "process_observation_sha256": fresh_observation["observation_sha256"]})
            success = True
        finally:
            try:
                quarantine_root.rmdir()
            except OSError:
                pass
        receipt = {"schema_version": 1, "kind": RECEIPT_KIND, "success": success, "completed_at_unix": int(time.time()), "plan_id": plan["plan_id"], "plan_sha256": expected_sha256, "policy_sha256": policy["policy_sha256"], "process_observation_sha256": fresh_observation["observation_sha256"], "outcomes": outcomes, "removed_bytes": sum(item["removed_bytes"] for item in outcomes), "source_files_removed": False, "worktrees_removed": False}
        receipt["receipt_sha256"] = canonical_sha256(receipt)
        atomic_json(receipt_path, receipt)
        return receipt
    finally:
        os.close(lock_fd)


def reconcile(policy_path: Path, state_root: Path) -> dict[str, Any]:
    policy = load_policy(policy_path)
    plan = collect_plan(policy, state_root=state_root)
    plan_path = write_plan(plan, state_root)
    result: dict[str, Any] = {"plan": plan, "plan_path": str(plan_path), "apply": None}
    if policy["automatic_apply"] and plan["selected"] and plan["process_observation_complete"]:
        result["apply"] = apply_plan(plan_path, expected_sha256=plan["plan_sha256"], confirmation=f"APPLY:{plan['plan_id']}", policy_path=policy_path, state_root=state_root)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--state-root", type=Path, default=DEFAULT_STATE_ROOT)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan")
    apply = sub.add_parser("apply")
    apply.add_argument("--plan", type=Path, required=True)
    apply.add_argument("--expected-sha256", required=True)
    apply.add_argument("--confirmation", required=True)
    sub.add_parser("reconcile")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "plan":
        policy = load_policy(args.policy)
        plan = collect_plan(policy, state_root=args.state_root)
        path = write_plan(plan, args.state_root)
        output = {"plan": plan, "plan_path": str(path)}
    elif args.command == "apply":
        output = apply_plan(args.plan, expected_sha256=args.expected_sha256, confirmation=args.confirmation, policy_path=args.policy, state_root=args.state_root)
    else:
        output = reconcile(args.policy, args.state_root)
    print(json.dumps(output, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (MaintenanceError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, sort_keys=True))
        raise SystemExit(2)
