#!/usr/bin/env python3
"""Run one bounded, evidence-bound managed Cargo cache maintenance wave."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import time
from typing import Any, Callable

try:
    from scripts import managed_build as mb
    from scripts import managed_cargo_gc as gc
except ImportError:  # Direct execution from scripts/.
    import managed_build as mb
    import managed_cargo_gc as gc


RECEIPT_KIND = "heim_pc.managed_cargo_maintenance_receipt"
DEFAULT_STATE_ROOT = Path.home() / ".local/state/heim-pc/managed-builds/maintenance"


class MaintenanceError(RuntimeError):
    """Raised when maintenance evidence or effects are not trustworthy."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _secure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise MaintenanceError(f"maintenance directory is unsafe: {path}")
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise MaintenanceError(f"maintenance directory ownership or mode is unsafe: {path}")


def _atomic_json(path: Path, value: Any) -> None:
    _secure_directory(path.parent)
    if path.is_symlink():
        raise MaintenanceError(f"maintenance output must not be a symlink: {path}")
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8"))
            handle.write(b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
        raise MaintenanceError(f"maintenance output readback is unsafe: {path}")


def _trim_receipts(path: Path, limit: int) -> None:
    entries = sorted(path.glob("*.json"), key=lambda item: item.name, reverse=True)
    for stale in entries[limit:]:
        if stale.is_symlink() or not stale.is_file():
            raise MaintenanceError(f"maintenance receipt path is unsafe: {stale}")
        stale.unlink()


def _validate_task_evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MaintenanceError("Grabowski managed Cargo evidence is not an object")
    if value.get("schema_version") != 1 or value.get("kind") != gc.EVIDENCE_KIND:
        raise MaintenanceError("Grabowski managed Cargo evidence identity is invalid")
    if value.get("complete") is not True or value.get("truncated") is not False:
        raise MaintenanceError("Grabowski managed Cargo evidence is incomplete")
    if value.get("observation_error_count") != 0 or value.get("observation_errors") != []:
        raise MaintenanceError("Grabowski managed Cargo evidence contains observation errors")
    evidence_sha = value.get("evidence_sha256")
    if (
        not isinstance(evidence_sha, str)
        or len(evidence_sha) != 64
        or any(character not in "0123456789abcdef" for character in evidence_sha)
    ):
        raise MaintenanceError("Grabowski managed Cargo evidence hash is invalid")
    return value


def _task_evidence(limit: int) -> dict[str, Any]:
    try:
        import grabowski_tasks
    except ModuleNotFoundError as exc:
        raise MaintenanceError("Grabowski runtime modules are unavailable") from exc
    return _validate_task_evidence(
        grabowski_tasks.grabowski_task_list(
            limit=limit,
            view="managed_cargo_evidence",
        )
    )


def _disk_state(home: Path) -> dict[str, int | float]:
    usage = shutil.disk_usage(home)
    used = usage.total - usage.free
    return {
        "total_bytes": usage.total,
        "used_bytes": used,
        "available_bytes": usage.free,
        "used_percent": round(used * 100 / usage.total, 2) if usage.total else 0.0,
    }


def reconcile(
    *,
    policy_path: Path,
    state_root: Path,
    task_limit: int = 100,
    evidence_provider: Callable[[int], dict[str, Any]] = _task_evidence,
) -> dict[str, Any]:
    if isinstance(task_limit, bool) or not 1 <= task_limit <= 100:
        raise MaintenanceError("task_limit must be between 1 and 100")
    home = Path(os.environ.get("HOME", "~")).expanduser().resolve()
    policy = mb.load_policy(policy_path)
    _secure_directory(state_root)
    lock_path = state_root / "reconcile.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    lock_fd = os.open(lock_path, flags, 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise MaintenanceError("another managed Cargo maintenance wave is active") from exc

        observed_at_ns = time.time_ns()
        evidence = _validate_task_evidence(evidence_provider(task_limit))
        evidence_path = state_root / "evidence-current.json"
        _atomic_json(evidence_path, evidence)
        before_disk = _disk_state(home)
        plan = gc.build_plan(
            policy,
            home=home,
            evidence_path=evidence_path,
            now_unix=observed_at_ns // 1_000_000_000,
        )
        plan_path = state_root / "plan-current.json"
        _atomic_json(plan_path, plan)

        candidates = plan.get("candidates")
        blockers = plan.get("convergence_blockers")
        if not isinstance(candidates, list) or not isinstance(blockers, list):
            raise MaintenanceError("managed Cargo GC plan shape is invalid")
        apply_result: dict[str, Any] | None = None
        if plan.get("safe_to_apply") is True and candidates and not blockers:
            apply_result = gc.apply_plan(
                policy,
                home=home,
                plan_path=plan_path,
                evidence_path=evidence_path,
                expected_plan_sha256=plan["plan_sha256"],
                confirmation=gc.CONFIRMATION,
            )

        after_disk = _disk_state(home)
        gc_receipt = apply_result.get("receipt") if isinstance(apply_result, dict) else None
        if isinstance(gc_receipt, dict):
            status = "applied"
            managed_after = gc_receipt.get("after_allocated_bytes")
            reclaimed = gc_receipt.get("reclaimed_bytes")
        elif blockers:
            status = "blocked"
            managed_after = plan.get("total_managed_allocated_bytes")
            reclaimed = 0
        elif plan.get("over_max_total") is True:
            status = "over_budget_no_eligible_candidates"
            managed_after = plan.get("total_managed_allocated_bytes")
            reclaimed = 0
        else:
            status = "within_budget"
            managed_after = plan.get("total_managed_allocated_bytes")
            reclaimed = 0

        receipt = {
            "schema_version": 1,
            "kind": RECEIPT_KIND,
            "status": status,
            "observed_at_unix_ns": observed_at_ns,
            "policy_sha256": plan.get("policy_sha256"),
            "evidence_sha256": evidence.get("evidence_sha256"),
            "plan_sha256": plan.get("plan_sha256"),
            "candidate_count": len(candidates),
            "blocker_count": len(blockers),
            "over_max_total": plan.get("over_max_total"),
            "managed_before_bytes": plan.get("total_managed_allocated_bytes"),
            "managed_after_bytes": managed_after,
            "reclaimed_bytes": reclaimed,
            "disk_before": before_disk,
            "disk_after": after_disk,
            "gc_receipt_path": apply_result.get("receipt_path") if isinstance(apply_result, dict) else None,
            "does_not_establish": [
                "permission to delete unclassified or named legacy cache roots",
                "absence of non-Grabowski consumers outside current process evidence",
                "worktree or source-file cleanup authority",
                "future storage convergence without repeated successful runs",
            ],
        }
        receipt["receipt_sha256"] = _sha256_json(receipt)
        receipts = state_root / "receipts"
        receipt_path = receipts / f"{observed_at_ns}-{receipt['receipt_sha256'][:16]}.json"
        _atomic_json(receipt_path, receipt)
        _atomic_json(state_root / "latest.json", receipt)
        _trim_receipts(receipts, int(policy["max_receipts"]))
        return {"receipt_path": str(receipt_path), "receipt": receipt}
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=mb.DEFAULT_POLICY_PATH)
    parser.add_argument("--state-root", type=Path, default=DEFAULT_STATE_ROOT)
    parser.add_argument("--task-limit", type=int, default=100)
    args = parser.parse_args(argv)
    try:
        result = reconcile(
            policy_path=args.policy.expanduser().resolve(),
            state_root=args.state_root.expanduser().resolve(),
            task_limit=args.task_limit,
        )
    except (MaintenanceError, gc.CargoGcError, mb.PolicyError, mb.ManagedBuildError, OSError) as exc:
        print(json.dumps({"kind": "heim_pc.managed_cargo_maintenance_error", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
