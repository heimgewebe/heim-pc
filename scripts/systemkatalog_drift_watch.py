#!/usr/bin/env python3
"""Run an independent proposal-only Systemkatalog drift check and dedupe Bureau notice."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CANDIDATE_ID = "SYSTEMKATALOG-DRIFT-CLOSED-LOOP-V1"
ACTIVE_STATUSES = {"active", "paused", "waiting", "blocked", "in_progress"}


def _run(argv: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def _latest_candidate(payload: dict[str, Any], candidate_id: str) -> tuple[int, str | None] | None:
    records = payload.get("records")
    if not isinstance(records, list):
        return None
    matching: list[tuple[int, str | None]] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        record = item.get("record")
        event_id = item.get("event_id")
        if (
            isinstance(record, dict)
            and record.get("candidate_id") == candidate_id
            and isinstance(event_id, int)
        ):
            status = record.get("status")
            matching.append((event_id, status if isinstance(status, str) else None))
    if not matching:
        return None
    return max(matching, key=lambda item: item[0])


def _latest_candidate_status(payload: dict[str, Any], candidate_id: str) -> str | None:
    latest = _latest_candidate(payload, candidate_id)
    return latest[1] if latest is not None else None


def _ensure_bureau_candidate(bureau_root: Path, report_path: Path, report: dict[str, Any]) -> dict[str, Any]:
    listed = _run([
        "bureau", "--root", str(bureau_root), "--json", "live-list",
        "--kind", "candidate_task", "--repo", "repo.systemkatalog", "--limit", "500",
    ])
    if listed.returncode != 0:
        raise RuntimeError(f"bureau live-list failed: {listed.stderr.strip()}")
    payload = json.loads(listed.stdout)
    latest = _latest_candidate(payload, CANDIDATE_ID)
    latest_event_id = latest[0] if latest is not None else None
    latest_status = latest[1] if latest is not None else None
    if latest_status in ACTIVE_STATUSES:
        return {
            "action": "deduplicated",
            "candidateId": CANDIDATE_ID,
            "eventId": latest_event_id,
            "status": latest_status,
        }
    digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
    kinds = sorted({str(item.get("kind")) for item in report.get("changes", []) if isinstance(item, dict)})
    note = (
        f"Unabhängiger Heim-PC-Watchdog erkannte {report.get('changeCount')} Systemkatalog-Abweichungen. "
        f"Driftarten: {', '.join(kinds) or 'unknown'}. Lokaler Bericht: {report_path}; sha256={digest}. "
        "Nur proposal-only prüfen; keine Katalogsemantik automatisch mergen."
    )
    register_argv = [
        "bureau", "--root", str(bureau_root), "--json", "live-register",
        "--kind", "candidate_task",
        "--title", "Systemkatalog-Drift prüfen und proposal-only aktualisieren",
        "--source", "heim-pc-systemkatalog-drift-watch-v1",
        "--worker-id", "heim-pc-systemkatalog-drift-watch",
        "--repo", "repo.systemkatalog",
        "--candidate-id", CANDIDATE_ID,
        "--status", "active",
        "--promotion-required",
    ]
    if latest_event_id is not None:
        register_argv.extend(["--supersedes-event-id", str(latest_event_id)])
    register_argv.extend([
        "--catalog-validation", "strict",
        "--note", note,
    ])
    registered = _run(register_argv)
    if registered.returncode != 0:
        raise RuntimeError(f"bureau live-register failed: {registered.stderr.strip()}")
    receipt = json.loads(registered.stdout)
    result = {
        "action": "reactivated" if latest_event_id is not None else "registered",
        "candidateId": CANDIDATE_ID,
        "eventId": receipt.get("event_id"),
    }
    if latest_event_id is not None:
        result["supersedesEventId"] = latest_event_id
    return result


def run_watch(
    *,
    systemkatalog_root: Path,
    fleet_file: Path,
    bureau_root: Path,
    state_root: Path,
) -> dict[str, Any]:
    required = [
        systemkatalog_root / "scripts/read_github_catalog_observations.py",
        systemkatalog_root / "scripts/system_catalog_drift.py",
        fleet_file,
        bureau_root,
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise RuntimeError(f"required paths missing: {missing}")
    state_root.mkdir(parents=True, exist_ok=True)
    os.chmod(state_root, 0o700)
    observations = state_root / "observations.json"
    report_path = state_root / "drift-report.json"
    proposal_path = state_root / "update-proposal.json"
    observed = _run([
        sys.executable,
        str(systemkatalog_root / "scripts/read_github_catalog_observations.py"),
        "--root", str(systemkatalog_root),
        "--output", str(observations),
    ], cwd=systemkatalog_root)
    if observed.returncode != 0:
        raise RuntimeError(f"GitHub observation failed: {observed.stderr.strip()}")
    drift = _run([
        sys.executable,
        str(systemkatalog_root / "scripts/system_catalog_drift.py"),
        "--root", str(systemkatalog_root),
        "--github-observations", str(observations),
        "--fleet-file", str(fleet_file),
        "--output", str(report_path),
        "--proposal-output", str(proposal_path),
    ], cwd=systemkatalog_root)
    if drift.returncode != 0:
        raise RuntimeError(f"drift report failed: {drift.stderr.strip()}")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    bureau = None
    if report.get("materialDrift") is True:
        bureau = _ensure_bureau_candidate(bureau_root, report_path, report)
    result = {
        "schemaVersion": 1,
        "kind": "heim_pc_systemkatalog_drift_watch_receipt",
        "checkedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "materialDrift": bool(report.get("materialDrift")),
        "changeCount": int(report.get("changeCount") or 0),
        "bureau": bureau,
        "report": str(report_path),
        "proposal": str(proposal_path),
        "doesNotEstablish": ["semantic_truth", "automatic_merge_authority", "runtime_health"],
    }
    _write_json(state_root / "last-run.json", result)
    return result


def main() -> int:
    home = Path.home()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--systemkatalog-root", type=Path, default=home / "repos/systemkatalog")
    parser.add_argument("--fleet-file", type=Path, default=home / "repos/metarepo/fleet/repos.yml")
    parser.add_argument("--bureau-root", type=Path, default=home / "repos/bureau")
    parser.add_argument("--state-root", type=Path, default=home / ".local/state/heim-pc/systemkatalog-drift-watch")
    args = parser.parse_args()
    try:
        result = run_watch(
            systemkatalog_root=args.systemkatalog_root.resolve(),
            fleet_file=args.fleet_file.resolve(),
            bureau_root=args.bureau_root.resolve(),
            state_root=args.state_root.expanduser().resolve(),
        )
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"kind": "heim_pc_systemkatalog_drift_watch_error", "error": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
