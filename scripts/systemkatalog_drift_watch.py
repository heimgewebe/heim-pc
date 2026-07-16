#!/usr/bin/env python3
"""Run an independent proposal-only Systemkatalog drift check and dedupe Bureau notice."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, NamedTuple
from urllib.parse import urlparse

CANDIDATE_ID = "SYSTEMKATALOG-DRIFT-CLOSED-LOOP-V1"
ACTIVE_STATUSES = {"active", "paused", "waiting", "blocked", "in_progress"}
SYSTEMKATALOG_REPOSITORY = "heimgewebe/systemkatalog"
METAREPO_REPOSITORY = "heimgewebe/metarepo"
REMOTE_NAME = "origin"
REMOTE_MAIN_REF = "refs/remotes/origin/main"
GIT_SHA_RE = re.compile(r"[0-9a-f]{40}")


class SourceSnapshot(NamedTuple):
    systemkatalog_root: Path
    fleet_file: Path
    systemkatalog_commit: str
    metarepo_commit: str


def _run(argv: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def _write_private_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def _result_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Accept both legacy direct JSON and the current Bureau result envelope."""
    result = payload.get("result")
    return result if isinstance(result, dict) else payload


def _command_error(completed: subprocess.CompletedProcess[str]) -> str:
    return completed.stderr.strip() or completed.stdout.strip() or f"exit status {completed.returncode}"


def _github_repository_from_remote(remote_url: str) -> str | None:
    value = remote_url.strip().rstrip("/")
    scp_match = re.fullmatch(r"[^/@:]+@github\.com:(.+)", value)
    if scp_match is not None:
        path = scp_match.group(1)
    else:
        parsed = urlparse(value)
        if parsed.hostname != "github.com":
            return None
        path = parsed.path.lstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = path.strip("/").split("/")
    if len(parts) != 2 or not all(parts):
        return None
    return f"{parts[0]}/{parts[1]}"


def _fetch_remote_main(repo_root: Path, expected_repository: str) -> str:
    remote = _run(["git", "-C", str(repo_root), "remote", "get-url", REMOTE_NAME])
    if remote.returncode != 0:
        raise RuntimeError(
            f"cannot read {expected_repository} origin: {_command_error(remote)}"
        )
    observed_repository = _github_repository_from_remote(remote.stdout)
    if observed_repository is None or observed_repository.lower() != expected_repository.lower():
        raise RuntimeError(
            f"unexpected origin for {repo_root}: {remote.stdout.strip()!r}; "
            f"expected GitHub repository {expected_repository}"
        )
    fetched = _run(
        [
            "git",
            "-C",
            str(repo_root),
            "fetch",
            "--quiet",
            "--no-tags",
            REMOTE_NAME,
            f"+refs/heads/main:{REMOTE_MAIN_REF}",
        ]
    )
    if fetched.returncode != 0:
        raise RuntimeError(
            f"cannot fetch {expected_repository} main: {_command_error(fetched)}"
        )
    resolved = _run(
        [
            "git",
            "-C",
            str(repo_root),
            "rev-parse",
            "--verify",
            f"{REMOTE_MAIN_REF}^{{commit}}",
        ]
    )
    commit = resolved.stdout.strip().lower()
    if resolved.returncode != 0 or GIT_SHA_RE.fullmatch(commit) is None:
        raise RuntimeError(
            f"cannot resolve fetched {expected_repository} main: {_command_error(resolved)}"
        )
    return commit


def _extract_git_archive(archive_path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    destination_root = destination.resolve()
    with tarfile.open(archive_path, mode="r:") as archive:
        members = archive.getmembers()
        for member in members:
            member_path = PurePosixPath(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise RuntimeError(f"unsafe path in Git archive: {member.name!r}")
            target = (destination / Path(*member_path.parts)).resolve()
            if target != destination_root and destination_root not in target.parents:
                raise RuntimeError(f"Git archive path escapes snapshot root: {member.name!r}")
            if not (member.isdir() or member.isfile()):
                raise RuntimeError(
                    f"unsupported non-regular entry in Git archive: {member.name!r}"
                )
        archive.extractall(destination, members=members)


def _archive_commit(repo_root: Path, commit: str, destination: Path, archive_path: Path) -> None:
    archived = _run(
        [
            "git",
            "-C",
            str(repo_root),
            "archive",
            "--format=tar",
            "--output",
            str(archive_path),
            commit,
        ]
    )
    if archived.returncode != 0:
        raise RuntimeError(f"cannot archive {repo_root} at {commit}: {_command_error(archived)}")
    try:
        _extract_git_archive(archive_path, destination)
    finally:
        archive_path.unlink(missing_ok=True)


def _read_git_file(repo_root: Path, commit: str, relative_path: str, output: Path) -> None:
    shown = _run(["git", "-C", str(repo_root), "show", f"{commit}:{relative_path}"])
    if shown.returncode != 0:
        raise RuntimeError(
            f"cannot read {relative_path} from {repo_root} at {commit}: {_command_error(shown)}"
        )
    _write_private_text(output, shown.stdout)


@contextmanager
def _fresh_source_snapshot(
    *,
    systemkatalog_root: Path,
    fleet_file: Path,
    state_root: Path,
) -> Iterator[SourceSnapshot]:
    metarepo_root = fleet_file.parent.parent
    systemkatalog_commit = _fetch_remote_main(
        systemkatalog_root, SYSTEMKATALOG_REPOSITORY
    )
    metarepo_commit = _fetch_remote_main(metarepo_root, METAREPO_REPOSITORY)
    with tempfile.TemporaryDirectory(prefix=".source-snapshot-", dir=state_root) as directory:
        snapshot_root = Path(directory)
        snapshot_systemkatalog = snapshot_root / "systemkatalog"
        snapshot_fleet = snapshot_root / "metarepo/fleet/repos.yml"
        _archive_commit(
            systemkatalog_root,
            systemkatalog_commit,
            snapshot_systemkatalog,
            snapshot_root / "systemkatalog.tar",
        )
        _read_git_file(
            metarepo_root,
            metarepo_commit,
            "fleet/repos.yml",
            snapshot_fleet,
        )
        required = [
            snapshot_systemkatalog / "scripts/read_github_catalog_observations.py",
            snapshot_systemkatalog / "scripts/system_catalog_drift.py",
            snapshot_fleet,
        ]
        missing = [str(path) for path in required if not path.is_file()]
        if missing:
            raise RuntimeError(f"fresh source snapshot is incomplete: {missing}")
        yield SourceSnapshot(
            systemkatalog_root=snapshot_systemkatalog,
            fleet_file=snapshot_fleet,
            systemkatalog_commit=systemkatalog_commit,
            metarepo_commit=metarepo_commit,
        )


def _latest_candidate(payload: dict[str, Any], candidate_id: str) -> tuple[int, str | None] | None:
    records = _result_payload(payload).get("records")
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
        raise RuntimeError(f"bureau live-list failed: {_command_error(listed)}")
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
        raise RuntimeError(f"bureau live-register failed: {_command_error(registered)}")
    receipt = _result_payload(json.loads(registered.stdout))
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
    if not bureau_root.exists():
        raise RuntimeError(f"required Bureau root missing: {bureau_root}")
    state_root.mkdir(parents=True, exist_ok=True)
    os.chmod(state_root, 0o700)
    observations = state_root / "observations.json"
    report_path = state_root / "drift-report.json"
    proposal_path = state_root / "update-proposal.json"
    with _fresh_source_snapshot(
        systemkatalog_root=systemkatalog_root,
        fleet_file=fleet_file,
        state_root=state_root,
    ) as sources:
        observed = _run([
            sys.executable,
            str(sources.systemkatalog_root / "scripts/read_github_catalog_observations.py"),
            "--root", str(sources.systemkatalog_root),
            "--output", str(observations),
        ], cwd=sources.systemkatalog_root)
        if observed.returncode != 0:
            raise RuntimeError(f"GitHub observation failed: {_command_error(observed)}")
        drift = _run([
            sys.executable,
            str(sources.systemkatalog_root / "scripts/system_catalog_drift.py"),
            "--root", str(sources.systemkatalog_root),
            "--github-observations", str(observations),
            "--fleet-file", str(sources.fleet_file),
            "--output", str(report_path),
            "--proposal-output", str(proposal_path),
        ], cwd=sources.systemkatalog_root)
        if drift.returncode != 0:
            raise RuntimeError(f"drift report failed: {_command_error(drift)}")
        source_receipt = {
            "systemkatalog": {
                "repository": SYSTEMKATALOG_REPOSITORY,
                "commit": sources.systemkatalog_commit,
                "materialization": "git_archive",
            },
            "fleet": {
                "repository": METAREPO_REPOSITORY,
                "commit": sources.metarepo_commit,
                "path": "fleet/repos.yml",
                "materialization": "git_show",
            },
        }
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
        "sources": source_receipt,
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
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError, tarfile.TarError) as exc:
        print(json.dumps({"kind": "heim_pc_systemkatalog_drift_watch_error", "error": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
