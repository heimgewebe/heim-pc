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
NONTERMINAL_CANDIDATE_STATUSES = {"active", "paused", "observed", "promoted"}
TERMINAL_CANDIDATE_STATUSES = {"closed", "dropped"}
LIVE_CANDIDATE_STATUSES = NONTERMINAL_CANDIDATE_STATUSES | TERMINAL_CANDIDATE_STATUSES
SYSTEMKATALOG_REPOSITORY = "heimgewebe/systemkatalog"
METAREPO_REPOSITORY = "heimgewebe/metarepo"
REMOTE_NAME = "origin"
GIT_SHA_RE = re.compile(r"[0-9a-f]{40}")


class SourceSnapshot(NamedTuple):
    systemkatalog_root: Path
    fleet_file: Path
    systemkatalog_commit: str
    metarepo_commit: str


class CandidateAssessment(NamedTuple):
    event_id: int
    status: str | None
    decision: str | None
    source_sha256: str | None
    missing_fields: tuple[str, ...]


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
    remote_url = remote.stdout.strip()
    observed_repository = _github_repository_from_remote(remote_url)
    if observed_repository is None or observed_repository.lower() != expected_repository.lower():
        raise RuntimeError(
            f"unexpected origin for {repo_root}: {remote_url!r}; "
            f"expected GitHub repository {expected_repository}"
        )
    listed = _run(
        [
            "git",
            "-C",
            str(repo_root),
            "ls-remote",
            "--exit-code",
            remote_url,
            "refs/heads/main",
        ]
    )
    fields = listed.stdout.strip().split()
    commit = fields[0].lower() if len(fields) == 2 and fields[1] == "refs/heads/main" else ""
    if listed.returncode != 0 or GIT_SHA_RE.fullmatch(commit) is None:
        raise RuntimeError(
            f"cannot resolve remote {expected_repository} main: {_command_error(listed)}"
        )
    fetched = _run(
        [
            "git",
            "-C",
            str(repo_root),
            "fetch",
            "--quiet",
            "--no-tags",
            remote_url,
            commit,
        ]
    )
    if fetched.returncode != 0:
        raise RuntimeError(
            f"cannot fetch {expected_repository} commit {commit}: {_command_error(fetched)}"
        )
    verified = _run(
        ["git", "-C", str(repo_root), "cat-file", "-e", f"{commit}^{{commit}}"]
    )
    if verified.returncode != 0:
        raise RuntimeError(
            f"fetched {expected_repository} commit is unavailable: {_command_error(verified)}"
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


def _candidate_assessment(
    bureau_root: Path,
    candidate_id: str,
) -> CandidateAssessment | None:
    """Read one exact candidate through the canonical Bureau runtime snapshot."""
    del bureau_root  # Compatibility argument; explicit checkout roots are forbidden here.
    assessed = _run(
        [
            "bureau",
            "--json",
            "operator-candidate-assess",
            "--candidate-id",
            candidate_id,
        ]
    )
    try:
        payload = json.loads(assessed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"bureau candidate assessment returned invalid JSON: {_command_error(assessed)}"
        ) from exc
    result = _result_payload(payload)
    if assessed.returncode != 0:
        message = result.get("message")
        effect_started = result.get("effect_started")
        if (
            isinstance(message, str)
            and f"candidate {candidate_id} is unknown" in message
            and effect_started is False
        ):
            return None
        raise RuntimeError(
            f"bureau candidate assessment failed: {_command_error(assessed)}"
        )
    event_id = result.get("event_id")
    observed_candidate_id = result.get("candidate_id")
    status = result.get("candidate_status")
    if observed_candidate_id != candidate_id or not isinstance(event_id, int):
        raise RuntimeError("bureau candidate assessment is not identity-bound")
    source_freshness = result.get("source_freshness")
    source_sha256 = (
        source_freshness.get("sha256")
        if isinstance(source_freshness, dict)
        and isinstance(source_freshness.get("sha256"), str)
        else None
    )
    decision = result.get("decision")
    missing_fields = result.get("missing_fields")
    return CandidateAssessment(
        event_id=event_id,
        status=status if isinstance(status, str) else None,
        decision=decision if isinstance(decision, str) else None,
        source_sha256=source_sha256,
        missing_fields=tuple(
            item for item in missing_fields if isinstance(item, str)
        )
        if isinstance(missing_fields, list)
        else (),
    )


def _candidate_matches_report(
    assessment: CandidateAssessment | None,
    report_sha256: str,
) -> bool:
    return bool(
        assessment is not None
        and assessment.status in NONTERMINAL_CANDIDATE_STATUSES
        and assessment.decision in {"merge", "promote"}
        and not assessment.missing_fields
        and assessment.source_sha256 == report_sha256
    )


def _ensure_bureau_candidate(
    bureau_root: Path,
    report_path: Path,
    report: dict[str, Any],
) -> dict[str, Any]:
    digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
    initial = _candidate_assessment(bureau_root, CANDIDATE_ID)
    if _candidate_matches_report(initial, digest):
        assert initial is not None
        return {
            "action": "deduplicated",
            "candidateId": CANDIDATE_ID,
            "eventId": initial.event_id,
            "status": initial.status,
        }

    kinds = sorted(
        {
            str(item.get("kind"))
            for item in report.get("changes", [])
            if isinstance(item, dict)
        }
    )
    title = "Systemkatalog-Drift prüfen und proposal-only aktualisieren"
    source_kind = "heim-pc-systemkatalog-drift-watch-v1"
    note = (
        f"Unabhängiger Heim-PC-Watchdog erkannte {report.get('changeCount')} Systemkatalog-Abweichungen. "
        f"Driftarten: {', '.join(kinds) or 'unknown'}. Lokaler Bericht: {report_path}; sha256={digest}. "
        "Nur proposal-only prüfen; keine Katalogsemantik automatisch mergen."
    )

    # Re-read immediately before the effect. The first observation may have
    # changed while the drift report was generated or while another operator
    # updated the append-only Live Register.
    current = _candidate_assessment(bureau_root, CANDIDATE_ID)
    if _candidate_matches_report(current, digest):
        assert current is not None
        return {
            "action": "deduplicated",
            "candidateId": CANDIDATE_ID,
            "eventId": current.event_id,
            "status": current.status,
        }
    if current is not None and current.status not in LIVE_CANDIDATE_STATUSES:
        raise RuntimeError(
            f"bureau candidate assessment returned unsupported status: {current.status!r}"
        )
    latest_event_id = current.event_id if current is not None else None
    reactivation_event_id: int | None = None
    reactivation_supersedes_event_id: int | None = None

    if current is not None and current.status in TERMINAL_CANDIDATE_STATUSES:
        reactivation_supersedes_event_id = current.event_id
        # Bureau inherits repo, task and operator_intake from the exact
        # predecessor when these identity fields are omitted.
        reactivated = _run(
            [
                "bureau",
                "--json",
                "live-register",
                "--kind",
                "candidate_task",
                "--title",
                title,
                "--source",
                source_kind,
                "--candidate-id",
                CANDIDATE_ID,
                "--supersedes-event-id",
                str(current.event_id),
                "--status",
                "observed",
                "--catalog-validation",
                "strict",
            ]
        )
        if reactivated.returncode != 0:
            # The CAS-style supersession may have appended before reporting a
            # failure. Never retry it unchanged: accept only an exact report
            # established by a concurrent writer, otherwise fail closed.
            readback = _candidate_assessment(bureau_root, CANDIDATE_ID)
            if _candidate_matches_report(readback, digest):
                assert readback is not None
                return {
                    "action": "deduplicated",
                    "candidateId": CANDIDATE_ID,
                    "eventId": readback.event_id,
                    "status": readback.status,
                    "recoveredFromConcurrentReactivation": True,
                }
            raise RuntimeError(
                f"bureau live-register reactivation failed: {_command_error(reactivated)}"
            )

        try:
            receipt = _result_payload(json.loads(reactivated.stdout))
        except json.JSONDecodeError as exc:
            raise RuntimeError("bureau live-register reactivation returned invalid JSON") from exc
        reactivation_event_id = receipt.get("event_id")
        if not isinstance(reactivation_event_id, int):
            raise RuntimeError("bureau live-register reactivation receipt is not event-bound")

        # _candidate_assessment rejects candidate identity drift; bind the
        # remaining readback to this exact event and the requested status.
        readback = _candidate_assessment(bureau_root, CANDIDATE_ID)
        if readback is None or readback.event_id != reactivation_event_id:
            if _candidate_matches_report(readback, digest):
                assert readback is not None
                return {
                    "action": "deduplicated",
                    "candidateId": CANDIDATE_ID,
                    "eventId": readback.event_id,
                    "status": readback.status,
                    "concurrentUpdateAfterReactivation": True,
                }
            raise RuntimeError(
                "bureau candidate reactivation post-readback is not bound to the event"
            )
        if readback.status != "observed":
            raise RuntimeError(
                "bureau candidate reactivation post-readback has unexpected status"
            )
        current = readback
        latest_event_id = reactivation_event_id
        if _candidate_matches_report(current, digest):
            return {
                "action": "reactivated",
                "candidateId": CANDIDATE_ID,
                "eventId": current.event_id,
                "status": current.status,
                "supersedesEventId": reactivation_supersedes_event_id,
            }

    request = {
        "schema_version": 1,
        "idempotency_key": f"systemkatalog-drift:{digest}",
        "title": title,
        "source_kind": source_kind,
        "desired_outcome": (
            "Den exakten, digestgebundenen Driftbericht semantisch prüfen, "
            "nur bestätigte stabile Katalogaussagen und Quellenbindungen über "
            "normale Review-Gates aktualisieren und den Kandidaten erst nach "
            "verifiziertem Merge schließen oder anhand neuer Drift verfeinern."
        ),
        "repo": "repo.systemkatalog",
        "source_locator": str(report_path),
        "source_sha256": digest,
        "observed_at": report.get("generatedAt"),
        "candidate_id": CANDIDATE_ID,
        "note": note,
        "catalog_validation": "strict",
    }
    if latest_event_id is not None:
        request["supersedes_event_id"] = latest_event_id
    request_path = report_path.with_name("bureau-candidate-request.json")
    _write_json(request_path, request)
    register_argv = [
        "bureau",
        "--json",
        "operator-candidate-record",
        "--request",
        str(request_path),
    ]
    registered = _run(register_argv)
    if registered.returncode != 0:
        # No unchanged retry after a possible concurrent append. One exact
        # readback may prove that another writer already established the
        # desired active state; every other outcome remains fail-closed.
        readback = _candidate_assessment(bureau_root, CANDIDATE_ID)
        if _candidate_matches_report(readback, digest):
            assert readback is not None
            return {
                "action": "deduplicated",
                "candidateId": CANDIDATE_ID,
                "eventId": readback.event_id,
                "status": readback.status,
                "recoveredFromConcurrentRegistration": True,
            }
        raise RuntimeError(
            f"bureau operator-candidate-record failed: {_command_error(registered)}"
        )

    try:
        receipt = _result_payload(json.loads(registered.stdout))
    except json.JSONDecodeError as exc:
        raise RuntimeError("bureau operator-candidate-record returned invalid JSON") from exc
    registered_event_id = receipt.get("event_id")
    if not isinstance(registered_event_id, int):
        raise RuntimeError("bureau operator-candidate-record receipt is not event-bound")

    readback = _candidate_assessment(bureau_root, CANDIDATE_ID)
    if not _candidate_matches_report(readback, digest):
        raise RuntimeError("bureau candidate post-readback is not bound to the report")
    assert readback is not None
    if readback.event_id != registered_event_id:
        return {
            "action": "deduplicated",
            "candidateId": CANDIDATE_ID,
            "eventId": readback.event_id,
            "status": readback.status,
            "registeredEventId": registered_event_id,
            "concurrentUpdateAfterRegistration": True,
        }

    if current is None:
        action = "registered"
    elif reactivation_event_id is not None:
        action = "reactivated"
    else:
        action = "refined"
    result = {
        "action": action,
        "candidateId": CANDIDATE_ID,
        "eventId": registered_event_id,
        "status": readback.status,
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
    # Kept for existing callers. Candidate helpers use the wrapper's
    # integrity-checked canonical snapshot and ignore checkout state.
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
    parser.add_argument(
        "--bureau-root",
        type=Path,
        default=home / "repos/bureau",
        help="Deprecated compatibility argument; Bureau uses its canonical runtime snapshot.",
    )
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
