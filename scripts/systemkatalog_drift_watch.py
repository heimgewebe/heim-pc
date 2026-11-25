#!/usr/bin/env python3
"""Consume the existing CI drift report and deduplicate Bureau notices."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import io
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NamedTuple

CANDIDATE_ID = "SYSTEMKATALOG-DRIFT-CLOSED-LOOP-V1"
NONTERMINAL_CANDIDATE_STATUSES = {"active", "paused", "observed", "promoted"}
TERMINAL_CANDIDATE_STATUSES = {"closed", "dropped"}
LIVE_CANDIDATE_STATUSES = NONTERMINAL_CANDIDATE_STATUSES | TERMINAL_CANDIDATE_STATUSES
SYSTEMKATALOG_REPOSITORY = "heimgewebe/systemkatalog"
WORKFLOW = "ecosystem-map.yml"
ARTIFACT = "systemkatalog-drift-report"
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
MAX_REPORT_AGE = timedelta(hours=48)
GIT_SHA_RE = re.compile(r"[0-9a-f]{40}")


class CandidateAssessment(NamedTuple):
    event_id: int
    status: str | None
    decision: str | None
    source_sha256: str | None
    missing_fields: tuple[str, ...]


def _run(argv: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True, timeout=30)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def _result_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Accept both legacy direct JSON and the current Bureau result envelope."""
    result = payload.get("result")
    return result if isinstance(result, dict) else payload


def _command_error(completed: subprocess.CompletedProcess[str]) -> str:
    return completed.stderr.strip() or completed.stdout.strip() or f"exit status {completed.returncode}"


def _gh_api(path: str) -> bytes:
    response = subprocess.run(
        ["gh", "api", path], capture_output=True, timeout=30, check=False
    )
    if response.returncode != 0:
        raise RuntimeError(f"GitHub artifact API failed (exit {response.returncode})")
    if len(response.stdout) > MAX_ARTIFACT_BYTES:
        raise ValueError("GitHub artifact response too large")
    return response.stdout


def _utc(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("missing report timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("report timestamp lacks timezone")
    return result.astimezone(timezone.utc)


def fetch_ci_report(api=_gh_api, *, now: datetime | None = None):
    """One completed main run; no fallback to an older missing/failed report."""
    now = now or datetime.now(timezone.utc)
    prefix = f"repos/{SYSTEMKATALOG_REPOSITORY}/actions"
    runs = json.loads(api(
        f"{prefix}/workflows/{WORKFLOW}/runs?branch=main&status=completed&per_page=1"
    ))["workflow_runs"]
    if len(runs) != 1:
        raise ValueError("no unique completed catalog workflow run")
    run = runs[0]
    run_id, head = run.get("id"), run.get("head_sha")
    if (
        type(run_id) is not int or run_id <= 0
        or not isinstance(head, str) or GIT_SHA_RE.fullmatch(head) is None
        or run.get("head_branch") != "main"
        or run.get("path") != f".github/workflows/{WORKFLOW}"
        or run.get("head_repository", {}).get("full_name") != SYSTEMKATALOG_REPOSITORY
        or run.get("repository", {}).get("full_name") != SYSTEMKATALOG_REPOSITORY
        or run.get("status") != "completed"
        or run.get("event") not in {"push", "schedule", "workflow_dispatch"}
        or run.get("conclusion") not in {"success", "failure"}
    ):
        raise ValueError("latest completed catalog workflow run is not usable")
    started, finished = _utc(run["run_started_at"]), _utc(run["updated_at"])
    if not started <= finished or not timedelta(0) <= now - finished <= MAX_REPORT_AGE:
        raise ValueError("catalog workflow run is stale or has invalid timing")
    payload = json.loads(api(f"{prefix}/runs/{run_id}/artifacts?per_page=100"))
    artifacts = payload["artifacts"]
    if payload.get("total_count") != len(artifacts):
        raise ValueError("incomplete catalog artifact listing")
    matches = [item for item in artifacts if item.get("name") == ARTIFACT]
    if len(matches) != 1:
        raise ValueError("latest completed catalog run lacks a unique drift artifact")
    artifact = matches[0]
    binding = artifact.get("workflow_run", {})
    artifact_id, size, digest = (
        artifact.get("id"), artifact.get("size_in_bytes"), artifact.get("digest")
    )
    if (
        type(artifact_id) is not int or artifact_id <= 0
        or artifact.get("expired") is not False
        or type(size) is not int or not 0 < size <= MAX_ARTIFACT_BYTES
        or not isinstance(digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        or binding.get("id") != run_id
        or binding.get("head_sha") != head
        or binding.get("head_branch") != "main"
        or binding.get("repository_id") != run["repository"]["id"]
        or binding.get("head_repository_id") != run["head_repository"]["id"]
    ):
        raise ValueError("catalog artifact identity, digest or size invalid")
    raw = api(f"{prefix}/artifacts/{artifact_id}/zip")
    if len(raw) != size or "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("catalog artifact bytes do not match provider digest")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        if (
            len(members) != 1
            or members[0].filename != ARTIFACT + ".json"
            or members[0].is_dir()
            or not 0 < members[0].file_size <= MAX_ARTIFACT_BYTES
        ):
            raise ValueError("unexpected catalog artifact archive contents")
        report = json.loads(archive.read(members[0]))
    changes = report.get("changes")
    material = report.get("materialDrift")
    proposal = report.get("proposal")
    candidate = report.get("bureauCandidate")
    observed = _utc(report.get("generatedAt"))
    if (
        report.get("schemaVersion") != 1 or report.get("kind") != "system_catalog_drift_report"
        or type(material) is not bool or not isinstance(changes, list)
        or type(report.get("changeCount")) is not int
        or report["changeCount"] != len(changes) or material != bool(changes)
        or any(not isinstance(change, dict) or not isinstance(change.get("kind"), str)
               or not change["kind"] for change in changes)
        or not isinstance(proposal, dict) or proposal.get("proposalOnly") is not True
        or proposal.get("autoMerge") is not False or proposal.get("candidateId") != CANDIDATE_ID
        or (material and (not isinstance(candidate, dict) or candidate.get("candidateId") != CANDIDATE_ID
                          or candidate.get("repo") != "repo.systemkatalog"))
        or (not material and candidate is not None)
        or (run["conclusion"] == "failure" and not material)
        or not started <= observed <= finished
        or not timedelta(0) <= now - observed <= MAX_REPORT_AGE
    ):
        raise ValueError("catalog artifact report inconsistent, stale or not proposal-only")
    return report, {
        "repository": SYSTEMKATALOG_REPOSITORY, "workflow": WORKFLOW,
        "runId": run_id, "commit": head, "conclusion": run["conclusion"],
        "artifactId": artifact_id, "artifactDigest": digest,
        "observedAt": report["generatedAt"],
    }


def material_fingerprint(report: dict[str, Any]) -> dict[str, Any]:
    """Stable semantic changes, not run timestamps or unrelated commit churn."""
    changes = []
    for row in report["changes"]:
        value = dict(row)
        if value["kind"] == "primary_source_changed" and value.get("observedSha256"):
            value.pop("observedCommit", None)
        changes.append(value)
    changes.sort(key=lambda row: json.dumps(row, sort_keys=True, ensure_ascii=False))
    return {
        "schemaVersion": 1, "kind": "system_catalog_material_drift_projection",
        "materialDrift": report["materialDrift"], "changeCount": len(changes),
        "changes": changes,
    }


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
        f"Zentraler Systemkatalog-CI-Bericht meldet {report.get('changeCount')} Systemkatalog-Abweichungen. "
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
        "idempotency_key": f"systemkatalog-drift:{digest}:{latest_event_id or 'initial'}",
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


def run_watch(*, bureau_root: Path, state_root: Path, check_only: bool = False):
    report, source = fetch_ci_report()
    projection = material_fingerprint(report)
    encoded = json.dumps(projection, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    report_path = state_root / "drift-report.json"
    material_path = state_root / "reports" / (digest + ".json")
    bureau = None
    if not check_only:
        state_root.mkdir(parents=True, exist_ok=True)
        os.chmod(state_root, 0o700)
        _write_json(report_path, report)
        if report["materialDrift"]:
            # Stable source bytes even across different CI run timestamps.
            _write_json(material_path, json.loads(encoded))
            if hashlib.sha256(material_path.read_bytes()).hexdigest() != digest:
                raise RuntimeError("material report digest changed")
            bureau = _ensure_bureau_candidate(bureau_root, material_path, report)
    result = {
        "schemaVersion": 1, "kind": "heim_pc_systemkatalog_drift_watch_receipt",
        "checkedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "checkOnly": check_only, "materialDrift": report["materialDrift"],
        "changeCount": report["changeCount"], "materialSha256": digest,
        "bureau": bureau, "sources": {"systemkatalog": source},
        "report": str(report_path) if not check_only else None,
        "materialReport": str(material_path) if not check_only and report["materialDrift"] else None,
        "doesNotEstablish": ["semantic_truth", "automatic_merge_authority", "runtime_health"],
    }
    if not check_only:
        _write_json(state_root / "last-run.json", result)
    return result


def main() -> int:
    home = Path.home()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bureau-root", type=Path, default=home / "repos/bureau",
                        help="Deprecated compatibility argument; Bureau uses its runtime snapshot.")
    parser.add_argument("--state-root", type=Path,
                        default=home / ".local/state/heim-pc/systemkatalog-drift-watch")
    parser.add_argument("--check-only", action="store_true",
                        help="Read and validate CI artifact without local state or Bureau writes")
    args = parser.parse_args()
    try:
        result = run_watch(bureau_root=args.bureau_root, state_root=args.state_root,
                           check_only=args.check_only)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, AttributeError,
            zipfile.BadZipFile, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"kind": "heim_pc_systemkatalog_drift_watch_error",
                          "error": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
