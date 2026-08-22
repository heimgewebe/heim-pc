#!/usr/bin/env python3
"""Collect bounded read-only outcomes for declared Heim-PC maintenance producers."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

POLICY_KIND = "heim_pc_maintenance_producers_policy"
ARTIFACT_KIND = "heim_pc_maintenance_outcomes"
SCHEMA_VERSION = 1
MAX_PRODUCERS = 64
MAX_JOURNAL_LINES = 200
MAX_FAILURE_MESSAGES = 4
MAX_FAILURE_MESSAGE_BYTES = 600
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
PRODUCER_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{1,79}")
TASK_ID_RE = re.compile(r"[A-Z0-9][A-Z0-9-]{2,159}")
EVIDENCE_PATH_PREFIXES = (
    "$HOME/.local/state/heim-pc/",
    "$HOME/.local/state/grabowski/",
    "$HOME/.local/state/leitstand/",
    "$HOME/.local/state/repoground/",
    "$HOME/repos/leitstand/artifacts/",
)
FAILURE_TERMS = (
    "error",
    "fail",
    "exception",
    "traceback",
    "refusing",
    "denied",
    "invalid",
    "timeout",
)
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
ISO_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+(?:Z|[A-Z]{3,5})?\b")
HEX_RE = re.compile(r"\b[0-9a-f]{8,64}\b", re.IGNORECASE)
LONG_NUMBER_RE = re.compile(r"\b\d{4,}\b")
HOME_PATH_RE = re.compile(r"/home/[^/\s]+")


class OutcomeError(RuntimeError):
    pass


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True, check=False)


def _command_error(completed: subprocess.CompletedProcess[str]) -> str:
    return (completed.stderr or completed.stdout).strip()[:1000] or f"exit status {completed.returncode}"


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.parent.lstat()
    if path.parent.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise OutcomeError(f"unsafe output directory: {path.parent}")
    os.chmod(path.parent, 0o700)
    if path.is_symlink():
        raise OutcomeError(f"output path must not be a symlink: {path}")
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
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
    if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise OutcomeError(f"output readback failed: {path}")


def _load_json(path: Path, *, required: bool) -> dict[str, Any] | None:
    if not path.exists():
        if required:
            raise OutcomeError(f"required JSON file missing: {path}")
        return None
    if path.is_symlink() or not path.is_file():
        raise OutcomeError(f"JSON path must be a regular non-symlink file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        if required:
            raise OutcomeError(f"cannot read JSON file {path}: {exc}") from exc
        return None
    if not isinstance(value, dict):
        if required:
            raise OutcomeError(f"JSON root must be an object: {path}")
        return None
    return value


def _validate_policy(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    value = _load_json(path, required=True)
    assert value is not None
    if value.get("schema_version") != SCHEMA_VERSION or value.get("kind") != POLICY_KIND:
        raise OutcomeError("maintenance producer policy identity is invalid")
    unknown_top_level = sorted(set(value) - {"schema_version", "kind", "task_id", "producers"})
    if unknown_top_level:
        raise OutcomeError(
            f"maintenance producer policy contains unknown fields: {unknown_top_level}"
        )
    task_id = value.get("task_id")
    if not isinstance(task_id, str) or TASK_ID_RE.fullmatch(task_id) is None:
        raise OutcomeError("maintenance producer policy task_id is invalid")
    producers = value.get("producers")
    if not isinstance(producers, list) or not producers or len(producers) > MAX_PRODUCERS:
        raise OutcomeError("maintenance producer policy has an invalid producer set")
    seen: set[str] = set()
    allowed = {
        "id",
        "unit",
        "timer_unit",
        "max_age_seconds",
        "owner_component",
        "success_evidence",
        "evidence_paths",
        "bureau_binding",
    }
    for producer in producers:
        if not isinstance(producer, dict):
            raise OutcomeError("maintenance producer entry must be an object")
        unknown = sorted(set(producer) - allowed)
        if unknown:
            raise OutcomeError(f"maintenance producer contains unknown fields: {unknown}")
        producer_id = producer.get("id")
        unit = producer.get("unit")
        timer = producer.get("timer_unit")
        max_age = producer.get("max_age_seconds")
        owner = producer.get("owner_component")
        success_evidence = producer.get("success_evidence")
        if not isinstance(producer_id, str) or PRODUCER_ID_RE.fullmatch(producer_id) is None:
            raise OutcomeError("maintenance producer id is invalid")
        if producer_id in seen:
            raise OutcomeError(f"duplicate maintenance producer id: {producer_id}")
        seen.add(producer_id)
        if not isinstance(unit, str) or not unit.endswith(".service") or len(unit) > 255:
            raise OutcomeError(f"maintenance producer unit is invalid: {producer_id}")
        if timer is not None and (
            not isinstance(timer, str) or not timer.endswith(".timer") or len(timer) > 255
        ):
            raise OutcomeError(f"maintenance producer timer is invalid: {producer_id}")
        if not isinstance(max_age, int) or isinstance(max_age, bool) or not 60 <= max_age <= 604800:
            raise OutcomeError(f"maintenance producer max_age_seconds is invalid: {producer_id}")
        if not isinstance(owner, str) or not owner or len(owner) > 120:
            raise OutcomeError(f"maintenance producer owner_component is invalid: {producer_id}")
        if success_evidence != "systemd-service-result":
            raise OutcomeError(f"maintenance producer success_evidence is invalid: {producer_id}")
        paths = producer.get("evidence_paths", [])
        if not isinstance(paths, list) or len(paths) > 8 or not all(
            isinstance(item, str)
            and 0 < len(item) <= 1000
            and any(item.startswith(prefix) for prefix in EVIDENCE_PATH_PREFIXES)
            for item in paths
        ):
            raise OutcomeError(f"maintenance producer evidence_paths are invalid: {producer_id}")
        binding = producer.get("bureau_binding")
        if binding is not None:
            if not isinstance(binding, dict) or set(binding) - {"candidate_id", "task_id"}:
                raise OutcomeError(f"maintenance producer bureau_binding is invalid: {producer_id}")
            if not any(isinstance(binding.get(key), str) and binding.get(key) for key in binding):
                raise OutcomeError(f"maintenance producer bureau_binding is empty: {producer_id}")
    return value, _sha256_bytes(raw)


def _parse_properties(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key] = value
    return result


def _systemd_show(unit: str, properties: tuple[str, ...]) -> tuple[dict[str, str] | None, str | None]:
    argv = ["systemctl", "--user", "show", unit, "--no-pager"]
    argv.extend(f"--property={item}" for item in properties)
    completed = _run(argv)
    if completed.returncode != 0:
        return None, _command_error(completed)
    return _parse_properties(completed.stdout), None


def _timestamp_to_epoch(value: str | None) -> int | None:
    if not value or value == "n/a":
        return None
    completed = _run(["date", "--date", value, "+%s"])
    if completed.returncode != 0:
        return None
    try:
        parsed = int(completed.stdout.strip())
    except ValueError:
        return None
    return parsed if parsed >= 0 else None



def _journal_entries(
    unit: str,
    invocation_id: str | None,
    *,
    started_at_unix: int | None,
    terminal_at_unix: int | None,
) -> tuple[list[dict[str, Any]], str | None]:
    argv = [
        "journalctl",
        "--user",
        "--unit",
        unit,
        "--no-pager",
        "--output=json",
        "--grep",
        "|".join(FAILURE_TERMS),
        "--case-sensitive=no",
        "--lines",
        str(MAX_JOURNAL_LINES),
    ]
    if started_at_unix is not None:
        argv.extend(["--since", f"@{max(0, started_at_unix - 1)}"])
    if terminal_at_unix is not None:
        argv.extend(["--until", f"@{terminal_at_unix + 1}"])
    completed = _run(argv)
    if completed.returncode != 0:
        return [], _command_error(completed)

    entries: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(value, dict):
            continue
        message = value.get("MESSAGE")
        if not isinstance(message, str):
            continue
        observed_invocation = value.get("_SYSTEMD_INVOCATION_ID") or value.get("INVOCATION_ID")
        timestamp_raw = value.get("__REALTIME_TIMESTAMP")
        try:
            timestamp = int(timestamp_raw) // 1_000_000
        except (TypeError, ValueError):
            timestamp = None
        entries.append(
            {
                "message": message,
                "invocation_id": observed_invocation if isinstance(observed_invocation, str) else None,
                "timestamp_unix": timestamp,
            }
        )

    if invocation_id:
        exact_or_unbound = [
            item
            for item in entries
            if item.get("invocation_id") in (None, invocation_id)
        ]
        if any(item.get("invocation_id") == invocation_id for item in exact_or_unbound):
            entries = exact_or_unbound
    return entries, None


def _redact_message(value: str) -> str:
    value = ANSI_RE.sub("", value)
    value = HOME_PATH_RE.sub("$HOME", value)
    value = " ".join(value.split())
    encoded = value.encode("utf-8", errors="replace")[:MAX_FAILURE_MESSAGE_BYTES]
    return encoded.decode("utf-8", errors="ignore")


def _normalize_message(value: str) -> str:
    value = _redact_message(value).lower()
    value = ISO_RE.sub("<timestamp>", value)
    value = HEX_RE.sub("<hex>", value)
    value = LONG_NUMBER_RE.sub("<n>", value)
    return value



def _failure_messages(entries: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    structured: list[str] = []
    generic: list[str] = []
    for item in entries:
        message = str(item["message"])
        lowered = message.lower()
        payload: dict[str, Any] | None = None
        candidates = [message]
        fragment = message.strip()
        if fragment.endswith(","):
            fragment = fragment[:-1]
        if fragment.startswith('"') and ":" in fragment:
            candidates.append("{" + fragment + "}")
        for candidate in candidates:
            try:
                decoded = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(decoded, dict):
                payload = decoded
                break

        extracted: list[str] = []
        if payload is not None:
            for key in ("error", "message", "reason"):
                candidate = payload.get(key)
                if isinstance(candidate, str) and any(
                    term in candidate.lower() for term in FAILURE_TERMS
                ):
                    extracted.append(candidate)
        target = structured if extracted else generic
        if not extracted and any(term in lowered for term in FAILURE_TERMS):
            extracted.append(message)
        for candidate in extracted:
            redacted = _redact_message(candidate)
            if redacted and redacted not in structured and redacted not in generic:
                target.append(redacted)

    selected = structured[-MAX_FAILURE_MESSAGES:]
    remaining = MAX_FAILURE_MESSAGES - len(selected)
    if remaining > 0:
        selected.extend(generic[-remaining:])
    return selected, [_normalize_message(item) for item in selected]


def _expand_path(value: str, *, home: Path) -> Path:
    if value == "$HOME":
        return home
    if value.startswith("$HOME/"):
        return home / value[len("$HOME/") :]
    path = Path(value)
    if not path.is_absolute():
        raise OutcomeError(f"evidence path must be absolute or $HOME-bound: {value}")
    return path


def _evidence_status(values: list[str], *, home: Path) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    for raw in values:
        path = _expand_path(raw, home=home)
        display = str(path).replace(str(home), "$HOME", 1)
        item: dict[str, Any] = {"path": display}
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | nofollow)
        except FileNotFoundError:
            item["state"] = "missing"
            result.append(item)
            continue
        except OSError as exc:
            item["state"] = (
                "unsafe-or-non-regular"
                if exc.errno == errno.ELOOP
                else "unsafe-or-unreadable"
            )
            result.append(item)
            continue
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                item["state"] = "unsafe-or-non-regular"
                result.append(item)
                continue
            if metadata.st_uid != os.getuid():
                item.update({"state": "foreign-owner", "owner_uid": metadata.st_uid})
                result.append(item)
                continue
            if metadata.st_size > MAX_EVIDENCE_BYTES:
                item.update({"state": "too-large", "size_bytes": metadata.st_size})
                result.append(item)
                continue
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                data = handle.read(MAX_EVIDENCE_BYTES + 1)
            if len(data) > MAX_EVIDENCE_BYTES:
                item.update({"state": "too-large", "size_bytes": len(data)})
                result.append(item)
                continue
            item.update(
                {
                    "state": "observed",
                    "size_bytes": len(data),
                    "mtime_ns": metadata.st_mtime_ns,
                    "sha256": _sha256_bytes(data),
                }
            )
            result.append(item)
        finally:
            os.close(descriptor)
    return result


def _bureau_status(binding: dict[str, Any] | None, *, bureau_root: Path) -> dict[str, Any] | None:
    if binding is None:
        return None
    candidate_id = binding.get("candidate_id")
    task_id = binding.get("task_id")
    result: dict[str, Any] = {
        "candidate_id": candidate_id,
        "task_id": task_id,
        "authority": "bureau-operator-candidate-assess",
    }
    if not isinstance(candidate_id, str) or not candidate_id:
        result.update({"state": "declared-only", "does_not_establish": ["task_state"]})
        return result
    argv = [
        "bureau",
        "--root",
        str(bureau_root),
        "--json",
        "operator-candidate-assess",
        "--candidate-id",
        candidate_id,
    ]
    if isinstance(task_id, str) and task_id:
        argv.extend(["--task-id", task_id])
    completed = _run(argv)
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        payload = None
    envelope = payload.get("result") if isinstance(payload, dict) and isinstance(payload.get("result"), dict) else payload
    if completed.returncode != 0 or not isinstance(envelope, dict):
        result.update({"state": "unknown", "error": _redact_message(_command_error(completed))})
        return result
    event_id = envelope.get("event_id")
    if envelope.get("candidate_id") != candidate_id or not isinstance(event_id, int):
        result.update(
            {
                "state": "unknown",
                "error": "candidate assessment is not identity-bound",
            }
        )
        return result
    result.update(
        {
            "state": "observed",
            "candidate_status": envelope.get("candidate_status"),
            "event_id": event_id,
            "decision": envelope.get("decision"),
            "assessment_status": envelope.get("status"),
        }
    )
    return result


def _previous_map(previous: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if previous is None:
        return {}
    if previous.get("schema_version") != SCHEMA_VERSION or previous.get("kind") != ARTIFACT_KIND:
        raise OutcomeError("previous maintenance outcome artifact identity is invalid")
    expected_sha256 = previous.get("artifact_sha256")
    if not isinstance(expected_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise OutcomeError("previous maintenance outcome artifact digest is missing or invalid")
    digest_payload = dict(previous)
    digest_payload.pop("artifact_sha256", None)
    actual_sha256 = _sha256_bytes(_canonical_json(digest_payload))
    if actual_sha256 != expected_sha256:
        raise OutcomeError("previous maintenance outcome artifact digest does not match")
    producers = previous.get("producers")
    if not isinstance(producers, list) or len(producers) > MAX_PRODUCERS:
        raise OutcomeError("previous maintenance outcome producer set is invalid")
    result: dict[str, dict[str, Any]] = {}
    for item in producers:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise OutcomeError("previous maintenance outcome producer entry is invalid")
        producer_id = item["id"]
        if producer_id in result:
            raise OutcomeError(f"duplicate previous maintenance producer id: {producer_id}")
        result[producer_id] = item
    return result


def _service_outcome(
    producer: dict[str, Any],
    *,
    previous: dict[str, Any] | None,
    now_unix: int,
    home: Path,
    bureau_root: Path,
) -> dict[str, Any]:
    unit = producer["unit"]
    service_properties, service_error = _systemd_show(
        unit,
        (
            "LoadState",
            "ActiveState",
            "SubState",
            "Result",
            "ExecMainCode",
            "ExecMainStatus",
            "ExecMainStartTimestamp",
            "ExecMainExitTimestamp",
            "InvocationID",
            "FragmentPath",
            "UnitFileState",
        ),
    )
    timer_properties = None
    timer_error = None
    if producer.get("timer_unit"):
        timer_properties, timer_error = _systemd_show(
            producer["timer_unit"],
            (
                "LoadState",
                "ActiveState",
                "SubState",
                "LastTriggerUSec",
                "NextElapseUSecRealtime",
                "UnitFileState",
                "FragmentPath",
            ),
        )
    if service_properties is None:
        return {
            "id": producer["id"],
            "owner_component": producer["owner_component"],
            "success_evidence": producer["success_evidence"],
            "unit": unit,
            "timer_unit": producer.get("timer_unit"),
            "status": "unknown",
            "run_state": "unobservable",
            "slo": {"max_age_seconds": producer["max_age_seconds"], "breached": None},
            "observation_error": _redact_message(service_error or "systemd service is unobservable"),
            "timer_observation_error": _redact_message(timer_error) if timer_error else None,
            "evidence": _evidence_status(producer.get("evidence_paths", []), home=home),
            "bureau": _bureau_status(producer.get("bureau_binding"), bureau_root=bureau_root),
            "attention": {"state": "review", "reason": "service-unobservable"},
        }

    active_state = service_properties.get("ActiveState")
    sub_state = service_properties.get("SubState")
    result_value = service_properties.get("Result")
    exec_status_raw = service_properties.get("ExecMainStatus")
    try:
        exec_status = int(exec_status_raw) if exec_status_raw not in (None, "") else None
    except ValueError:
        exec_status = None
    invocation_id = service_properties.get("InvocationID") or None
    started_at = _timestamp_to_epoch(service_properties.get("ExecMainStartTimestamp"))
    terminal_at = _timestamp_to_epoch(service_properties.get("ExecMainExitTimestamp"))
    failed = (
        active_state == "failed"
        or result_value not in (None, "", "success")
        or (exec_status is not None and exec_status != 0)
    )
    in_progress = active_state in {"activating", "active"} and sub_state not in {"failed", "dead", "exited"}
    current_success = not failed and result_value == "success" and exec_status in (None, 0) and terminal_at is not None

    previous = previous or {}
    last_success_at = terminal_at if current_success else previous.get("last_success_at_unix")
    if not isinstance(last_success_at, int):
        last_success_at = None
    age_seconds = now_unix - last_success_at if last_success_at is not None else None
    if age_seconds is not None:
        age_seconds = max(0, age_seconds)

    journal_error = None
    raw_messages: list[str] = []
    normalized_messages: list[str] = []
    if failed:
        journal, journal_error = _journal_entries(
            unit,
            invocation_id,
            started_at_unix=started_at,
            terminal_at_unix=terminal_at,
        )
        raw_messages, normalized_messages = _failure_messages(journal)
    fingerprint = None
    consecutive_failures = 0
    run_identity = invocation_id or (f"terminal:{terminal_at}" if terminal_at is not None else None)
    if failed:
        if not normalized_messages:
            normalized_messages = [
                f"result={result_value or 'unknown'} exec_status={exec_status!r} active={active_state} sub={sub_state}"
            ]
            raw_messages = normalized_messages.copy()
        fingerprint = _sha256_bytes(
            _canonical_json(
                {
                    "producer_id": producer["id"],
                    "unit": unit,
                    "result": result_value,
                    "exec_status": exec_status,
                    "messages": normalized_messages,
                }
            )
        )
        previous_fingerprint = previous.get("failure_fingerprint")
        previous_run_identity = previous.get("run_identity")
        previous_count = previous.get("consecutive_failures")
        if (
            previous_fingerprint == fingerprint
            and previous_run_identity == run_identity
            and isinstance(previous_count, int)
        ):
            consecutive_failures = previous_count
        elif previous_fingerprint == fingerprint and isinstance(previous_count, int):
            consecutive_failures = previous_count + 1
        else:
            consecutive_failures = 1

    if failed:
        status_value = "failed"
        run_state = "terminal-failed"
        breached: bool | None = True
    elif in_progress:
        status_value = "observed"
        run_state = "running"
        breached = age_seconds > producer["max_age_seconds"] if age_seconds is not None else None
    elif last_success_at is None:
        status_value = "unknown"
        run_state = "no-success-evidence"
        breached = None
    elif age_seconds is not None and age_seconds > producer["max_age_seconds"]:
        status_value = "stale"
        run_state = "terminal-success"
        breached = True
    else:
        status_value = "observed"
        run_state = "terminal-success"
        breached = False

    timer_state = None
    if timer_properties is not None:
        timer_ready = (
            timer_properties.get("LoadState") == "loaded"
            and timer_properties.get("ActiveState") == "active"
        )
        timer_state = {
            "health": "ready" if timer_ready else "not-ready",
            "load_state": timer_properties.get("LoadState"),
            "active_state": timer_properties.get("ActiveState"),
            "sub_state": timer_properties.get("SubState"),
            "unit_file_state": timer_properties.get("UnitFileState"),
            "last_trigger_unix": _timestamp_to_epoch(timer_properties.get("LastTriggerUSec")),
            "next_elapse_unix": _timestamp_to_epoch(timer_properties.get("NextElapseUSecRealtime")),
            "fragment_path": timer_properties.get("FragmentPath"),
        }

    evidence = _evidence_status(producer.get("evidence_paths", []), home=home)
    evidence_issue = any(item.get("state") != "observed" for item in evidence)

    attention_state = "none"
    attention_reason = None
    if status_value in {"failed", "stale"}:
        attention_state = "required"
        attention_reason = status_value
    elif producer.get("timer_unit") and timer_properties is None:
        attention_state = "review"
        attention_reason = "timer-unobservable"
    elif timer_state is not None and timer_state["health"] != "ready":
        attention_state = "required"
        attention_reason = "timer-not-active"
    elif evidence_issue:
        attention_state = "review"
        attention_reason = "evidence-unavailable"
    elif status_value == "unknown":
        attention_state = "review"
        attention_reason = "insufficient-evidence"

    escalation_key = None
    if fingerprint is not None:
        escalation_key = _sha256_bytes(f"{producer['id']}:{fingerprint}".encode("utf-8"))

    return {
        "id": producer["id"],
        "owner_component": producer["owner_component"],
        "success_evidence": producer["success_evidence"],
        "unit": unit,
        "timer_unit": producer.get("timer_unit"),
        "status": status_value,
        "run_state": run_state,
        "run_identity": run_identity,
        "service": {
            "load_state": service_properties.get("LoadState"),
            "active_state": active_state,
            "sub_state": sub_state,
            "result": result_value,
            "exec_main_code": service_properties.get("ExecMainCode"),
            "exec_main_status": exec_status,
            "fragment_path": service_properties.get("FragmentPath"),
            "unit_file_state": service_properties.get("UnitFileState"),
        },
        "timer": timer_state,
        "started_at_unix": started_at,
        "terminal_at_unix": terminal_at,
        "last_success_at_unix": last_success_at,
        "slo": {
            "max_age_seconds": producer["max_age_seconds"],
            "age_since_success_seconds": age_seconds,
            "breached": breached,
        },
        "failure_fingerprint": fingerprint,
        "failure_messages": raw_messages,
        "consecutive_failures": consecutive_failures,
        "escalation_key": escalation_key,
        "journal_observation_error": _redact_message(journal_error) if journal_error else None,
        "timer_observation_error": _redact_message(timer_error) if timer_error else None,
        "evidence": evidence,
        "bureau": _bureau_status(producer.get("bureau_binding"), bureau_root=bureau_root),
        "attention": {
            "state": attention_state,
            "reason": attention_reason,
            "automatic_mutation_authorized": False,
        },
    }


def collect(
    *,
    policy_path: Path,
    output_path: Path,
    bureau_root: Path,
    home: Path,
    now_unix: int | None = None,
) -> dict[str, Any]:
    policy, policy_sha256 = _validate_policy(policy_path)
    previous = _load_json(output_path, required=output_path.exists())
    previous_by_id = _previous_map(previous)
    observed_at = int(now_unix if now_unix is not None else __import__("time").time())
    producers = [
        _service_outcome(
            producer,
            previous=previous_by_id.get(producer["id"]),
            now_unix=observed_at,
            home=home,
            bureau_root=bureau_root,
        )
        for producer in policy["producers"]
    ]
    counts = {key: sum(1 for item in producers if item["status"] == key) for key in (
        "observed",
        "stale",
        "failed",
        "unknown",
        "not-applicable",
    )}
    attention_count = sum(1 for item in producers if item["attention"]["state"] != "none")
    artifact: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": ARTIFACT_KIND,
        "generated_at_unix": observed_at,
        "host": os.uname().nodename,
        "policy_path": str(policy_path),
        "policy_sha256": policy_sha256,
        "producers": producers,
        "summary": {
            "producer_count": len(producers),
            "status_counts": counts,
            "attention_count": attention_count,
            "automatic_repair_authorized": False,
        },
        "does_not_establish": [
            "root_cause_from_unit_failure_alone",
            "automatic_service_restart_authority",
            "automatic_cleanup_authority",
            "task_or_queue_truth",
            "future_timer_success",
            "absence_of_unobserved_maintenance_producers",
        ],
    }
    artifact["artifact_sha256"] = _sha256_bytes(_canonical_json(artifact))
    _atomic_json(output_path, artifact)
    return artifact


def _run_receipt(result: dict[str, Any]) -> dict[str, Any]:
    """Return the compact, artifact-bound success record intended for stdout."""
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "heim_pc_maintenance_outcomes_run_receipt",
        "generated_at_unix": result["generated_at_unix"],
        "artifact_sha256": result["artifact_sha256"],
        "summary": result["summary"],
    }


def main() -> int:
    home = Path.home().resolve()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=home / ".local/state/heim-pc/maintenance-outcomes/maintenance-outcomes.v1.json",
    )
    parser.add_argument("--bureau-root", type=Path, default=home / "repos/bureau")
    parser.add_argument("--home", type=Path, default=home)
    parser.add_argument("--now-unix", type=int)
    args = parser.parse_args()
    output_path = args.output.expanduser().resolve()
    try:
        result = collect(
            policy_path=args.policy.expanduser().resolve(),
            output_path=output_path,
            bureau_root=args.bureau_root.expanduser().resolve(),
            home=args.home.expanduser().resolve(),
            now_unix=args.now_unix,
        )
    except (OutcomeError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(
            json.dumps(
                {"kind": "heim_pc_maintenance_outcomes_error", "error": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(
        json.dumps(
            _run_receipt(result),
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
