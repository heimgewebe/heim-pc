#!/usr/bin/env python3
"""Build fail-closed Day-1 workload-parity runtime evidence.

This helper does not classify workloads and never grants readiness. It only
validates one fresh, bounded heim-pc inventory observation against the reviewed
Day-1 contract and can bind that evidence into ``inventory.current_binding``.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "nixos/production/day1-workload-parity-contract-v1.json"
DEFAULT_EVIDENCE = (
    ROOT / "nixos/production/day1-workload-parity-current-evidence-v1.json"
)
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TASK_ID_RE = re.compile(r"^[0-9a-f]{16,64}$")


class Day1EvidenceError(RuntimeError):
    pass


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Day1EvidenceError(f"invalid RFC3339 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise Day1EvidenceError(f"timestamp has no timezone: {value!r}")
    return parsed.astimezone(timezone.utc)


def _frontmatter(path: Path) -> dict[str, str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---":
        raise Day1EvidenceError(f"{path} is missing YAML frontmatter")
    out: dict[str, str] = {}
    for line in lines[1:]:
        if line == "---":
            return out
        if not line or line.startswith((" ", "\t")) or ":" not in line:
            continue
        key, raw = line.split(":", 1)
        value = raw.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        out[key.strip()] = value
    raise Day1EvidenceError(f"{path} has unterminated YAML frontmatter")


def _bool_field(value: str | None, *, field: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise Day1EvidenceError(f"{field} must be true or false")


def _git_blob(root: Path, revision: str, relpath: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), "show", f"{revision}:{relpath}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise Day1EvidenceError(
            f"cannot read {relpath} from source revision {revision}: {detail}"
        )
    return completed.stdout


def _source_file_digest(root: Path, revision: str, relpath: str) -> str:
    source = _git_blob(root, revision, relpath)
    worktree = (root / relpath).read_bytes()
    source_digest = _sha256_bytes(source)
    if _sha256_bytes(worktree) != source_digest:
        raise Day1EvidenceError(
            f"{relpath} does not match reviewed source revision {revision}"
        )
    return source_digest


def _require_hex(value: str, pattern: re.Pattern[str], *, field: str) -> str:
    if not pattern.fullmatch(value):
        raise Day1EvidenceError(f"{field} has invalid digest/revision format")
    return value


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )


def _require_argv_binding(
    argv: Iterable[str],
    *,
    observation_id: str,
    observed_at: str,
    expected_script: str,
    field: str,
) -> list[str]:
    values = list(argv)
    if not values:
        raise Day1EvidenceError(f"{field} argv is empty")
    if expected_script not in values:
        raise Day1EvidenceError(f"{field} argv does not bind {expected_script}")
    for option, expected, label in (
        ("--observation-id", observation_id, "observation_id"),
        ("--observed-at", observed_at, "observed_at"),
    ):
        positions = [index for index, value in enumerate(values) if value == option]
        if len(positions) != 1:
            raise Day1EvidenceError(f"{field} argv must bind exactly one {option}")
        index = positions[0]
        if index + 1 >= len(values) or values[index + 1] != expected:
            raise Day1EvidenceError(f"{field} argv does not bind {label}")
    return values


def _verify_execution_receipt(
    receipt: dict[str, Any],
    *,
    authoritative_host: str,
    observation_id: str,
    observed_at: str,
    expected_script: str,
    field: str,
) -> dict[str, Any]:
    task_id = receipt.get("task_id")
    if not isinstance(task_id, str) or TASK_ID_RE.fullmatch(task_id) is None:
        raise Day1EvidenceError(f"{field} receipt task_id is invalid")
    attempt = receipt.get("attempt")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise Day1EvidenceError(f"{field} receipt attempt is invalid")
    expected_unit = f"grabowski-task-{task_id}-a{attempt}.service"
    if receipt.get("unit") != expected_unit:
        raise Day1EvidenceError(f"{field} receipt unit is not task/attempt bound")
    if receipt.get("host") != authoritative_host:
        raise Day1EvidenceError(f"{field} receipt host is not authoritative heim-pc")
    if receipt.get("state") != "completed":
        raise Day1EvidenceError(f"{field} receipt is not terminal successful")

    argv = receipt.get("argv")
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        raise Day1EvidenceError(f"{field} receipt argv must be an array of strings")
    argv = _require_argv_binding(
        argv,
        observation_id=observation_id,
        observed_at=observed_at,
        expected_script=expected_script,
        field=field,
    )
    argv_sha256 = receipt.get("argv_sha256")
    if not isinstance(argv_sha256, str) or HEX64.fullmatch(argv_sha256) is None:
        raise Day1EvidenceError(f"{field} receipt argv_sha256 is invalid")
    if argv_sha256 != _sha256_json(argv):
        raise Day1EvidenceError(f"{field} receipt argv_sha256 does not authenticate argv")

    lifecycle_receipt_sha256 = receipt.get("lifecycle_receipt_sha256")
    if (
        not isinstance(lifecycle_receipt_sha256, str)
        or HEX64.fullmatch(lifecycle_receipt_sha256) is None
    ):
        raise Day1EvidenceError(f"{field} lifecycle receipt digest is invalid")

    return {
        "task_id": task_id,
        "attempt": attempt,
        "unit": expected_unit,
        "host": authoritative_host,
        "state": "completed",
        "argv": argv,
        "argv_sha256": argv_sha256,
        "lifecycle_receipt_sha256": lifecycle_receipt_sha256,
    }


def build_current_binding(
    *,
    root: Path,
    contract_path: Path,
    source_revision: str,
    observation_id: str,
    started_at: str,
    completed_at: str,
    software_execution_receipt: dict[str, Any],
    program_execution_receipt: dict[str, Any],
) -> dict[str, Any]:
    root = root.resolve()
    _require_hex(source_revision, HEX40, field="source_revision")
    _require_hex(observation_id, HEX64, field="observation_id")

    contract_path = contract_path.resolve()
    try:
        contract_relpath = contract_path.relative_to(root).as_posix()
    except ValueError as exc:
        raise Day1EvidenceError("contract path must be inside repository root") from exc
    try:
        contract = json.loads(
            _git_blob(root, source_revision, contract_relpath).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Day1EvidenceError(
            "reviewed Day-1 contract is not valid UTF-8 JSON"
        ) from exc
    inventory = contract["inventory"]
    schema = inventory["current_binding_schema"]
    authoritative_host = inventory["authoritative_host"]


    started = _parse_time(started_at)
    completed = _parse_time(completed_at)
    if completed < started:
        raise Day1EvidenceError("observation completed_at precedes started_at")

    expected_paths = list(schema["required_output_paths"])
    if expected_paths != list(inventory["canonical_outputs"]):
        raise Day1EvidenceError("contract required outputs diverge from canonical outputs")

    outputs: list[dict[str, Any]] = []
    metadata: dict[str, dict[str, Any]] = {}

    software_path = root / "runtime/software-inventory.md"
    software_meta = _frontmatter(software_path)
    software_observed_at = software_meta.get("observed_at", "")
    software_id = software_meta.get("observation_id", "")
    software_binding = _bool_field(
        software_meta.get("binding_eligible"), field="software binding_eligible"
    )
    if software_meta.get("observed_host") != authoritative_host:
        raise Day1EvidenceError("software inventory host is not authoritative heim-pc")
    if software_id != observation_id or not software_binding:
        raise Day1EvidenceError("software inventory is not binding-eligible for session")
    software_observed = _parse_time(software_observed_at)
    if not (started <= software_observed <= completed):
        raise Day1EvidenceError("software observed_at falls outside observation session")
    metadata["runtime/software-inventory.md"] = {
        "observed_at": software_observed_at,
        "observation_id": software_id,
        "binding_eligible": software_binding,
    }

    summary_path = root / "runtime/program-inventory-summary.md"
    summary_meta = _frontmatter(summary_path)
    summary_observed_at = summary_meta.get("observed_at", "")
    summary_id = summary_meta.get("observation_id", "")
    summary_binding = _bool_field(
        summary_meta.get("binding_eligible"), field="program summary binding_eligible"
    )
    summary_observed = _parse_time(summary_observed_at)
    if summary_id != observation_id or not summary_binding:
        raise Day1EvidenceError("program summary is not binding-eligible for session")
    if not (started <= summary_observed <= completed):
        raise Day1EvidenceError("program summary observed_at falls outside observation session")
    metadata["runtime/program-inventory-summary.md"] = {
        "observed_at": summary_observed_at,
        "observation_id": summary_id,
        "binding_eligible": summary_binding,
    }

    program_path = root / "runtime/program-inventory.v1.json"
    program = json.loads(program_path.read_text(encoding="utf-8"))
    scope = program.get("observation_scope", {})
    provenance = program.get("collection_provenance", {})
    program_observed_at = str(scope.get("observed_at", ""))
    program_id = scope.get("observation_id")
    program_binding = scope.get("binding_eligible")
    program_observed = _parse_time(program_observed_at)
    if program_id != observation_id or program_binding is not True:
        raise Day1EvidenceError("program JSON is not binding-eligible for session")
    if not (started <= program_observed <= completed):
        raise Day1EvidenceError("program JSON observed_at falls outside observation session")
    if provenance.get("host") != authoritative_host:
        raise Day1EvidenceError("program inventory host is not authoritative heim-pc")
    metadata["runtime/program-inventory.v1.json"] = {
        "observed_at": program_observed_at,
        "observation_id": program_id,
        "binding_eligible": True,
    }

    if len({item["observation_id"] for item in metadata.values()}) != 1:
        raise Day1EvidenceError("required outputs do not share one observation_id")

    software_script = schema["provenance"]["software"]["collector_path"]
    program_schema = schema["provenance"]["program"]
    program_collector = program_schema["collector_path"]
    program_renderer = program_schema["renderer_path"]

    software_execution = _verify_execution_receipt(
        software_execution_receipt,
        authoritative_host=authoritative_host,
        observation_id=observation_id,
        observed_at=software_observed_at,
        expected_script=software_script,
        field="software execution",
    )
    program_execution = _verify_execution_receipt(
        program_execution_receipt,
        authoritative_host=authoritative_host,
        observation_id=observation_id,
        observed_at=program_observed_at,
        expected_script=program_collector,
        field="program execution",
    )

    for relpath in expected_paths:
        path = root / relpath
        if not path.is_file():
            raise Day1EvidenceError(f"required output missing: {relpath}")
        row = {"path": relpath, "sha256": _sha256_file(path), **metadata[relpath]}
        outputs.append(row)

    software_collector_sha = _source_file_digest(root, source_revision, software_script)
    program_collector_sha = _source_file_digest(root, source_revision, program_collector)
    program_renderer_sha = _source_file_digest(root, source_revision, program_renderer)

    if software_meta.get("collector_sha256") != software_collector_sha:
        raise Day1EvidenceError("software output collector digest mismatches source revision")
    if provenance.get("collector_sha256") != program_collector_sha:
        raise Day1EvidenceError("program output collector digest mismatches source revision")

    raw_manifest_sha = str(provenance.get("raw_manifest_sha256", ""))
    _require_hex(raw_manifest_sha, HEX64, field="program raw_manifest_sha256")
    raw_artifact_count = provenance.get("raw_artifact_count")
    if not isinstance(raw_artifact_count, int) or raw_artifact_count < 1:
        raise Day1EvidenceError("program raw_artifact_count must be a positive integer")


    return {
        "host": authoritative_host,
        "source_revision": source_revision,
        "observation": {
            "kind": schema["observation"]["kind"],
            "id": observation_id,
            "started_at": started_at,
            "completed_at": completed_at,
        },
        "outputs": outputs,
        "provenance": {
            "software": {
                "collector_path": software_script,
                "collector_sha256": software_collector_sha,
                "execution_receipt_sha256": software_execution[
                    "lifecycle_receipt_sha256"
                ],
                "execution": software_execution,
                "argv": software_execution["argv"],
            },
            "program": {
                "collector_path": program_collector,
                "collector_sha256": program_collector_sha,
                "renderer_path": program_renderer,
                "renderer_sha256": program_renderer_sha,
                "execution_receipt_sha256": program_execution[
                    "lifecycle_receipt_sha256"
                ],
                "execution": program_execution,
                "argv": program_execution["argv"],
                "raw_manifest_sha256": raw_manifest_sha,
                "raw_artifact_count": raw_artifact_count,
            },
        },
    }


def write_evidence(
    *,
    root: Path,
    contract_path: Path,
    evidence_path: Path,
    binding: dict[str, Any],
    update_contract: bool,
) -> None:
    root = root.resolve()
    contract_path = contract_path.resolve()
    evidence_path = evidence_path.resolve()
    try:
        evidence_path.relative_to(root)
    except ValueError as exc:
        raise Day1EvidenceError("evidence path must be inside repository root") from exc

    try:
        contract_relpath = contract_path.relative_to(root).as_posix()
    except ValueError as exc:
        raise Day1EvidenceError("contract path must be inside repository root") from exc

    source_revision = str(binding.get("source_revision", ""))
    _require_hex(source_revision, HEX40, field="binding source_revision")
    try:
        reviewed_contract = json.loads(
            _git_blob(root, source_revision, contract_relpath).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Day1EvidenceError(
            "reviewed Day-1 contract is not valid UTF-8 JSON"
        ) from exc

    expected_bound_contract = copy.deepcopy(reviewed_contract)
    expected_bound_contract["inventory"]["current_binding"] = binding
    expected_bound_contract["admission"]["current_status"] = (
        "blocked-until-day1-classification-and-acceptance"
    )

    try:
        existing_contract = json.loads(contract_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise Day1EvidenceError("worktree Day-1 contract is not valid JSON") from exc
    if existing_contract not in (reviewed_contract, expected_bound_contract):
        raise Day1EvidenceError(
            "worktree Day-1 contract is neither the reviewed preimage nor the identical bound post-state"
        )

    payload = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_day1_workload_parity_current_evidence",
        "readiness_authorized": False,
        "classification_complete": False,
        "current_binding": binding,
    }

    if evidence_path.exists():
        try:
            existing_evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise Day1EvidenceError(
                "existing evidence file is not valid JSON and will not be overwritten"
            ) from exc
        if existing_evidence != payload:
            raise Day1EvidenceError(
                "refusing to replace different existing Day-1 evidence"
            )
    else:
        evidence_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if update_contract and existing_contract == reviewed_contract:
        contract_path.write_text(
            json.dumps(expected_bound_contract, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


def _json_object(value: str, *, field: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise Day1EvidenceError(f"{field} is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise Day1EvidenceError(f"{field} must be a JSON object")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--evidence-out", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--observation-id", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--completed-at", required=True)
    parser.add_argument("--software-execution-receipt-json", required=True)
    parser.add_argument("--program-execution-receipt-json", required=True)
    parser.add_argument("--update-contract", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = args.root.resolve()
    contract = args.contract
    if not contract.is_absolute():
        contract = root / contract
    evidence = args.evidence_out
    if not evidence.is_absolute():
        evidence = root / evidence
    binding = build_current_binding(
        root=root,
        contract_path=contract,
        source_revision=args.source_revision,
        observation_id=args.observation_id,
        started_at=args.started_at,
        completed_at=args.completed_at,
        software_execution_receipt=_json_object(
            args.software_execution_receipt_json,
            field="software execution receipt",
        ),
        program_execution_receipt=_json_object(
            args.program_execution_receipt_json,
            field="program execution receipt",
        ),
    )
    write_evidence(
        root=root,
        contract_path=contract,
        evidence_path=evidence,
        binding=binding,
        update_contract=args.update_contract,
    )
    print(evidence)


if __name__ == "__main__":
    main()
