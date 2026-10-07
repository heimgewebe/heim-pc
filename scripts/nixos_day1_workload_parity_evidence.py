#!/usr/bin/env python3
"""Build fail-closed Day-1 workload-parity runtime evidence.

This helper does not classify workloads and never grants readiness. It only
validates one fresh, bounded heim-pc inventory observation against the reviewed
Day-1 contract and can bind that evidence into ``inventory.current_binding``.
"""
from __future__ import annotations

import argparse
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


def build_current_binding(
    *,
    root: Path,
    contract_path: Path,
    source_revision: str,
    observation_id: str,
    started_at: str,
    completed_at: str,
    software_execution_receipt_sha256: str,
    software_argv: Iterable[str],
    program_execution_receipt_sha256: str,
    program_argv: Iterable[str],
) -> dict[str, Any]:
    root = root.resolve()
    _require_hex(source_revision, HEX40, field="source_revision")
    _require_hex(observation_id, HEX64, field="observation_id")

    contract_path = contract_path.resolve()
    try:
        contract_relpath = contract_path.relative_to(root).as_posix()
    except ValueError as exc:
        raise Day1EvidenceError("contract path must be inside repository root") from exc
    _source_file_digest(root, source_revision, contract_relpath)

    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    inventory = contract["inventory"]
    schema = inventory["current_binding_schema"]
    authoritative_host = inventory["authoritative_host"]

    _require_hex(
        software_execution_receipt_sha256,
        HEX64,
        field="software_execution_receipt_sha256",
    )
    _require_hex(
        program_execution_receipt_sha256,
        HEX64,
        field="program_execution_receipt_sha256",
    )

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

    for relpath in expected_paths:
        path = root / relpath
        if not path.is_file():
            raise Day1EvidenceError(f"required output missing: {relpath}")
        row = {"path": relpath, "sha256": _sha256_file(path), **metadata[relpath]}
        outputs.append(row)

    software_script = schema["provenance"]["software"]["collector_path"]
    program_schema = schema["provenance"]["program"]
    program_collector = program_schema["collector_path"]
    program_renderer = program_schema["renderer_path"]

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

    software_args = _require_argv_binding(
        software_argv,
        observation_id=observation_id,
        observed_at=software_observed_at,
        expected_script=software_script,
        field="software execution",
    )
    program_args = _require_argv_binding(
        program_argv,
        observation_id=observation_id,
        observed_at=program_observed_at,
        expected_script=program_collector,
        field="program execution",
    )

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
                "execution_receipt_sha256": software_execution_receipt_sha256,
                "argv": software_args,
            },
            "program": {
                "collector_path": program_collector,
                "collector_sha256": program_collector_sha,
                "renderer_path": program_renderer,
                "renderer_sha256": program_renderer_sha,
                "execution_receipt_sha256": program_execution_receipt_sha256,
                "argv": program_args,
                "raw_manifest_sha256": raw_manifest_sha,
                "raw_artifact_count": raw_artifact_count,
            },
        },
    }


def write_evidence(
    *,
    contract_path: Path,
    evidence_path: Path,
    binding: dict[str, Any],
    update_contract: bool,
) -> None:
    payload = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_day1_workload_parity_current_evidence",
        "readiness_authorized": False,
        "classification_complete": False,
        "current_binding": binding,
    }
    evidence_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if update_contract:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        contract["inventory"]["current_binding"] = binding
        contract["admission"]["current_status"] = (
            "blocked-until-day1-classification-and-acceptance"
        )
        contract_path.write_text(
            json.dumps(contract, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


def _json_argv(value: str, *, field: str) -> list[str]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise Day1EvidenceError(f"{field} is not valid JSON") from exc
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        raise Day1EvidenceError(f"{field} must be a JSON array of strings")
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
    parser.add_argument("--software-execution-receipt-sha256", required=True)
    parser.add_argument("--software-argv-json", required=True)
    parser.add_argument("--program-execution-receipt-sha256", required=True)
    parser.add_argument("--program-argv-json", required=True)
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
        software_execution_receipt_sha256=args.software_execution_receipt_sha256,
        software_argv=_json_argv(args.software_argv_json, field="software argv"),
        program_execution_receipt_sha256=args.program_execution_receipt_sha256,
        program_argv=_json_argv(args.program_argv_json, field="program argv"),
    )
    write_evidence(
        contract_path=contract,
        evidence_path=evidence,
        binding=binding,
        update_contract=args.update_contract,
    )
    print(evidence)


if __name__ == "__main__":
    main()
