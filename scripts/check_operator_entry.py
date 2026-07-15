#!/usr/bin/env python3
"""Validate the canonical heim-pc operator entry and optional installed projections."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "manifest/operator-entry.v1.json"
MANAGED_BUILD_POLICY_PATH = ROOT / "config/managed-build.v1.json"
AI_CONTEXT_PATH = ROOT / ".ai-context.yml"
AGENT_POINTER_PATH = ROOT / "config/agents/home-AGENTS.md"
REPOS_AGENT_POINTER_PATH = ROOT / "config/agents/repos-root-AGENTS.md"
README_POINTER_PATH = ROOT / "config/agents/home-README.md"
RECEIPT_RELATIVE_PATH = Path(".local/state/heim-pc/operator-entry-install-receipt.v1.json")
HOME_VARIABLE = "${HOME}"
SECRET_MATERIAL_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require_object(value: Any, name: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{name} must be an object")
        return {}
    return value


def _require_host_path(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not (value == HOME_VARIABLE or value.startswith(f"{HOME_VARIABLE}/")):
        errors.append(f"{name} must be a ${{HOME}}-rooted path template")
        return
    remainder = value.removeprefix(HOME_VARIABLE)
    if any(part == ".." for part in Path(remainder or "/").parts):
        errors.append(f"{name} must not traverse above ${{HOME}}")


def _iter_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _iter_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item)


def _validate_receipt(home: Path, contract_sha256: str, errors: list[str]) -> dict[str, Any]:
    receipt_path = home / RECEIPT_RELATIVE_PATH
    receipt_errors: list[str] = []
    status: dict[str, Any] = {
        "target": str(receipt_path),
        "exists": receipt_path.is_file() and not receipt_path.is_symlink(),
        "valid": False,
        "targetSha256": _sha256(receipt_path)
        if receipt_path.is_file() and not receipt_path.is_symlink()
        else None,
    }
    if receipt_path.is_symlink():
        receipt_errors.append("installed receipt must not be a symlink")
    elif not receipt_path.exists():
        receipt_errors.append("installed receipt is missing")
    elif not receipt_path.is_file():
        receipt_errors.append("installed receipt is not a regular file")
    else:
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            receipt_errors.append(f"installed receipt cannot be read: {exc}")
        else:
            if receipt.get("kind") != "heim_pc_operator_entry_install_receipt":
                receipt_errors.append("installed receipt has unsupported kind")
            if receipt.get("valid") is not True or receipt.get("apply") is not True:
                receipt_errors.append("installed receipt does not attest a successful apply")
            if receipt.get("sourceContractSha256") != contract_sha256:
                receipt_errors.append("installed receipt is not bound to the current contract")

            file_entries = receipt.get("files")
            if not isinstance(file_entries, list) or not file_entries:
                receipt_errors.append("installed receipt has no file entries")
                file_entries = []
            for item in file_entries:
                if not isinstance(item, dict):
                    receipt_errors.append("installed receipt contains a malformed file entry")
                    continue
                target_value = item.get("target")
                expected_sha256 = item.get("afterSha256")
                if not isinstance(target_value, str) or not isinstance(expected_sha256, str):
                    receipt_errors.append("installed receipt file entry lacks target or afterSha256")
                    continue
                target = Path(target_value)
                try:
                    target.resolve(strict=False).relative_to(home.resolve())
                except ValueError:
                    receipt_errors.append(f"installed receipt target escapes home: {target}")
                    continue
                if target.is_symlink() or not target.is_file() or _sha256(target) != expected_sha256:
                    receipt_errors.append(f"installed receipt target differs from attested content: {target}")

            status["sourceContractSha256"] = receipt.get("sourceContractSha256")

    errors.extend(receipt_errors)
    status["valid"] = not receipt_errors
    status["errors"] = receipt_errors
    return status


def check(*, home: Path, require_installed: bool) -> dict[str, Any]:
    errors: list[str] = []
    try:
        contract_text = CONTRACT_PATH.read_text(encoding="utf-8")
        contract = json.loads(contract_text)
    except (OSError, json.JSONDecodeError) as exc:
        contract_text = ""
        contract = {}
        errors.append(f"cannot read canonical contract: {exc}")

    if contract.get("schemaVersion") != 1:
        errors.append("schemaVersion must be 1")
    if contract.get("kind") != "heim_pc_operator_entry":
        errors.append("kind must be heim_pc_operator_entry")
    if contract.get("authority") != "static_local_entry_contract":
        errors.append("authority must be static_local_entry_contract")

    operator_model = _require_object(contract.get("operatorModel"), "operatorModel", errors)
    if operator_model.get("operator") != "chatgpt_via_grabowski":
        errors.append("operatorModel.operator must be chatgpt_via_grabowski")
    if operator_model.get("humanRole") != "meaning_approval_abort":
        errors.append("operatorModel.humanRole must be meaning_approval_abort")
    for flag in ("machineFirst", "proseIsProjection", "liveStateRequiresFreshRead", "doNotDelegateShellToHuman"):
        if operator_model.get(flag) is not True:
            errors.append(f"operatorModel.{flag} must be true")

    host = _require_object(contract.get("host"), "host", errors)
    if host.get("role") != "primary_local_operator_host":
        errors.append("host.role must be primary_local_operator_host")
    for field in (
        "home",
        "repositoriesRoot",
        "canonicalEntryRepository",
        "canonicalEntryFile",
        "installedEntryFile",
        "agentPointer",
        "repositoriesAgentPointer",
    ):
        _require_host_path(host.get(field), f"host.{field}", errors)

    managed_builds = _require_object(contract.get("managedBuilds"), "managedBuilds", errors)
    _require_host_path(managed_builds.get("policy"), "managedBuilds.policy", errors)
    expected_managed_build_argv = [
        "python3",
        "${HOME}/repos/heim-pc/scripts/managed_build.py",
    ]
    if managed_builds.get("entryArgv") != expected_managed_build_argv:
        errors.append("managedBuilds.entryArgv must name the canonical managed build entry")
    if managed_builds.get("automationRule") != "operator_managed_builds_use_entry":
        errors.append("managedBuilds.automationRule must require the canonical entry")
    if managed_builds.get("interactiveShellBehavior") != "unchanged":
        errors.append("managedBuilds.interactiveShellBehavior must remain unchanged")
    warning_bytes = managed_builds.get("worktreeWarningBytes")
    hard_bytes = managed_builds.get("worktreeHardBytes")
    if (
        not isinstance(warning_bytes, int)
        or isinstance(warning_bytes, bool)
        or not isinstance(hard_bytes, int)
        or isinstance(hard_bytes, bool)
        or warning_bytes < 0
        or hard_bytes < warning_bytes
    ):
        errors.append("managedBuilds worktree budgets must be ordered non-negative integers")
    if managed_builds.get("automaticCleanupAuthorized") is not False:
        errors.append("managedBuilds.automaticCleanupAuthorized must remain false")
    managed_limits = managed_builds.get("doesNotEstablish")
    required_managed_limits = {
        "execution_authority_for_child_commands",
        "build_correctness",
        "permission_to_delete_worktree_or_cache_payloads",
        "global_shell_environment_changes",
    }
    if not isinstance(managed_limits, list) or not required_managed_limits.issubset(set(managed_limits)):
        errors.append("managedBuilds.doesNotEstablish is incomplete")

    try:
        managed_policy = json.loads(MANAGED_BUILD_POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        managed_policy = {}
        errors.append(f"cannot read managed build policy: {exc}")
    if managed_policy.get("schema_version") != 1:
        errors.append("managed build policy schema_version must be 1")
    if managed_policy.get("kind") != "heim_pc.managed_build_policy":
        errors.append("managed build policy kind is unsupported")
    if managed_policy.get("interactive_shell_behavior") != "unchanged":
        errors.append("managed build policy must preserve interactive shell behavior")
    if managed_policy.get("automatic_cleanup_authorized") is not False:
        errors.append("managed build policy must not authorize automatic cleanup")
    _require_host_path(managed_policy.get("cache_root"), "managed build policy cache_root", errors)
    _require_host_path(managed_policy.get("state_root"), "managed build policy state_root", errors)
    policy_budget = _require_object(
        managed_policy.get("managed_worktree_budget_bytes"),
        "managed build policy managed_worktree_budget_bytes",
        errors,
    )
    if policy_budget.get("warning") != warning_bytes or policy_budget.get("hard") != hard_bytes:
        errors.append("managedBuilds worktree budgets must match the managed build policy")

    entry_sequence = contract.get("entrySequence")
    if not isinstance(entry_sequence, list) or not entry_sequence:
        errors.append("entrySequence must be a non-empty array")
        entry_sequence = []
    entry_ids = [item.get("id") for item in entry_sequence if isinstance(item, dict)]
    if len(entry_ids) != len(entry_sequence) or any(not isinstance(item, str) or not item for item in entry_ids):
        errors.append("every entrySequence item must have a non-empty string id")
    if len(entry_ids) != len(set(entry_ids)):
        errors.append("entrySequence ids must be unique")
    required_entry_ids = {
        "runtime_identity",
        "execution_contract",
        "operator_context",
        "local_entry",
        "scope_classification",
        "source_resolution",
        "target_specific_live_state",
    }
    if not required_entry_ids.issubset(set(entry_ids)):
        errors.append("entrySequence is missing required entry steps")

    truth_sources = _require_object(contract.get("truthSources"), "truthSources", errors)
    required_sources = {
        "stableEcosystemSemantics",
        "tasksClaimsReceipts",
        "executionRuntimeLeases",
        "repositoriesPullRequestsReviews",
        "technicalChecks",
        "repositoryContext",
        "appendOnlyHistory",
        "fleetMembershipAndContracts",
    }
    missing_sources = sorted(required_sources - set(truth_sources))
    if missing_sources:
        errors.append(f"truthSources missing: {', '.join(missing_sources)}")

    source_policy = _require_object(contract.get("sourcePolicy"), "sourcePolicy", errors)
    excluded_paths = {
        item.get("path")
        for item in source_policy.get("excludedAsCurrentTruth", [])
        if isinstance(item, dict)
    }
    required_exclusions = {
        "${HOME}/repos/heim-pc/state/index.json",
        "${HOME}/repos/heim-pc/state/repos.json",
    }
    if not required_exclusions.issubset(excluded_paths):
        errors.append("sourcePolicy must exclude placeholder state index and repository inventory")

    path_resolution = _require_object(contract.get("pathResolution"), "pathResolution", errors)
    variables = _require_object(path_resolution.get("variables"), "pathResolution.variables", errors)
    home_resolution = _require_object(variables.get("HOME"), "pathResolution.variables.HOME", errors)
    if home_resolution.get("source") != "operator_process_home":
        errors.append("pathResolution.variables.HOME.source must be operator_process_home")
    if home_resolution.get("required") is not True:
        errors.append("pathResolution.variables.HOME.required must be true")
    if home_resolution.get("mustResolveToAbsoluteDirectory") is not True:
        errors.append("pathResolution.variables.HOME.mustResolveToAbsoluteDirectory must be true")
    if path_resolution.get("publicTemplateContainsResolvedHostPath") is not False:
        errors.append("pathResolution.publicTemplateContainsResolvedHostPath must be false")
    if "/home/" in contract_text:
        errors.append("public operator-entry contract contains a resolved /home path")

    projection = _require_object(contract.get("projection"), "projection", errors)
    expected_projection = {
        "source": "manifest/operator-entry.v1.json",
        "aiContext": ".ai-context.yml",
        "installedContract": "${HOME}/.config/heimgewebe/operator-entry.v1.json",
        "homeAgentPointer": "${HOME}/AGENTS.md",
        "repositoriesAgentPointer": "${HOME}/repos/AGENTS.md",
        "homeReadmePointer": "${HOME}/README.md",
        "installer": "scripts/install_operator_entry.py",
        "checker": "scripts/check_operator_entry.py",
        "byteIdenticalContractRequired": True,
    }
    for key, expected in expected_projection.items():
        if projection.get(key) != expected:
            errors.append(f"projection.{key} must equal {expected!r}")

    ai_context = AI_CONTEXT_PATH.read_text(encoding="utf-8") if AI_CONTEXT_PATH.exists() else ""
    for required_text in (
        "role: operator-entry",
        "canonical_entry: manifest/operator-entry.v1.json",
        "kind: chatgpt_via_grabowski",
        "machine_first: true",
    ):
        if required_text not in ai_context:
            errors.append(f".ai-context.yml missing required declaration: {required_text}")

    forbidden_top_level = {"runtimeHealth", "taskPriority", "mergeReadiness", "currentHead"}
    present_forbidden = sorted(forbidden_top_level & set(contract))
    if present_forbidden:
        errors.append(f"static contract contains live-state fields: {', '.join(present_forbidden)}")
    for string_value in _iter_strings(contract):
        if any(pattern.search(string_value) for pattern in SECRET_MATERIAL_PATTERNS):
            errors.append("static contract appears to contain secret material")
            break

    home = home.expanduser().resolve()
    installed = {
        "contract": home / ".config/heimgewebe/operator-entry.v1.json",
        "agentPointer": home / "AGENTS.md",
        "reposAgentPointer": home / "repos/AGENTS.md",
        "readmePointer": home / "README.md",
    }
    sources = {
        "contract": CONTRACT_PATH,
        "agentPointer": AGENT_POINTER_PATH,
        "reposAgentPointer": REPOS_AGENT_POINTER_PATH,
        "readmePointer": README_POINTER_PATH,
    }
    projection_status: dict[str, Any] = {}
    for name, target in installed.items():
        exists = target.is_file() and not target.is_symlink()
        matches = exists and target.read_bytes() == sources[name].read_bytes()
        projection_status[name] = {
            "target": str(target),
            "exists": exists,
            "matchesSource": matches,
            "targetSha256": _sha256(target) if exists else None,
            "sourceSha256": _sha256(sources[name]),
        }
        if require_installed and not matches:
            errors.append(f"installed {name} is missing or differs from canonical source")

    contract_sha256 = _sha256(CONTRACT_PATH) if CONTRACT_PATH.exists() else ""
    receipt_path = home / RECEIPT_RELATIVE_PATH
    if require_installed:
        projection_status["receipt"] = _validate_receipt(home, contract_sha256, errors)
    else:
        projection_status["receipt"] = {
            "target": str(receipt_path),
            "exists": receipt_path.is_file() and not receipt_path.is_symlink(),
            "targetSha256": _sha256(receipt_path)
            if receipt_path.is_file() and not receipt_path.is_symlink()
            else None,
        }

    return {
        "schemaVersion": 1,
        "kind": "heim_pc_operator_entry_check_receipt",
        "valid": not errors,
        "requireInstalled": require_installed,
        "contract": str(CONTRACT_PATH),
        "contractSha256": contract_sha256 or None,
        "projection": projection_status,
        "errors": errors,
        "doesNotEstablish": [
            "grabowski_runtime_health",
            "connector_snapshot_freshness",
            "systemkatalog_semantic_truth",
            "task_priority",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--require-installed", action="store_true")
    args = parser.parse_args()
    receipt = check(home=args.home, require_installed=args.require_installed)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0 if receipt["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
