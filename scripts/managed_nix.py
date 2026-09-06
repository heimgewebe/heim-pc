#!/usr/bin/env python3
"""Effect-free managed NixOS build/activation contracts for the Heim-PC.

This module validates immutable build inputs, observed source bindings and
receipt-bound activation authority. It intentionally contains no Nix build or
runtime NixOS activation executor. Realization/activation is delegated to a
separately authorized successor (migration T004/T011).

The CLI is validation-only. Supplying ``--observed-*``, ``--expected-target``
or ``--now`` proves only that the supplied values satisfy this pure contract;
an executable successor must obtain those values from its trusted Git/runtime
observer and clock before any effect.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


class ManagedNixError(ValueError):
    """Raised before any runtime effect when a managed Nix binding is invalid."""


class ManagedNixContractError(RuntimeError):
    """Raised when the checked-in v1 contract itself is unsupported or malformed."""


CONTRACT_VERSION = 1
_CONTRACT_KIND = "heim_pc.nixos_managed_deployment_contract"
_CONTRACT_PATH = Path(__file__).resolve().parents[1] / "nixos" / "deployment" / "contract-v1.json"

# Contract-v1 sentinels. The JSON file is the runtime policy source, while these
# constants make semantic changes to safety-critical v1 policy fail closed.
_SUPPORTED_BUILD_REQUEST_FIELDS = frozenset(
    {
        "schema_version", "kind", "effect_class", "repository",
        "source_revision", "control_release_set", "nix_inputs", "budgets",
        "leases", "possible_effects", "entrypoint",
    }
)
_SUPPORTED_BUILD_RECEIPT_FIELDS = frozenset(
    {
        "schema_version", "kind", "effect_class", "result", "repository",
        "source_revision", "control_release_set", "nix_inputs_sha256",
        "budgets", "leases_sha256", "possible_effects", "effect_scope",
        "system_closure", "declared_capabilities", "build_request_sha256",
        "build_source_context_sha256", "activation_authorized",
    }
)
_SUPPORTED_ACTIVATION_AUTHORITY_FIELDS = frozenset(
    {
        "schema_version", "kind", "effect_class", "mode", "source_revision",
        "system_closure", "target", "build_receipt_sha256", "prior_closure",
        "recovery_path", "issued_at", "expires_at",
    }
)
_SUPPORTED_ACTIVATION_PLAN_FIELDS = frozenset(
    {
        "schema_version", "kind", "effect_class", "mode", "target",
        "source_revision", "system_closure", "build_receipt_sha256",
        "prior_closure", "recovery_path", "authority_sha256", "issued_at",
        "expires_at", "executor_authority", "source_reevaluation_allowed",
        "broad_root_shell_allowed",
    }
)
_SUPPORTED_ACTIVATION_RECEIPT_FIELDS = frozenset(
    {
        "schema_version", "kind", "effect_class", "result", "mode", "target",
        "source_revision", "system_closure", "live_closure",
        "build_receipt_sha256", "authority_sha256", "readback_evidence_sha256",
        "prior_closure", "recovery_path", "source_reevaluation_used",
    }
)
_SUPPORTED_ROLLBACK_PLAN_FIELDS = frozenset(
    {
        "schema_version", "kind", "target", "system_closure",
        "recovery_path", "source_reevaluation_allowed",
    }
)
_SUPPORTED_BUILD_SOURCE_CONTEXT_FIELDS = frozenset(
    {"schema_version", "kind", "repository", "source_revision", "build_request_sha256"}
)
_SUPPORTED_STORE_ROOT = "/nix/store"
_SUPPORTED_SYSTEM_NAME_PREFIX = "nixos-system-heim-pc-"
_SUPPORTED_NIX_BASE32_ALPHABET = "0123456789abcdfghijklmnpqrsvwxyz"
_SUPPORTED_BUILD_EFFECT_CLASS = "build"
_SUPPORTED_BUILD_REQUEST_KIND = "heim_pc.nixos_build_request"
_SUPPORTED_BUILD_RECEIPT_KIND = "heim_pc.nixos_build_receipt"
_SUPPORTED_REQUEST_DIGEST_SEMANTICS = "canonical-validated-input-v1"
_SUPPORTED_CANONICAL_BUILD_ENTRYPOINT = (
    "nix",
    "build",
    ".#nixosConfigurations.heim-pc.config.system.build.toplevel",
    "--no-link",
    "--print-out-paths",
)
_SUPPORTED_ACTIVATION_EFFECT_CLASS = "activation"
_SUPPORTED_ACTIVATION_AUTHORITY_KIND = "heim_pc.nixos_activation_authority"
_SUPPORTED_ACTIVATION_PLAN_KIND = "heim_pc.nixos_activation_plan"
_SUPPORTED_ACTIVATION_RECEIPT_KIND = "heim_pc.nixos_activation_receipt"
_SUPPORTED_ROLLBACK_PLAN_KIND = "heim_pc.nixos_rollback_plan"
_SUPPORTED_ACTIVATION_MODES = frozenset({"test", "next-boot", "persistent"})
_SUPPORTED_ACTIVATION_EXECUTOR_AUTHORITY = "successor-task-typed-activation-only"
_SUPPORTED_MAX_AUTHORITY_LIFETIME_SECONDS = 7200
_SUPPORTED_RUNTIME_PROOF_TASK = "HEIM-PC-NIXOS-MIGRATION-V1-T004"
_SUPPORTED_BUILD_SOURCE_CONTEXT_KIND = "heim_pc.nixos_build_source_context"
_SUPPORTED_DESTRUCTIVE_EFFECTS = frozenset(
    {
        "partition-table-mutation",
        "filesystem-create-destroy",
        "luks-container-mutation",
        "luks-metadata-mutation",
        "luks-keyslot-mutation",
        "efi-key-material-mutation",
        "secure-boot-key-material-mutation",
        "firmware-flash",
    }
)
_SUPPORTED_BOOT_CRITICAL_EFFECTS = frozenset(
    {
        "kernel",
        "initrd",
        "bootloader",
        "root-unlock-config",
        "early-mount-config",
        "early-driver-module",
        "storage-layout-config",
        "luks-config",
    }
)
_SUPPORTED_NORMAL_EFFECTS = frozenset(
    {
        "package-set",
        "desktop-session",
        "user-service",
        "normal-system-service",
        "development-tooling",
        "audio-userspace",
        "network-userspace",
    }
)
_SUPPORTED_MINIMUM_MANAGED_BUILD_SCOPE = "boot-critical"


def _contract_error(message: str) -> ManagedNixContractError:
    return ManagedNixContractError(f"managed Nix contract invalid: {message}")


def _require_contract_object(
    value: Any, name: str, *, keys: frozenset[str] | None = None
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _contract_error(f"{name} must be an object")
    if keys is not None and set(value) != keys:
        missing = sorted(keys - set(value))
        extra = sorted(set(value) - keys)
        raise _contract_error(f"{name} fields mismatch: missing={missing}, extra={extra}")
    return value


def _contract_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise _contract_error(f"{name} must be a non-empty trimmed string")
    return value


def _contract_strings(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise _contract_error(f"{name} must be a non-empty string list")
    result = [_contract_string(item, f"{name} item") for item in value]
    if len(set(result)) != len(result):
        raise _contract_error(f"{name} must not contain duplicates")
    return result


def _contract_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise _contract_error(f"{name} must be boolean")
    return value


def _contract_int(value: Any, name: str) -> int:
    if type(value) is not int:
        raise _contract_error(f"{name} must be an integer")
    return value


def _load_managed_contract() -> dict[str, Any]:
    try:
        value = json.loads(_CONTRACT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise _contract_error(f"cannot read {_CONTRACT_PATH}: {exc}") from exc

    root = _require_contract_object(
        value,
        "contract",
        keys=frozenset(
            {
                "schema_version", "kind", "closure", "build", "activation",
                "effect_classifier", "rollback", "implementation_boundary",
                "execution_context",
            }
        ),
    )
    if type(root.get("schema_version")) is not int or root.get("schema_version") != CONTRACT_VERSION:
        raise _contract_error("schema_version must be integer 1")
    if root.get("kind") != _CONTRACT_KIND:
        raise _contract_error("kind is unsupported")

    closure = _require_contract_object(
        root.get("closure"),
        "closure",
        keys=frozenset(
            {"store_root", "system_name_prefix", "nix_base32_alphabet", "validation_scope"}
        ),
    )
    store_root = _contract_string(closure.get("store_root"), "closure.store_root")
    system_prefix = _contract_string(
        closure.get("system_name_prefix"), "closure.system_name_prefix"
    )
    alphabet = _contract_string(
        closure.get("nix_base32_alphabet"), "closure.nix_base32_alphabet"
    )
    if store_root != _SUPPORTED_STORE_ROOT:
        raise _contract_error("closure.store_root is unsupported for contract v1")
    if system_prefix != _SUPPORTED_SYSTEM_NAME_PREFIX:
        raise _contract_error("closure.system_name_prefix is unsupported for contract v1")
    if alphabet != _SUPPORTED_NIX_BASE32_ALPHABET:
        raise _contract_error("closure.nix_base32_alphabet is unsupported for contract v1")
    _contract_string(closure.get("validation_scope"), "closure.validation_scope")

    build = _require_contract_object(
        root.get("build"),
        "build",
        keys=frozenset(
            {
                "effect_class", "request_kind", "request_fields", "required_bindings",
                "canonical_entrypoint", "receipt_kind", "receipt_fields",
                "receipt_requires", "request_digest_semantics",
                "request_digest_excludes_derived_fields", "activation_authorized",
                "receipt_validation_establishes", "declared_capabilities_schema",
                "budget_policy",
            }
        ),
    )
    for key in (
        "effect_class", "request_kind", "receipt_kind", "request_digest_semantics",
        "receipt_validation_establishes", "declared_capabilities_schema", "budget_policy",
    ):
        _contract_string(build.get(key), f"build.{key}")
    if build.get("effect_class") != _SUPPORTED_BUILD_EFFECT_CLASS:
        raise _contract_error("build.effect_class is unsupported for contract v1")
    if build.get("request_kind") != _SUPPORTED_BUILD_REQUEST_KIND:
        raise _contract_error("build.request_kind is unsupported for contract v1")
    if build.get("receipt_kind") != _SUPPORTED_BUILD_RECEIPT_KIND:
        raise _contract_error("build.receipt_kind is unsupported for contract v1")
    if build.get("request_digest_semantics") != _SUPPORTED_REQUEST_DIGEST_SEMANTICS:
        raise _contract_error("build.request_digest_semantics is unsupported for contract v1")
    request_fields = _contract_strings(build.get("request_fields"), "build.request_fields")
    required_bindings = _contract_strings(
        build.get("required_bindings"), "build.required_bindings"
    )
    canonical_entrypoint = _contract_strings(
        build.get("canonical_entrypoint"), "build.canonical_entrypoint"
    )
    receipt_fields = _contract_strings(build.get("receipt_fields"), "build.receipt_fields")
    receipt_requires = _contract_strings(
        build.get("receipt_requires"), "build.receipt_requires"
    )
    excluded = _contract_strings(
        build.get("request_digest_excludes_derived_fields"),
        "build.request_digest_excludes_derived_fields",
    )
    if tuple(canonical_entrypoint) != _SUPPORTED_CANONICAL_BUILD_ENTRYPOINT:
        raise _contract_error("build.canonical_entrypoint is unsupported for contract v1")
    if set(request_fields) != _SUPPORTED_BUILD_REQUEST_FIELDS:
        raise _contract_error("build.request_fields contain unsupported schema drift")
    if set(receipt_fields) != _SUPPORTED_BUILD_RECEIPT_FIELDS:
        raise _contract_error("build.receipt_fields contain unsupported schema drift")
    if set(required_bindings) != set(request_fields) - {"schema_version", "kind", "effect_class"}:
        raise _contract_error("build.required_bindings must equal all semantic request fields")
    if set(receipt_requires) != set(receipt_fields):
        raise _contract_error("build.receipt_requires must describe the exact receipt shape")
    if excluded != ["effect_scope"]:
        raise _contract_error("build request digest must exclude only derived effect_scope")
    if _contract_bool(build.get("activation_authorized"), "build.activation_authorized"):
        raise _contract_error("build receipts must not authorize activation")

    activation = _require_contract_object(
        root.get("activation"),
        "activation",
        keys=frozenset(
            {
                "effect_class", "authority_kind", "authority_fields", "plan_kind",
                "plan_fields", "receipt_kind", "receipt_fields", "receipt_requires",
                "allowed_modes", "executor_authority",
                "max_authority_lifetime_seconds", "boot_critical_persistent_directly_allowed",
                "requires_exact_build_receipt", "requires_exact_system_closure",
                "requires_exact_target", "requires_independent_live_closure_readback",
                "source_reevaluation_allowed", "branch_resolution_allowed",
                "lock_resolution_allowed", "remote_input_resolution_allowed",
                "broad_root_shell_allowed", "runtime_executor_implemented_here",
                "runtime_proof_task", "requires_external_authority_sha256",
                "self_asserted_review_flag_allowed",
            }
        ),
    )
    for key in (
        "effect_class", "authority_kind", "plan_kind", "receipt_kind",
        "executor_authority", "runtime_proof_task",
    ):
        _contract_string(activation.get(key), f"activation.{key}")
    supported_activation_values = {
        "effect_class": _SUPPORTED_ACTIVATION_EFFECT_CLASS,
        "authority_kind": _SUPPORTED_ACTIVATION_AUTHORITY_KIND,
        "plan_kind": _SUPPORTED_ACTIVATION_PLAN_KIND,
        "receipt_kind": _SUPPORTED_ACTIVATION_RECEIPT_KIND,
        "executor_authority": _SUPPORTED_ACTIVATION_EXECUTOR_AUTHORITY,
        "runtime_proof_task": _SUPPORTED_RUNTIME_PROOF_TASK,
    }
    for key, expected in supported_activation_values.items():
        if activation.get(key) != expected:
            raise _contract_error(f"activation.{key} is unsupported for contract v1")
    authority_fields = _contract_strings(
        activation.get("authority_fields"), "activation.authority_fields"
    )
    plan_fields = _contract_strings(activation.get("plan_fields"), "activation.plan_fields")
    receipt_fields = _contract_strings(
        activation.get("receipt_fields"), "activation.receipt_fields"
    )
    receipt_requires = _contract_strings(
        activation.get("receipt_requires"), "activation.receipt_requires"
    )
    allowed_modes = _contract_strings(activation.get("allowed_modes"), "activation.allowed_modes")
    if set(authority_fields) != _SUPPORTED_ACTIVATION_AUTHORITY_FIELDS:
        raise _contract_error("activation.authority_fields contain unsupported schema drift")
    if set(plan_fields) != _SUPPORTED_ACTIVATION_PLAN_FIELDS:
        raise _contract_error("activation.plan_fields contain unsupported schema drift")
    if set(receipt_fields) != _SUPPORTED_ACTIVATION_RECEIPT_FIELDS:
        raise _contract_error("activation.receipt_fields contain unsupported schema drift")
    if set(receipt_requires) != set(receipt_fields):
        raise _contract_error("activation.receipt_requires must describe the exact receipt shape")
    if set(allowed_modes) != _SUPPORTED_ACTIVATION_MODES:
        raise _contract_error("activation.allowed_modes are unsupported for contract v1")
    lifetime = _contract_int(
        activation.get("max_authority_lifetime_seconds"),
        "activation.max_authority_lifetime_seconds",
    )
    if lifetime != _SUPPORTED_MAX_AUTHORITY_LIFETIME_SECONDS:
        raise _contract_error("activation.max_authority_lifetime_seconds is unsupported for contract v1")
    required_true = (
        "requires_exact_build_receipt", "requires_exact_system_closure",
        "requires_exact_target", "requires_independent_live_closure_readback",
        "requires_external_authority_sha256",
    )
    required_false = (
        "boot_critical_persistent_directly_allowed", "source_reevaluation_allowed",
        "branch_resolution_allowed", "lock_resolution_allowed",
        "remote_input_resolution_allowed", "broad_root_shell_allowed",
        "runtime_executor_implemented_here", "self_asserted_review_flag_allowed",
    )
    for key in required_true:
        if _contract_bool(activation.get(key), f"activation.{key}") is not True:
            raise _contract_error(f"activation.{key} must remain true")
    for key in required_false:
        if _contract_bool(activation.get(key), f"activation.{key}") is not False:
            raise _contract_error(f"activation.{key} must remain false")

    classifier = _require_contract_object(
        root.get("effect_classifier"),
        "effect_classifier",
        keys=frozenset(
            {
                "unknown_effect", "destructive_path", "destructive_effects",
                "boot_critical_effects", "normal_effects",
                "minimum_managed_build_scope", "boot_critical_requires_next_boot_path",
            }
        ),
    )
    if _contract_string(classifier.get("unknown_effect"), "effect_classifier.unknown_effect") != "destructive":
        raise _contract_error("unknown effects must remain destructive")
    _contract_string(classifier.get("destructive_path"), "effect_classifier.destructive_path")
    effect_sets: dict[str, frozenset[str]] = {}
    for name in ("destructive_effects", "boot_critical_effects", "normal_effects"):
        items = _contract_strings(classifier.get(name), f"effect_classifier.{name}")
        if any(item != item.casefold() for item in items):
            raise _contract_error("effect names must already be case-folded")
        effect_sets[name] = frozenset(items)
    if effect_sets["destructive_effects"] != _SUPPORTED_DESTRUCTIVE_EFFECTS:
        raise _contract_error("effect_classifier.destructive_effects are unsupported for contract v1")
    if effect_sets["boot_critical_effects"] != _SUPPORTED_BOOT_CRITICAL_EFFECTS:
        raise _contract_error("effect_classifier.boot_critical_effects are unsupported for contract v1")
    if effect_sets["normal_effects"] != _SUPPORTED_NORMAL_EFFECTS:
        raise _contract_error("effect_classifier.normal_effects are unsupported for contract v1")
    minimum_scope = _contract_string(
        classifier.get("minimum_managed_build_scope"),
        "effect_classifier.minimum_managed_build_scope",
    )
    if minimum_scope != _SUPPORTED_MINIMUM_MANAGED_BUILD_SCOPE:
        raise _contract_error(
            "effect_classifier.minimum_managed_build_scope is unsupported for contract v1"
        )
    flattened = [item for group in effect_sets.values() for item in group]
    if len(set(flattened)) != len(flattened):
        raise _contract_error("effect classes must be pairwise disjoint")
    if _contract_bool(
        classifier.get("boot_critical_requires_next_boot_path"),
        "effect_classifier.boot_critical_requires_next_boot_path",
    ) is not True:
        raise _contract_error("boot-critical effects must require the next-boot path")

    rollback = _require_contract_object(
        root.get("rollback"),
        "rollback",
        keys=frozenset(
            {
                "plan_kind", "plan_fields", "requires_prior_closure",
                "requires_recovery_path", "source_reevaluation_allowed",
            }
        ),
    )
    if _contract_string(rollback.get("plan_kind"), "rollback.plan_kind") != _SUPPORTED_ROLLBACK_PLAN_KIND:
        raise _contract_error("rollback.plan_kind is unsupported for contract v1")
    rollback_plan_fields = _contract_strings(rollback.get("plan_fields"), "rollback.plan_fields")
    if set(rollback_plan_fields) != _SUPPORTED_ROLLBACK_PLAN_FIELDS:
        raise _contract_error("rollback.plan_fields contain unsupported schema drift")
    if _contract_bool(rollback.get("requires_prior_closure"), "rollback.requires_prior_closure") is not True:
        raise _contract_error("rollback must require prior closure")
    if _contract_bool(rollback.get("requires_recovery_path"), "rollback.requires_recovery_path") is not True:
        raise _contract_error("rollback must require recovery path")
    if _contract_bool(rollback.get("source_reevaluation_allowed"), "rollback.source_reevaluation_allowed") is not False:
        raise _contract_error("rollback source reevaluation must remain false")

    boundary = _require_contract_object(
        root.get("implementation_boundary"),
        "implementation_boundary",
        keys=frozenset(
            {
                "live_activation", "service_restart", "runtime_rollback",
                "production_storage_mutation", "efi_mutation", "secure_boot_mutation",
                "firmware_mutation", "reboot",
            }
        ),
    )
    for key, item in boundary.items():
        if _contract_bool(item, f"implementation_boundary.{key}") is not False:
            raise _contract_error(f"implementation boundary {key} must remain false")

    execution = _require_contract_object(
        root.get("execution_context"),
        "execution_context",
        keys=frozenset(
            {
                "build_context_kind", "build_context_fields",
                "build_repository_must_match_observed_repository",
                "build_source_revision_must_match_observed_checkout",
                "build_receipt_must_bind_source_context_sha256",
                "activation_target_must_come_from_reserved_runtime_target",
                "current_time_must_come_from_trusted_runtime_clock",
                "activation_plan_execution_requires_fresh_authority_window",
                "caller_supplied_values_are_authority",
            }
        ),
    )
    build_context_kind = _contract_string(
        execution.get("build_context_kind"), "execution_context.build_context_kind"
    )
    if build_context_kind != _SUPPORTED_BUILD_SOURCE_CONTEXT_KIND:
        raise _contract_error("execution_context.build_context_kind is unsupported for contract v1")
    context_fields = _contract_strings(
        execution.get("build_context_fields"), "execution_context.build_context_fields"
    )
    if set(context_fields) != _SUPPORTED_BUILD_SOURCE_CONTEXT_FIELDS:
        raise _contract_error("execution_context.build_context_fields contain unsupported schema drift")
    for key in (
        "build_repository_must_match_observed_repository",
        "build_source_revision_must_match_observed_checkout",
        "build_receipt_must_bind_source_context_sha256",
        "activation_target_must_come_from_reserved_runtime_target",
        "current_time_must_come_from_trusted_runtime_clock",
        "activation_plan_execution_requires_fresh_authority_window",
    ):
        if _contract_bool(execution.get(key), f"execution_context.{key}") is not True:
            raise _contract_error(f"execution_context.{key} must remain true")
    if _contract_bool(
        execution.get("caller_supplied_values_are_authority"),
        "execution_context.caller_supplied_values_are_authority",
    ) is not False:
        raise _contract_error("caller-supplied values must not become execution authority")

    return root


try:
    MANAGED_DEPLOYMENT_CONTRACT = _load_managed_contract()
except ManagedNixContractError as exc:
    if __name__ == "__main__":
        print(f"managed-nix contract error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    raise

_BUILD_CONTRACT = MANAGED_DEPLOYMENT_CONTRACT["build"]
_ACTIVATION_CONTRACT = MANAGED_DEPLOYMENT_CONTRACT["activation"]
_ROLLBACK_CONTRACT = MANAGED_DEPLOYMENT_CONTRACT["rollback"]
_EFFECT_CONTRACT = MANAGED_DEPLOYMENT_CONTRACT["effect_classifier"]
_CLOSURE_CONTRACT = MANAGED_DEPLOYMENT_CONTRACT["closure"]
_EXECUTION_CONTEXT_CONTRACT = MANAGED_DEPLOYMENT_CONTRACT["execution_context"]

BUILD_REQUEST_KIND = str(_BUILD_CONTRACT["request_kind"])
BUILD_RECEIPT_KIND = str(_BUILD_CONTRACT["receipt_kind"])
ACTIVATION_AUTHORITY_KIND = str(_ACTIVATION_CONTRACT["authority_kind"])
ACTIVATION_PLAN_KIND = str(_ACTIVATION_CONTRACT["plan_kind"])
ACTIVATION_RECEIPT_KIND = str(_ACTIVATION_CONTRACT["receipt_kind"])
ROLLBACK_PLAN_KIND = str(_ROLLBACK_CONTRACT["plan_kind"])
BUILD_SOURCE_CONTEXT_KIND = str(_EXECUTION_CONTEXT_CONTRACT["build_context_kind"])

DESTRUCTIVE_EFFECTS = frozenset(_EFFECT_CONTRACT["destructive_effects"])
BOOT_CRITICAL_EFFECTS = frozenset(_EFFECT_CONTRACT["boot_critical_effects"])
NORMAL_EFFECTS = frozenset(_EFFECT_CONTRACT["normal_effects"])
MINIMUM_MANAGED_BUILD_SCOPE = str(_EFFECT_CONTRACT["minimum_managed_build_scope"])
ALLOWED_ACTIVATION_MODES = frozenset(_ACTIVATION_CONTRACT["allowed_modes"])
MAX_AUTHORITY_LIFETIME_SECONDS = int(_ACTIVATION_CONTRACT["max_authority_lifetime_seconds"])
ACTIVATION_EXECUTOR_AUTHORITY = str(_ACTIVATION_CONTRACT["executor_authority"])
CANONICAL_BUILD_ENTRYPOINT = tuple(_BUILD_CONTRACT["canonical_entrypoint"])

_BUILD_REQUEST_KEYS = frozenset(_BUILD_CONTRACT["request_fields"])
_BUILD_RECEIPT_KEYS = frozenset(_BUILD_CONTRACT["receipt_fields"])
_ACTIVATION_AUTHORITY_KEYS = frozenset(_ACTIVATION_CONTRACT["authority_fields"])
_ACTIVATION_PLAN_KEYS = frozenset(_ACTIVATION_CONTRACT["plan_fields"])
_ACTIVATION_RECEIPT_KEYS = frozenset(_ACTIVATION_CONTRACT["receipt_fields"])
_ROLLBACK_PLAN_KEYS = frozenset(_ROLLBACK_CONTRACT["plan_fields"])
_BUILD_SOURCE_CONTEXT_KEYS = frozenset(_EXECUTION_CONTEXT_CONTRACT["build_context_fields"])

_HEX_RE = re.compile(r"^[0-9a-f]+$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_NIX_BASE32_ALPHABET = str(_CLOSURE_CONTRACT["nix_base32_alphabet"])
_STORE_ROOT = PurePosixPath(str(_CLOSURE_CONTRACT["store_root"]))
_SYSTEM_NAME_PREFIX = str(_CLOSURE_CONTRACT["system_name_prefix"])
_STORE_SYSTEM_RE = re.compile(
    rf"^([{re.escape(_NIX_BASE32_ALPHABET)}]{{32}})-"
    rf"{re.escape(_SYSTEM_NAME_PREFIX)}([A-Za-z0-9+._?=-]+)$"
)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _copy_json(value: Any, name: str) -> Any:
    try:
        return json.loads(canonical_json(value))
    except (TypeError, ValueError) as exc:
        raise ManagedNixError(f"{name} must be canonical JSON data") from exc


def _require_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManagedNixError(f"{name} must be an object")
    return _copy_json(value, name)


def _require_exact_keys(value: Mapping[str, Any], expected: frozenset[str], name: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ManagedNixError(f"{name} fields mismatch: missing={missing}, extra={extra}")


def _require_contract_version(value: Any, name: str = "schema_version") -> int:
    if type(value) is not int or value != CONTRACT_VERSION:
        raise ManagedNixError(f"{name} must be integer {CONTRACT_VERSION}")
    return CONTRACT_VERSION


def _require_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ManagedNixError(f"{name} must be a non-empty single-line string")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ManagedNixError(f"{name} must not contain control characters")
    return value.strip()


def _require_canonical_string(value: Any, name: str) -> str:
    text = _require_string(value, name)
    if value != text:
        raise ManagedNixError(f"{name} must already be canonical without surrounding whitespace")
    return text


def _require_sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or not _HEX_RE.fullmatch(value):
        raise ManagedNixError(f"{name} must be exactly 64 lowercase hexadecimal characters")
    return value


def _require_revision(value: Any, name: str = "source_revision") -> str:
    if not isinstance(value, str) or len(value) != 40 or not _HEX_RE.fullmatch(value):
        raise ManagedNixError(f"{name} must be an immutable 40-character Git object id")
    return value


def _require_repository(value: Any) -> str:
    repository = _require_canonical_string(value, "repository")
    if not _REPOSITORY_RE.fullmatch(repository) or repository.endswith(".git"):
        raise ManagedNixError("repository must be a canonical owner/repository identity")
    owner, name = repository.split("/", 1)
    if owner in {".", ".."} or name in {".", ".."}:
        raise ManagedNixError("repository must be a canonical owner/repository identity")
    return repository


def _require_closure(value: Any, name: str = "system_closure") -> str:
    text = _require_canonical_string(value, name)
    path = PurePosixPath(text)
    if text != path.as_posix() or path.parent != _STORE_ROOT:
        raise ManagedNixError(f"{name} must be a canonical immutable NixOS /nix/store path")
    if _STORE_SYSTEM_RE.fullmatch(path.name) is None:
        raise ManagedNixError(
            f"{name} must identify a canonical immutable Heim-PC NixOS system closure"
        )
    return text


def _parse_time(value: Any, name: str) -> datetime:
    text = _require_canonical_string(value, name)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ManagedNixError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ManagedNixError(f"{name} must carry a timezone")
    return parsed.astimezone(timezone.utc)


def _validate_authority_window(issued_at: Any, expires_at: Any) -> tuple[str, str, datetime, datetime]:
    issued_text = _require_canonical_string(issued_at, "issued_at")
    expires_text = _require_canonical_string(expires_at, "expires_at")
    issued = _parse_time(issued_text, "issued_at")
    expires = _parse_time(expires_text, "expires_at")
    if expires <= issued:
        raise ManagedNixError("activation authority expires_at must be after issued_at")
    if (expires - issued).total_seconds() > MAX_AUTHORITY_LIFETIME_SECONDS:
        raise ManagedNixError("activation authority lifetime exceeds the contract maximum")
    return issued_text, expires_text, issued, expires


def _require_control_release(value: Any) -> dict[str, str]:
    control = _require_object(value, "control_release_set")
    if set(control) != {"id", "digest"}:
        raise ManagedNixError("control_release_set must contain exactly id and digest")
    return {
        "id": _require_canonical_string(control["id"], "control_release_set.id"),
        "digest": _require_sha256(control["digest"], "control_release_set.digest"),
    }


def _require_budget(value: Any, name: str) -> dict[str, int]:
    budget = _require_object(value, name)
    if set(budget) != {"warning", "hard"}:
        raise ManagedNixError(f"{name} must contain exactly warning and hard")
    warning, hard = budget["warning"], budget["hard"]
    if type(warning) is not int or type(hard) is not int or warning < 0 or hard <= warning:
        raise ManagedNixError(
            f"{name} must contain non-negative integers with warning strictly below hard"
        )
    return {"warning": warning, "hard": hard}


def _require_budgets(value: Any, name: str = "budgets") -> dict[str, dict[str, int]]:
    budgets = _require_object(value, name)
    if set(budgets) != {"store_bytes", "cache_bytes", "runtime_seconds"}:
        raise ManagedNixError(f"{name} must define store_bytes, cache_bytes and runtime_seconds")
    return {
        key: _require_budget(budgets[key], f"{name}.{key}")
        for key in ("store_bytes", "cache_bytes", "runtime_seconds")
    }


def _normalize_effects(possible_effects: Sequence[str]) -> list[str]:
    if not isinstance(possible_effects, Sequence) or isinstance(possible_effects, (str, bytes)):
        raise ManagedNixError("possible_effects must be a sequence")
    if not possible_effects:
        raise ManagedNixError("possible_effects must not be empty")
    normalized = sorted(
        {_require_string(value, "possible_effect").casefold() for value in possible_effects}
    )
    if len(normalized) != len(possible_effects):
        raise ManagedNixError("possible_effects must be unique after canonicalization")
    return normalized


def _classify_normalized_effects(normalized: Sequence[str]) -> str:
    effects = set(normalized)
    if effects & DESTRUCTIVE_EFFECTS:
        return "destructive"
    known = DESTRUCTIVE_EFFECTS | BOOT_CRITICAL_EFFECTS | NORMAL_EFFECTS
    if effects - known:
        return "destructive"
    if effects & BOOT_CRITICAL_EFFECTS:
        return "boot-critical"
    return "normal"


def classify_effect(possible_effects: Sequence[str]) -> str:
    """Classify the declared effect taxonomy without granting build authority."""
    return _classify_normalized_effects(_normalize_effects(possible_effects))


def _managed_build_effect_scope(normalized_effects: Sequence[str]) -> str:
    """Apply the conservative v1 floor to caller-declared managed Nix effects."""
    classified = _classify_normalized_effects(normalized_effects)
    if classified == "normal" and MINIMUM_MANAGED_BUILD_SCOPE == "boot-critical":
        return "boot-critical"
    return classified


def _validate_build_entrypoint(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ManagedNixError("entrypoint must be an argv list")
    normalized = [_require_canonical_string(item, "entrypoint argv") for item in value]
    if tuple(normalized) != CANONICAL_BUILD_ENTRYPOINT:
        raise ManagedNixError("entrypoint must equal the canonical pure NixOS toplevel build adapter")
    return normalized


def validate_build_request(request: Mapping[str, Any]) -> dict[str, Any]:
    """Validate immutable build inputs without invoking Nix or changing runtime state."""
    if not isinstance(request, Mapping):
        raise ManagedNixError("build request must be an object")
    _require_exact_keys(request, _BUILD_REQUEST_KEYS, "build request")
    _require_contract_version(request.get("schema_version"))
    if request.get("kind") != BUILD_REQUEST_KIND:
        raise ManagedNixError("unsupported managed NixOS build request")
    if request.get("effect_class") != _BUILD_CONTRACT["effect_class"]:
        raise ManagedNixError("build request effect_class must be build")

    repository = _require_repository(request.get("repository"))
    source_revision = _require_revision(request.get("source_revision"))
    control = _require_control_release(request.get("control_release_set"))
    nix_inputs = _require_object(request.get("nix_inputs"), "nix_inputs")
    if not nix_inputs:
        raise ManagedNixError("nix_inputs must not be empty")
    normalized_inputs: dict[str, str] = {}
    for raw_name, digest in nix_inputs.items():
        name = _require_canonical_string(raw_name, "nix input name")
        normalized_inputs[name] = _require_sha256(digest, f"nix_inputs.{name}")
    budgets = _require_budgets(request.get("budgets"))
    leases = request.get("leases")
    if not isinstance(leases, list) or not leases:
        raise ManagedNixError("leases must be a non-empty list")
    normalized_leases = sorted(_require_canonical_string(item, "lease") for item in leases)
    if len(set(normalized_leases)) != len(normalized_leases):
        raise ManagedNixError("leases must be unique")
    if len({item.casefold() for item in normalized_leases}) != len(normalized_leases):
        raise ManagedNixError("leases must be unique after case-folding")
    possible_effects = request.get("possible_effects")
    if not isinstance(possible_effects, list):
        raise ManagedNixError("possible_effects must be a list")
    normalized_effects = _normalize_effects(possible_effects)
    effect_scope = _managed_build_effect_scope(normalized_effects)
    if effect_scope == "destructive":
        raise ManagedNixError("destructive or ambiguous effects require the separate destructive plan")
    entrypoint = _validate_build_entrypoint(request.get("entrypoint"))
    return {
        "schema_version": CONTRACT_VERSION,
        "kind": BUILD_REQUEST_KIND,
        "effect_class": str(_BUILD_CONTRACT["effect_class"]),
        "repository": repository,
        "source_revision": source_revision,
        "control_release_set": control,
        "nix_inputs": dict(sorted(normalized_inputs.items())),
        "budgets": budgets,
        "leases": normalized_leases,
        "possible_effects": normalized_effects,
        "effect_scope": effect_scope,
        "entrypoint": entrypoint,
    }


def _build_request_payload_from_normalized(normalized: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: _copy_json(normalized[key], f"build_request.{key}")
        for key in sorted(_BUILD_REQUEST_KEYS)
    }


def canonical_build_request_payload(request: Mapping[str, Any]) -> dict[str, Any]:
    """Canonical caller-controlled digest payload for ``build_request_sha256``."""
    return _build_request_payload_from_normalized(validate_build_request(request))


def validate_build_source_context(
    request: Mapping[str, Any],
    *,
    observed_repository: str,
    observed_source_revision: str,
) -> dict[str, Any]:
    """Bind a request to source identity observed by a trusted build successor."""
    normalized = validate_build_request(request)
    repository = _require_repository(observed_repository)
    source_revision = _require_revision(observed_source_revision, "observed_source_revision")
    if repository != normalized["repository"]:
        raise ManagedNixError("observed repository does not match build request")
    if source_revision != normalized["source_revision"]:
        raise ManagedNixError("observed source revision does not match build request")
    result = {
        "schema_version": CONTRACT_VERSION,
        "kind": BUILD_SOURCE_CONTEXT_KIND,
        "repository": repository,
        "source_revision": source_revision,
        "build_request_sha256": sha256_json(_build_request_payload_from_normalized(normalized)),
    }
    _require_exact_keys(result, _BUILD_SOURCE_CONTEXT_KEYS, "build source context")
    return result


def make_build_receipt(
    request: Mapping[str, Any],
    *,
    observed_repository: str,
    observed_source_revision: str,
    system_closure: str,
    declared_capabilities: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind a successful managed build to observed source, inputs and exact closure."""
    normalized = validate_build_request(request)
    request_payload = _build_request_payload_from_normalized(normalized)
    source_context = validate_build_source_context(
        request,
        observed_repository=observed_repository,
        observed_source_revision=observed_source_revision,
    )
    closure = _require_closure(system_closure)
    capabilities = _require_object(dict(declared_capabilities), "declared_capabilities")
    if not capabilities:
        raise ManagedNixError("declared_capabilities must not be empty")
    return {
        "schema_version": CONTRACT_VERSION,
        "kind": BUILD_RECEIPT_KIND,
        "effect_class": str(_BUILD_CONTRACT["effect_class"]),
        "result": "succeeded",
        "repository": normalized["repository"],
        "source_revision": normalized["source_revision"],
        "control_release_set": normalized["control_release_set"],
        "nix_inputs_sha256": sha256_json(normalized["nix_inputs"]),
        "budgets": normalized["budgets"],
        "leases_sha256": sha256_json(normalized["leases"]),
        "possible_effects": normalized["possible_effects"],
        "effect_scope": normalized["effect_scope"],
        "system_closure": closure,
        "declared_capabilities": capabilities,
        "build_request_sha256": sha256_json(request_payload),
        "build_source_context_sha256": sha256_json(source_context),
        "activation_authorized": False,
    }


def validate_build_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Validate receipt shape/internal consistency, not producer authenticity."""
    if not isinstance(receipt, Mapping):
        raise ManagedNixError("build receipt must be an object")
    _require_exact_keys(receipt, _BUILD_RECEIPT_KEYS, "build receipt")
    _require_contract_version(receipt.get("schema_version"))
    if receipt.get("kind") != BUILD_RECEIPT_KIND:
        raise ManagedNixError("unsupported managed NixOS build receipt")
    if receipt.get("effect_class") != _BUILD_CONTRACT["effect_class"] or receipt.get("result") != "succeeded":
        raise ManagedNixError("build receipt is not a successful build-effect result")
    if receipt.get("activation_authorized") is not False:
        raise ManagedNixError("build receipt must not itself authorize activation")

    repository = _require_repository(receipt.get("repository"))
    source_revision = _require_revision(receipt.get("source_revision"))
    control = _require_control_release(receipt.get("control_release_set"))
    nix_inputs_sha256 = _require_sha256(receipt.get("nix_inputs_sha256"), "nix_inputs_sha256")
    budgets = _require_budgets(receipt.get("budgets"), "build receipt budgets")
    leases_sha256 = _require_sha256(receipt.get("leases_sha256"), "leases_sha256")
    request_sha256 = _require_sha256(receipt.get("build_request_sha256"), "build_request_sha256")
    source_context_sha256 = _require_sha256(
        receipt.get("build_source_context_sha256"), "build_source_context_sha256"
    )
    closure = _require_closure(receipt.get("system_closure"))
    possible_effects = receipt.get("possible_effects")
    if not isinstance(possible_effects, list):
        raise ManagedNixError("build receipt possible_effects must be a list")
    normalized_effects = _normalize_effects(possible_effects)
    recomputed_scope = _managed_build_effect_scope(normalized_effects)
    if recomputed_scope == "destructive":
        raise ManagedNixError("build receipt possible_effects are destructive or ambiguous")
    if receipt.get("effect_scope") != recomputed_scope:
        raise ManagedNixError("build receipt effect_scope does not match possible_effects")
    capabilities = _require_object(receipt.get("declared_capabilities"), "declared_capabilities")
    if not capabilities:
        raise ManagedNixError("build receipt declared_capabilities are missing")
    return {
        "schema_version": CONTRACT_VERSION,
        "kind": BUILD_RECEIPT_KIND,
        "effect_class": str(_BUILD_CONTRACT["effect_class"]),
        "result": "succeeded",
        "repository": repository,
        "source_revision": source_revision,
        "control_release_set": control,
        "nix_inputs_sha256": nix_inputs_sha256,
        "budgets": budgets,
        "leases_sha256": leases_sha256,
        "possible_effects": normalized_effects,
        "effect_scope": recomputed_scope,
        "system_closure": closure,
        "declared_capabilities": capabilities,
        "build_request_sha256": request_sha256,
        "build_source_context_sha256": source_context_sha256,
        "activation_authorized": False,
    }


def validate_activation_authority(
    build_receipt: Mapping[str, Any],
    authority: Mapping[str, Any],
    *,
    expected_authority_sha256: str,
    expected_target: str,
    now: str,
) -> dict[str, Any]:
    """Validate fresh externally bound activation authority and derive an exact plan."""
    receipt = validate_build_receipt(build_receipt)
    if not isinstance(authority, Mapping):
        raise ManagedNixError("activation authority must be an object")
    _require_exact_keys(authority, _ACTIVATION_AUTHORITY_KEYS, "activation authority")
    _require_contract_version(authority.get("schema_version"))
    if authority.get("kind") != ACTIVATION_AUTHORITY_KIND:
        raise ManagedNixError("unsupported activation authority")
    if authority.get("effect_class") != _ACTIVATION_CONTRACT["effect_class"]:
        raise ManagedNixError("activation authority effect_class must be activation")
    mode = authority.get("mode")
    if mode not in ALLOWED_ACTIVATION_MODES:
        raise ManagedNixError("activation mode is invalid")
    if receipt["effect_scope"] == "boot-critical" and mode == "persistent":
        raise ManagedNixError("boot-critical build must use test/next-boot before persistent activation")

    source_revision = _require_revision(authority.get("source_revision"))
    closure = _require_closure(authority.get("system_closure"))
    target = _require_canonical_string(authority.get("target"), "target")
    expected_target_value = _require_canonical_string(expected_target, "expected_target")
    prior_closure = _require_closure(authority.get("prior_closure"), "prior_closure")
    recovery_path = _require_canonical_string(authority.get("recovery_path"), "recovery_path")
    build_digest = _require_sha256(authority.get("build_receipt_sha256"), "build_receipt_sha256")
    issued_text, expires_text, issued, expires = _validate_authority_window(
        authority.get("issued_at"), authority.get("expires_at")
    )
    current = _parse_time(now, "now")
    if current < issued:
        raise ManagedNixError("activation authority is not yet valid")
    if current >= expires:
        raise ManagedNixError("activation authority is expired")

    normalized_authority = {
        "schema_version": CONTRACT_VERSION,
        "kind": ACTIVATION_AUTHORITY_KIND,
        "effect_class": str(_ACTIVATION_CONTRACT["effect_class"]),
        "mode": mode,
        "source_revision": source_revision,
        "system_closure": closure,
        "target": target,
        "build_receipt_sha256": build_digest,
        "prior_closure": prior_closure,
        "recovery_path": recovery_path,
        "issued_at": issued_text,
        "expires_at": expires_text,
    }
    authority_digest = _require_sha256(expected_authority_sha256, "expected_authority_sha256")
    if sha256_json(normalized_authority) != authority_digest:
        raise ManagedNixError("activation authority does not match externally bound review authority")
    if source_revision != receipt["source_revision"]:
        raise ManagedNixError("activation source revision does not match build receipt")
    if closure != receipt["system_closure"]:
        raise ManagedNixError("activation closure does not match build receipt")
    if target != expected_target_value:
        raise ManagedNixError("activation target does not match reserved target")
    if build_digest != sha256_json(receipt):
        raise ManagedNixError("activation authority is not bound to this build receipt")
    if prior_closure == closure:
        raise ManagedNixError("prior_closure must identify an independent rollback generation")

    return {
        "schema_version": CONTRACT_VERSION,
        "kind": ACTIVATION_PLAN_KIND,
        "effect_class": str(_ACTIVATION_CONTRACT["effect_class"]),
        "mode": mode,
        "target": target,
        "source_revision": source_revision,
        "system_closure": closure,
        "build_receipt_sha256": build_digest,
        "prior_closure": prior_closure,
        "recovery_path": recovery_path,
        "authority_sha256": authority_digest,
        "issued_at": issued_text,
        "expires_at": expires_text,
        "executor_authority": ACTIVATION_EXECUTOR_AUTHORITY,
        "source_reevaluation_allowed": False,
        "broad_root_shell_allowed": False,
    }


def validate_activation_plan(activation_plan: Mapping[str, Any]) -> dict[str, Any]:
    """Validate activation-plan shape/semantics; this alone is not execution authority."""
    if not isinstance(activation_plan, Mapping):
        raise ManagedNixError("activation plan must be an object")
    _require_exact_keys(activation_plan, _ACTIVATION_PLAN_KEYS, "activation plan")
    _require_contract_version(activation_plan.get("schema_version"))
    if activation_plan.get("kind") != ACTIVATION_PLAN_KIND:
        raise ManagedNixError("unsupported activation plan")
    if activation_plan.get("effect_class") != _ACTIVATION_CONTRACT["effect_class"]:
        raise ManagedNixError("activation plan effect_class must be activation")
    mode = activation_plan.get("mode")
    if mode not in ALLOWED_ACTIVATION_MODES:
        raise ManagedNixError("activation plan mode is invalid")
    target = _require_canonical_string(activation_plan.get("target"), "target")
    source_revision = _require_revision(activation_plan.get("source_revision"))
    closure = _require_closure(activation_plan.get("system_closure"))
    build_digest = _require_sha256(
        activation_plan.get("build_receipt_sha256"), "build_receipt_sha256"
    )
    prior_closure = _require_closure(activation_plan.get("prior_closure"), "prior_closure")
    recovery_path = _require_canonical_string(activation_plan.get("recovery_path"), "recovery_path")
    authority_digest = _require_sha256(activation_plan.get("authority_sha256"), "authority_sha256")
    issued_text, expires_text, _, _ = _validate_authority_window(
        activation_plan.get("issued_at"), activation_plan.get("expires_at")
    )
    if activation_plan.get("executor_authority") != ACTIVATION_EXECUTOR_AUTHORITY:
        raise ManagedNixError("activation plan executor authority is invalid")
    if activation_plan.get("source_reevaluation_allowed") is not False:
        raise ManagedNixError("activation plan must forbid source reevaluation")
    if activation_plan.get("broad_root_shell_allowed") is not False:
        raise ManagedNixError("activation plan must forbid broad root shell access")
    if prior_closure == closure:
        raise ManagedNixError("activation plan prior_closure must differ from system_closure")
    return {
        "schema_version": CONTRACT_VERSION,
        "kind": ACTIVATION_PLAN_KIND,
        "effect_class": str(_ACTIVATION_CONTRACT["effect_class"]),
        "mode": mode,
        "target": target,
        "source_revision": source_revision,
        "system_closure": closure,
        "build_receipt_sha256": build_digest,
        "prior_closure": prior_closure,
        "recovery_path": recovery_path,
        "authority_sha256": authority_digest,
        "issued_at": issued_text,
        "expires_at": expires_text,
        "executor_authority": ACTIVATION_EXECUTOR_AUTHORITY,
        "source_reevaluation_allowed": False,
        "broad_root_shell_allowed": False,
    }


def authorize_activation_plan_execution(
    build_receipt: Mapping[str, Any],
    authority: Mapping[str, Any],
    activation_plan: Mapping[str, Any],
    *,
    expected_authority_sha256: str,
    expected_target: str,
    now: str,
) -> dict[str, Any]:
    """Fresh pre-effect gate: rebind plan to receipt, external authority, target and clock."""
    plan = validate_activation_plan(activation_plan)
    freshly_derived = validate_activation_authority(
        build_receipt,
        authority,
        expected_authority_sha256=expected_authority_sha256,
        expected_target=expected_target,
        now=now,
    )
    if plan != freshly_derived:
        raise ManagedNixError("activation plan does not match fresh externally bound authority")
    return plan


def make_activation_receipt(
    activation_plan: Mapping[str, Any],
    *,
    live_closure: str,
    readback_evidence_sha256: str,
) -> dict[str, Any]:
    """Bind independent post-effect readback to an exact structurally valid plan."""
    plan = validate_activation_plan(activation_plan)
    approved = plan["system_closure"]
    live = _require_closure(live_closure, "live_closure")
    if live != approved:
        raise ManagedNixError("live closure does not match the approved activation closure")
    evidence = _require_sha256(readback_evidence_sha256, "readback_evidence_sha256")
    result = {
        "schema_version": CONTRACT_VERSION,
        "kind": ACTIVATION_RECEIPT_KIND,
        "effect_class": str(_ACTIVATION_CONTRACT["effect_class"]),
        "result": "succeeded",
        "mode": plan["mode"],
        "target": plan["target"],
        "source_revision": plan["source_revision"],
        "system_closure": approved,
        "live_closure": live,
        "build_receipt_sha256": plan["build_receipt_sha256"],
        "authority_sha256": plan["authority_sha256"],
        "readback_evidence_sha256": evidence,
        "prior_closure": plan["prior_closure"],
        "recovery_path": plan["recovery_path"],
        "source_reevaluation_used": False,
    }
    return validate_activation_receipt(result)


def validate_activation_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Validate exact post-effect receipt shape and independent live-readback binding."""
    if not isinstance(receipt, Mapping):
        raise ManagedNixError("activation receipt must be an object")
    _require_exact_keys(receipt, _ACTIVATION_RECEIPT_KEYS, "activation receipt")
    _require_contract_version(receipt.get("schema_version"))
    if receipt.get("kind") != ACTIVATION_RECEIPT_KIND:
        raise ManagedNixError("unsupported activation receipt")
    if receipt.get("effect_class") != _ACTIVATION_CONTRACT["effect_class"] or receipt.get("result") != "succeeded":
        raise ManagedNixError("activation receipt is not a successful activation result")
    mode = receipt.get("mode")
    if mode not in ALLOWED_ACTIVATION_MODES:
        raise ManagedNixError("activation receipt mode is invalid")
    target = _require_canonical_string(receipt.get("target"), "target")
    source_revision = _require_revision(receipt.get("source_revision"))
    system_closure = _require_closure(receipt.get("system_closure"))
    live_closure = _require_closure(receipt.get("live_closure"), "live_closure")
    if live_closure != system_closure:
        raise ManagedNixError("activation receipt live closure does not match system closure")
    prior_closure = _require_closure(receipt.get("prior_closure"), "prior_closure")
    if prior_closure == system_closure:
        raise ManagedNixError("activation receipt prior_closure must differ from system_closure")
    result = {
        "schema_version": CONTRACT_VERSION,
        "kind": ACTIVATION_RECEIPT_KIND,
        "effect_class": str(_ACTIVATION_CONTRACT["effect_class"]),
        "result": "succeeded",
        "mode": mode,
        "target": target,
        "source_revision": source_revision,
        "system_closure": system_closure,
        "live_closure": live_closure,
        "build_receipt_sha256": _require_sha256(receipt.get("build_receipt_sha256"), "build_receipt_sha256"),
        "authority_sha256": _require_sha256(receipt.get("authority_sha256"), "authority_sha256"),
        "readback_evidence_sha256": _require_sha256(receipt.get("readback_evidence_sha256"), "readback_evidence_sha256"),
        "prior_closure": prior_closure,
        "recovery_path": _require_canonical_string(receipt.get("recovery_path"), "recovery_path"),
        "source_reevaluation_used": False,
    }
    if receipt.get("source_reevaluation_used") is not False:
        raise ManagedNixError("activation receipt must prove source reevaluation was not used")
    return result


def validate_rollback_plan(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the exact no-reevaluation rollback document defined by contract v1."""
    if not isinstance(value, Mapping):
        raise ManagedNixError("rollback plan must be an object")
    _require_exact_keys(value, _ROLLBACK_PLAN_KEYS, "rollback plan")
    _require_contract_version(value.get("schema_version"))
    if value.get("kind") != ROLLBACK_PLAN_KIND:
        raise ManagedNixError("unsupported rollback plan")
    if value.get("source_reevaluation_allowed") is not False:
        raise ManagedNixError("rollback plan must forbid source reevaluation")
    return {
        "schema_version": CONTRACT_VERSION,
        "kind": ROLLBACK_PLAN_KIND,
        "target": _require_canonical_string(value.get("target"), "target"),
        "system_closure": _require_closure(value.get("system_closure")),
        "recovery_path": _require_canonical_string(value.get("recovery_path"), "recovery_path"),
        "source_reevaluation_allowed": False,
    }


def rollback_plan(activation_plan: Mapping[str, Any]) -> dict[str, Any]:
    plan = validate_activation_plan(activation_plan)
    return validate_rollback_plan({
        "kind": ROLLBACK_PLAN_KIND,
        "schema_version": CONTRACT_VERSION,
        "target": plan["target"],
        "system_closure": plan["prior_closure"],
        "recovery_path": plan["recovery_path"],
        "source_reevaluation_allowed": False,
    })


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManagedNixError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ManagedNixError(f"JSON input {path} must be an object")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validation-only managed Nix contract CLI. Pretty JSON is for humans; "
            "use --canonical-json when exact canonical output bytes are required."
        )
    )
    parser.add_argument(
        "--canonical-json",
        action="store_true",
        help="emit compact sorted canonical JSON instead of pretty-printed JSON",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("validate-build-request")
    check.add_argument("request", type=Path)
    source = sub.add_parser("validate-build-source-context")
    source.add_argument("request", type=Path)
    source.add_argument("--observed-repository", required=True)
    source.add_argument("--observed-source-revision", required=True)
    receipt = sub.add_parser("validate-build-receipt")
    receipt.add_argument("receipt", type=Path)
    activation = sub.add_parser("validate-activation")
    activation.add_argument("build_receipt", type=Path)
    activation.add_argument("authority", type=Path)
    activation.add_argument("--expected-authority-sha256", required=True)
    activation.add_argument("--expected-target", required=True)
    activation.add_argument("--now", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-build-request":
            result = validate_build_request(_load(args.request))
        elif args.command == "validate-build-source-context":
            result = validate_build_source_context(
                _load(args.request),
                observed_repository=args.observed_repository,
                observed_source_revision=args.observed_source_revision,
            )
        elif args.command == "validate-build-receipt":
            result = validate_build_receipt(_load(args.receipt))
        else:
            result = validate_activation_authority(
                _load(args.build_receipt),
                _load(args.authority),
                expected_authority_sha256=args.expected_authority_sha256,
                expected_target=args.expected_target,
                now=args.now,
            )
    except ManagedNixError as exc:
        print(f"managed-nix validation error: {exc}", file=sys.stderr)
        return 1
    if args.canonical_json:
        sys.stdout.buffer.write(canonical_json(result) + b"\n")
    else:
        print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
