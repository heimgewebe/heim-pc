#!/usr/bin/env python3
"""Effect-free managed NixOS build/activation contracts for the Heim-PC.

This module validates immutable build inputs and receipt-bound activation authority.
It intentionally contains no runtime NixOS activation executor. Realization/activation
is delegated to a separately authorized successor (migration T004/T011).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

BUILD_REQUEST_KIND = "heim_pc.nixos_build_request"
BUILD_RECEIPT_KIND = "heim_pc.nixos_build_receipt"
ACTIVATION_AUTHORITY_KIND = "heim_pc.nixos_activation_authority"
ACTIVATION_PLAN_KIND = "heim_pc.nixos_activation_plan"
ACTIVATION_RECEIPT_KIND = "heim_pc.nixos_activation_receipt"
CONTRACT_VERSION = 1

_HEX_RE = re.compile(r"^[0-9a-f]+$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_NIX_BASE32_RE = re.compile(r"^[0123456789abcdfghijklmnpqrsvwxyz]{32}$")
_STORE_SYSTEM_RE = re.compile(
    r"^([0123456789abcdfghijklmnpqrsvwxyz]{32})-nixos-system-[^/\x00\r\n]+$"
)

DESTRUCTIVE_EFFECTS = frozenset(
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
BOOT_CRITICAL_EFFECTS = frozenset(
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
NORMAL_EFFECTS = frozenset(
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
ALLOWED_ACTIVATION_MODES = frozenset({"test", "next-boot", "persistent"})
CANONICAL_BUILD_ENTRYPOINT = (
    "nix",
    "build",
    ".#nixosConfigurations.heim-pc.config.system.build.toplevel",
    "--no-link",
    "--print-out-paths",
)

_BUILD_REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "effect_class",
        "repository",
        "source_revision",
        "control_release_set",
        "nix_inputs",
        "budgets",
        "leases",
        "possible_effects",
        "entrypoint",
    }
)
_BUILD_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "effect_class",
        "result",
        "repository",
        "source_revision",
        "control_release_set",
        "nix_inputs_sha256",
        "budgets",
        "leases_sha256",
        "effect_scope",
        "system_closure",
        "declared_capabilities",
        "build_request_sha256",
        "activation_authorized",
    }
)
_ACTIVATION_AUTHORITY_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "effect_class",
        "mode",
        "source_revision",
        "system_closure",
        "target",
        "build_receipt_sha256",
        "prior_closure",
        "recovery_path",
        "expires_at",
    }
)


class ManagedNixError(ValueError):
    """Raised before any runtime effect when a managed Nix binding is invalid."""


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


def _require_string(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or "\x00" in value
        or "\n" in value
        or "\r" in value
    ):
        raise ManagedNixError(f"{name} must be a non-empty single-line string")
    return value.strip()


def _require_sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or not _HEX_RE.fullmatch(value):
        raise ManagedNixError(f"{name} must be exactly 64 lowercase hexadecimal characters")
    return value


def _require_revision(value: Any, name: str = "source_revision") -> str:
    if (
        not isinstance(value, str)
        or len(value) not in {40, 64}
        or not _HEX_RE.fullmatch(value)
    ):
        raise ManagedNixError(f"{name} must be an immutable 40/64-character Git object id")
    return value


def _require_repository(value: Any) -> str:
    repository = _require_string(value, "repository")
    if not _REPOSITORY_RE.fullmatch(repository) or repository.endswith(".git"):
        raise ManagedNixError("repository must be a canonical owner/repository identity")
    owner, name = repository.split("/", 1)
    if owner in {".", ".."} or name in {".", ".."}:
        raise ManagedNixError("repository must be a canonical owner/repository identity")
    return repository


def _require_closure(value: Any, name: str = "system_closure") -> str:
    text = _require_string(value, name)
    path = Path(text)
    if text != str(path) or path.parent != Path("/nix/store"):
        raise ManagedNixError(f"{name} must be a canonical immutable NixOS /nix/store path")
    match = _STORE_SYSTEM_RE.fullmatch(path.name)
    if match is None or _NIX_BASE32_RE.fullmatch(match.group(1)) is None:
        raise ManagedNixError(f"{name} must identify a canonical immutable NixOS system closure")
    return text


def _parse_time(value: Any, name: str) -> datetime:
    text = _require_string(value, name)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ManagedNixError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ManagedNixError(f"{name} must carry a timezone")
    return parsed.astimezone(timezone.utc)


def _require_control_release(value: Any) -> dict[str, str]:
    control = _require_object(value, "control_release_set")
    if set(control) != {"id", "digest"}:
        raise ManagedNixError("control_release_set must contain exactly id and digest")
    return {
        "id": _require_string(control["id"], "control_release_set.id"),
        "digest": _require_sha256(control["digest"], "control_release_set.digest"),
    }


def _require_budget(value: Any, name: str) -> dict[str, int]:
    budget = _require_object(value, name)
    if set(budget) != {"warning", "hard"}:
        raise ManagedNixError(f"{name} must contain exactly warning and hard")
    warning = budget["warning"]
    hard = budget["hard"]
    if (
        not isinstance(warning, int)
        or isinstance(warning, bool)
        or not isinstance(hard, int)
        or isinstance(hard, bool)
        or warning < 0
        or hard < warning
    ):
        raise ManagedNixError(f"{name} must contain ordered non-negative integers")
    return {"warning": warning, "hard": hard}


def _require_budgets(value: Any, name: str = "budgets") -> dict[str, dict[str, int]]:
    budgets = _require_object(value, name)
    if set(budgets) != {"store_bytes", "cache_bytes", "runtime_seconds"}:
        raise ManagedNixError(f"{name} must define store_bytes, cache_bytes and runtime_seconds")
    return {
        "store_bytes": _require_budget(budgets["store_bytes"], f"{name}.store_bytes"),
        "cache_bytes": _require_budget(budgets["cache_bytes"], f"{name}.cache_bytes"),
        "runtime_seconds": _require_budget(
            budgets["runtime_seconds"], f"{name}.runtime_seconds"
        ),
    }


def _normalize_effects(possible_effects: Sequence[str]) -> list[str]:
    if not isinstance(possible_effects, Sequence) or isinstance(
        possible_effects, (str, bytes)
    ):
        raise ManagedNixError("possible_effects must be a sequence")
    if not possible_effects:
        raise ManagedNixError("possible_effects must not be empty")
    normalized = sorted(
        {_require_string(value, "possible_effect").casefold() for value in possible_effects}
    )
    if len(normalized) != len(possible_effects):
        raise ManagedNixError("possible_effects must be unique after canonicalization")
    return normalized


def classify_effect(possible_effects: Sequence[str]) -> str:
    """Classify by possible effect. Unknown effects fail closed as destructive."""

    normalized = set(_normalize_effects(possible_effects))
    if normalized & DESTRUCTIVE_EFFECTS:
        return "destructive"
    known = DESTRUCTIVE_EFFECTS | BOOT_CRITICAL_EFFECTS | NORMAL_EFFECTS
    if normalized - known:
        return "destructive"
    if normalized & BOOT_CRITICAL_EFFECTS:
        return "boot-critical"
    return "normal"


def _validate_build_entrypoint(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ManagedNixError("entrypoint must be an argv list")
    normalized = [_require_string(item, "entrypoint argv") for item in value]
    if tuple(normalized) != CANONICAL_BUILD_ENTRYPOINT:
        raise ManagedNixError(
            "entrypoint must equal the canonical pure NixOS toplevel build adapter"
        )
    return normalized


def validate_build_request(request: Mapping[str, Any]) -> dict[str, Any]:
    """Validate immutable build inputs without invoking Nix or changing runtime state."""

    if not isinstance(request, Mapping):
        raise ManagedNixError("build request must be an object")
    _require_exact_keys(request, _BUILD_REQUEST_KEYS, "build request")
    if (
        request.get("schema_version") != CONTRACT_VERSION
        or request.get("kind") != BUILD_REQUEST_KIND
    ):
        raise ManagedNixError("unsupported managed NixOS build request")
    if request.get("effect_class") != "build":
        raise ManagedNixError("build request effect_class must be build")

    repository = _require_repository(request.get("repository"))
    source_revision = _require_revision(request.get("source_revision"))
    control = _require_control_release(request.get("control_release_set"))

    nix_inputs = _require_object(request.get("nix_inputs"), "nix_inputs")
    if not nix_inputs:
        raise ManagedNixError("nix_inputs must not be empty")
    normalized_inputs: dict[str, str] = {}
    for raw_name, digest in nix_inputs.items():
        name = _require_string(raw_name, "nix input name")
        if name != raw_name:
            raise ManagedNixError("nix input names must already be canonical")
        normalized_inputs[name] = _require_sha256(digest, f"nix_inputs.{name}")

    budgets = _require_budgets(request.get("budgets"))

    leases = request.get("leases")
    if not isinstance(leases, list) or not leases:
        raise ManagedNixError("leases must be a non-empty list")
    normalized_leases = sorted({_require_string(item, "lease") for item in leases})
    if len(normalized_leases) != len(leases):
        raise ManagedNixError("leases must be unique")

    possible_effects = request.get("possible_effects")
    if not isinstance(possible_effects, list):
        raise ManagedNixError("possible_effects must be a list")
    normalized_effects = _normalize_effects(possible_effects)
    effect_scope = classify_effect(normalized_effects)
    if effect_scope == "destructive":
        raise ManagedNixError(
            "destructive or ambiguous effects require the separate destructive plan"
        )

    entrypoint = _validate_build_entrypoint(request.get("entrypoint"))
    return {
        "schema_version": CONTRACT_VERSION,
        "kind": BUILD_REQUEST_KIND,
        "effect_class": "build",
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


def make_build_receipt(
    request: Mapping[str, Any],
    *,
    system_closure: str,
    declared_capabilities: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind a successful managed-build result to exact immutable inputs and closure."""

    normalized = validate_build_request(request)
    closure = _require_closure(system_closure)
    capabilities = _require_object(dict(declared_capabilities), "declared_capabilities")
    if not capabilities:
        raise ManagedNixError("declared_capabilities must not be empty")
    return {
        "schema_version": CONTRACT_VERSION,
        "kind": BUILD_RECEIPT_KIND,
        "effect_class": "build",
        "result": "succeeded",
        "repository": normalized["repository"],
        "source_revision": normalized["source_revision"],
        "control_release_set": normalized["control_release_set"],
        "nix_inputs_sha256": sha256_json(normalized["nix_inputs"]),
        "budgets": normalized["budgets"],
        "leases_sha256": sha256_json(normalized["leases"]),
        "effect_scope": normalized["effect_scope"],
        "system_closure": closure,
        "declared_capabilities": capabilities,
        "build_request_sha256": sha256_json(normalized),
        "activation_authorized": False,
    }


def validate_build_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(receipt, Mapping):
        raise ManagedNixError("build receipt must be an object")
    _require_exact_keys(receipt, _BUILD_RECEIPT_KEYS, "build receipt")
    if (
        receipt.get("schema_version") != CONTRACT_VERSION
        or receipt.get("kind") != BUILD_RECEIPT_KIND
    ):
        raise ManagedNixError("unsupported managed NixOS build receipt")
    if receipt.get("effect_class") != "build" or receipt.get("result") != "succeeded":
        raise ManagedNixError("build receipt is not a successful build-effect result")
    if receipt.get("activation_authorized") is not False:
        raise ManagedNixError("build receipt must not itself authorize activation")

    _require_repository(receipt.get("repository"))
    _require_revision(receipt.get("source_revision"))
    _require_control_release(receipt.get("control_release_set"))
    _require_sha256(receipt.get("nix_inputs_sha256"), "nix_inputs_sha256")
    _require_budgets(receipt.get("budgets"), "build receipt budgets")
    _require_sha256(receipt.get("leases_sha256"), "leases_sha256")
    _require_sha256(receipt.get("build_request_sha256"), "build_request_sha256")
    _require_closure(receipt.get("system_closure"))
    if receipt.get("effect_scope") not in {"normal", "boot-critical"}:
        raise ManagedNixError("build receipt effect_scope is invalid")
    capabilities = _require_object(
        receipt.get("declared_capabilities"), "declared_capabilities"
    )
    if not capabilities:
        raise ManagedNixError("build receipt declared_capabilities are missing")
    return _copy_json(dict(receipt), "build_receipt")


def validate_activation_authority(
    build_receipt: Mapping[str, Any],
    authority: Mapping[str, Any],
    *,
    expected_authority_sha256: str,
    expected_target: str,
    now: str,
) -> dict[str, Any]:
    """Validate externally bound activation authority without executing it.

    ``expected_authority_sha256`` is not minted here. The successor runtime lane must
    obtain it from its canonical typed review/authority boundary and pass that exact
    digest into this pure validator.
    """

    receipt = validate_build_receipt(build_receipt)
    if not isinstance(authority, Mapping):
        raise ManagedNixError("activation authority must be an object")
    _require_exact_keys(authority, _ACTIVATION_AUTHORITY_KEYS, "activation authority")
    authority_digest = _require_sha256(
        expected_authority_sha256, "expected_authority_sha256"
    )
    if sha256_json(dict(authority)) != authority_digest:
        raise ManagedNixError(
            "activation authority does not match externally bound review authority"
        )
    if (
        authority.get("schema_version") != CONTRACT_VERSION
        or authority.get("kind") != ACTIVATION_AUTHORITY_KIND
    ):
        raise ManagedNixError("unsupported activation authority")
    if authority.get("effect_class") != "activation":
        raise ManagedNixError("activation authority effect_class must be activation")

    mode = authority.get("mode")
    if mode not in ALLOWED_ACTIVATION_MODES:
        raise ManagedNixError("activation mode is invalid")
    if receipt["effect_scope"] == "boot-critical" and mode == "persistent":
        raise ManagedNixError(
            "boot-critical build must use test/next-boot before persistent activation"
        )

    source_revision = _require_revision(authority.get("source_revision"))
    closure = _require_closure(authority.get("system_closure"))
    target = _require_string(authority.get("target"), "target")
    expected_target_value = _require_string(expected_target, "expected_target")
    prior_closure = _require_closure(authority.get("prior_closure"), "prior_closure")
    recovery_path = _require_string(authority.get("recovery_path"), "recovery_path")
    build_digest = _require_sha256(
        authority.get("build_receipt_sha256"), "build_receipt_sha256"
    )
    expires = _parse_time(authority.get("expires_at"), "expires_at")
    current = _parse_time(now, "now")
    if current > expires:
        raise ManagedNixError("activation authority is expired")

    if source_revision != receipt["source_revision"]:
        raise ManagedNixError("activation source revision does not match build receipt")
    if closure != receipt["system_closure"]:
        raise ManagedNixError("activation closure does not match build receipt")
    if target != expected_target_value:
        raise ManagedNixError("activation target does not match reserved target")
    if build_digest != sha256_json(receipt):
        raise ManagedNixError("activation authority is not bound to this build receipt")
    if prior_closure == closure:
        raise ManagedNixError(
            "prior_closure must identify an independent rollback generation"
        )

    return {
        "schema_version": CONTRACT_VERSION,
        "kind": ACTIVATION_PLAN_KIND,
        "effect_class": "activation",
        "mode": mode,
        "target": target,
        "source_revision": source_revision,
        "system_closure": closure,
        "build_receipt_sha256": build_digest,
        "prior_closure": prior_closure,
        "recovery_path": recovery_path,
        "authority_sha256": authority_digest,
        "executor_authority": "successor-task-typed-activation-only",
        "source_reevaluation_allowed": False,
        "broad_root_shell_allowed": False,
    }


def make_activation_receipt(
    activation_plan: Mapping[str, Any],
    *,
    live_closure: str,
    readback_evidence_sha256: str,
) -> dict[str, Any]:
    """Bind a successor executor's independent readback to the approved activation plan."""

    if activation_plan.get("kind") != ACTIVATION_PLAN_KIND:
        raise ManagedNixError("activation receipt requires a validated activation plan")
    approved = _require_closure(activation_plan.get("system_closure"))
    live = _require_closure(live_closure, "live_closure")
    if live != approved:
        raise ManagedNixError(
            "live closure does not match the approved activation closure"
        )
    evidence = _require_sha256(
        readback_evidence_sha256, "readback_evidence_sha256"
    )
    return {
        "schema_version": CONTRACT_VERSION,
        "kind": ACTIVATION_RECEIPT_KIND,
        "effect_class": "activation",
        "result": "succeeded",
        "mode": _require_string(activation_plan.get("mode"), "mode"),
        "target": _require_string(activation_plan.get("target"), "target"),
        "source_revision": _require_revision(activation_plan.get("source_revision")),
        "system_closure": approved,
        "live_closure": live,
        "build_receipt_sha256": _require_sha256(
            activation_plan.get("build_receipt_sha256"), "build_receipt_sha256"
        ),
        "authority_sha256": _require_sha256(
            activation_plan.get("authority_sha256"), "authority_sha256"
        ),
        "readback_evidence_sha256": evidence,
        "prior_closure": _require_closure(
            activation_plan.get("prior_closure"), "prior_closure"
        ),
        "recovery_path": _require_string(
            activation_plan.get("recovery_path"), "recovery_path"
        ),
        "source_reevaluation_used": False,
    }


def rollback_plan(activation_plan: Mapping[str, Any]) -> dict[str, Any]:
    if activation_plan.get("kind") != ACTIVATION_PLAN_KIND:
        raise ManagedNixError("rollback requires a validated activation plan")
    return {
        "kind": "heim_pc.nixos_rollback_plan",
        "schema_version": CONTRACT_VERSION,
        "target": _require_string(activation_plan.get("target"), "target"),
        "system_closure": _require_closure(
            activation_plan.get("prior_closure"), "prior_closure"
        ),
        "recovery_path": _require_string(
            activation_plan.get("recovery_path"), "recovery_path"
        ),
        "source_reevaluation_allowed": False,
    }


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManagedNixError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ManagedNixError(f"JSON input {path} must be an object")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("validate-build-request")
    check.add_argument("request", type=Path)

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
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
