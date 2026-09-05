#!/usr/bin/env python3
"""Derive NixOS declared facts and bind volatile runtime observations.

The module deliberately has no command that writes a current facts file into Git.
Declared facts are derived from an immutable managed-build receipt. Runtime facts are
observation artifacts that belong outside the repository and carry freshness/evidence
bindings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

DECLARED_API_VERSION = "heim-pc.nixos.declared-facts/v1"
RUNTIME_API_VERSION = "heim-pc.nixos.runtime-facts/v1"
BUILD_RECEIPT_KIND = "heim_pc.nixos_build_receipt"
HOST_ID = "heim-pc"
PROFILE_ID = "nixos-executor-2026"
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_STORE_PATH_RE = re.compile(r"^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-nixos-system-[A-Za-z0-9._+-]+$")


class FactsError(ValueError):
    """Raised when a facts binding is missing, mutable or stale."""


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


def _require_sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or not _HEX_RE.fullmatch(value):
        raise FactsError(f"{name} must be exactly 64 lowercase hexadecimal characters")
    return value


def _require_revision(value: Any, name: str = "source_revision") -> str:
    if (
        not isinstance(value, str)
        or len(value) not in {40, 64}
        or not _HEX_RE.fullmatch(value)
    ):
        raise FactsError(f"{name} must be an immutable 40/64-character Git object id")
    return value


def _require_closure(value: Any) -> str:
    if not isinstance(value, str) or not _STORE_PATH_RE.fullmatch(value):
        raise FactsError("system_closure must be a canonical immutable NixOS /nix/store path")
    return value


def _require_nonempty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise FactsError(f"{name} must be a non-empty string")
    return value.strip()


def _parse_timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise FactsError(f"{name} must be an ISO-8601 timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise FactsError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise FactsError(f"{name} must carry a timezone")
    return parsed.astimezone(timezone.utc)


def _copy_json_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FactsError(f"{name} must be an object")
    # Canonical round-trip rejects non-JSON values and detaches caller-owned state.
    try:
        return json.loads(canonical_json(value))
    except (TypeError, ValueError) as exc:
        raise FactsError(f"{name} must be canonical JSON data") from exc


def declared_facts_from_build_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Project desired facts from one exact managed NixOS build receipt."""

    if not isinstance(receipt, Mapping):
        raise FactsError("build receipt must be an object")
    if receipt.get("schema_version") != 1 or receipt.get("kind") != BUILD_RECEIPT_KIND:
        raise FactsError("unsupported managed NixOS build receipt")
    if receipt.get("effect_class") != "build":
        raise FactsError("declared facts require a build-effect receipt")
    if receipt.get("result") != "succeeded":
        raise FactsError("declared facts require a successful build receipt")

    source_revision = _require_revision(receipt.get("source_revision"))
    closure = _require_closure(receipt.get("system_closure"))
    control = _copy_json_object(receipt.get("control_release_set"), "control_release_set")
    control_id = _require_nonempty_string(control.get("id"), "control_release_set.id")
    control_digest = _require_sha256(control.get("digest"), "control_release_set.digest")
    capabilities = _copy_json_object(receipt.get("declared_capabilities"), "declared_capabilities")
    if not capabilities:
        raise FactsError("declared_capabilities must not be empty")

    receipt_copy = _copy_json_object(dict(receipt), "build_receipt")
    return {
        "apiVersion": DECLARED_API_VERSION,
        "kind": "DeclaredFacts",
        "host": HOST_ID,
        "profile": PROFILE_ID,
        "sourceRevision": source_revision,
        "controlReleaseSet": {"id": control_id, "digest": control_digest},
        "systemClosure": closure,
        "capabilities": capabilities,
        "binding": {
            "buildReceiptSha256": sha256_json(receipt_copy),
            "derivation": "managed-nixos-build-receipt",
        },
    }


def runtime_facts(
    *,
    source_revision: str,
    source: str,
    observed_at: str,
    freshness_seconds: int,
    observations: Mapping[str, str],
) -> dict[str, Any]:
    """Bind volatile observations to source, timestamp, revision and content hashes."""

    revision = _require_revision(source_revision)
    source_value = _require_nonempty_string(source, "source")
    observed = _parse_timestamp(observed_at, "observed_at")
    if (
        not isinstance(freshness_seconds, int)
        or isinstance(freshness_seconds, bool)
        or freshness_seconds <= 0
    ):
        raise FactsError("freshness_seconds must be a positive integer")
    if not isinstance(observations, Mapping) or not observations:
        raise FactsError("observations must be a non-empty mapping")

    bound: dict[str, dict[str, str]] = {}
    for name, value in sorted(observations.items()):
        key = _require_nonempty_string(name, "observation name")
        text = _require_nonempty_string(value, f"observation {key}")
        encoded = text.encode("utf-8")
        bound[key] = {
            "value": text,
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }

    evidence_digest = sha256_json(bound)
    return {
        "apiVersion": RUNTIME_API_VERSION,
        "kind": "RuntimeFacts",
        "host": HOST_ID,
        "profile": PROFILE_ID,
        "sourceRevision": revision,
        "source": source_value,
        "observedAt": observed.isoformat().replace("+00:00", "Z"),
        "freshnessSeconds": freshness_seconds,
        "observations": bound,
        "binding": {
            "observationsSha256": evidence_digest,
            "truthClass": "volatile-runtime-observation",
        },
    }


def validate_runtime_facts(
    facts: Mapping[str, Any],
    *,
    expected_revision: str,
    now: str,
    max_age_seconds: int | None = None,
) -> dict[str, Any]:
    """Fail closed unless runtime facts are current and bound to the reviewed source."""

    if not isinstance(facts, Mapping):
        raise FactsError("runtime facts must be an object")
    if facts.get("apiVersion") != RUNTIME_API_VERSION or facts.get("kind") != "RuntimeFacts":
        raise FactsError("unsupported runtime facts schema")
    if facts.get("host") != HOST_ID or facts.get("profile") != PROFILE_ID:
        raise FactsError("runtime facts target a different host/profile")

    expected = _require_revision(expected_revision, "expected_revision")
    actual = _require_revision(facts.get("sourceRevision"))
    if actual != expected:
        raise FactsError("runtime facts source revision does not match reviewed revision")

    observed = _parse_timestamp(facts.get("observedAt"), "observedAt")
    current = _parse_timestamp(now, "now")
    age = (current - observed).total_seconds()
    if age < -60:
        raise FactsError("runtime facts observation time is materially in the future")

    declared_freshness = facts.get("freshnessSeconds")
    if (
        not isinstance(declared_freshness, int)
        or isinstance(declared_freshness, bool)
        or declared_freshness <= 0
    ):
        raise FactsError("runtime facts freshnessSeconds is invalid")
    effective_max_age = declared_freshness
    if max_age_seconds is not None:
        if (
            not isinstance(max_age_seconds, int)
            or isinstance(max_age_seconds, bool)
            or max_age_seconds <= 0
        ):
            raise FactsError("max_age_seconds must be a positive integer")
        effective_max_age = min(effective_max_age, max_age_seconds)
    if age > effective_max_age:
        raise FactsError("runtime facts are stale")

    observations = facts.get("observations")
    if not isinstance(observations, dict) or not observations:
        raise FactsError("runtime observations are missing")
    normalized: dict[str, dict[str, str]] = {}
    for name, item in observations.items():
        if not isinstance(name, str) or not isinstance(item, dict):
            raise FactsError("runtime observation record is invalid")
        value = item.get("value")
        digest = item.get("sha256")
        if not isinstance(value, str) or not value:
            raise FactsError(f"runtime observation {name} has no value")
        expected_digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        if digest != expected_digest:
            raise FactsError(f"runtime observation {name} hash mismatch")
        normalized[name] = {"value": value, "sha256": expected_digest}
    binding = facts.get("binding")
    if not isinstance(binding, dict) or binding.get("truthClass") != "volatile-runtime-observation":
        raise FactsError("runtime facts truth class is missing")
    if binding.get("observationsSha256") != sha256_json(normalized):
        raise FactsError("runtime facts aggregate evidence hash mismatch")

    return {
        "valid": True,
        "ageSeconds": max(0, int(age)),
        "effectiveFreshnessSeconds": effective_max_age,
        "sourceRevision": actual,
        "observationsSha256": binding["observationsSha256"],
    }


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FactsError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise FactsError(f"JSON input {path} must be an object")
    return value


def _cli_declared(args: argparse.Namespace) -> dict[str, Any]:
    return declared_facts_from_build_receipt(_load_json(args.build_receipt))


def _cli_runtime(args: argparse.Namespace) -> dict[str, Any]:
    observations: dict[str, str] = {}
    for item in args.observation:
        if "=" not in item:
            raise FactsError("--observation must be NAME=PATH")
        name, path = item.split("=", 1)
        observations[name] = Path(path).read_text(encoding="utf-8")
    return runtime_facts(
        source_revision=args.source_revision,
        source=args.source,
        observed_at=args.observed_at,
        freshness_seconds=args.freshness_seconds,
        observations=observations,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    declared = sub.add_parser("declared", help="derive declared facts from one build receipt")
    declared.add_argument("--build-receipt", type=Path, required=True)
    declared.set_defaults(handler=_cli_declared)

    runtime = sub.add_parser("runtime", help="bind external read-only observation files")
    runtime.add_argument("--source-revision", required=True)
    runtime.add_argument("--source", required=True)
    runtime.add_argument("--observed-at", required=True)
    runtime.add_argument("--freshness-seconds", type=int, required=True)
    runtime.add_argument("--observation", action="append", default=[], metavar="NAME=PATH")
    runtime.set_defaults(handler=_cli_runtime)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = args.handler(args)
    except (FactsError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
