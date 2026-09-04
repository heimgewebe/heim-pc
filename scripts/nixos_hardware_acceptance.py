#!/usr/bin/env python3
"""Produce and evaluate fresh read-only Heim-PC hardware acceptance evidence."""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

try:
    from scripts.nixos_facts import (
        FactsError,
        runtime_facts,
        sha256_json,
        validate_runtime_facts,
    )
except ModuleNotFoundError:  # Direct execution from scripts/.
    from nixos_facts import FactsError, runtime_facts, sha256_json, validate_runtime_facts

HARDWARE_SOURCE_ID = "heim-pc:read-only-hardware-probe:v1"
PROBE_DEFINITION = {
    "schema_version": 1,
    "kind": "heim_pc.nixos_hardware_probe_definition",
    "source": HARDWARE_SOURCE_ID,
    "gpu": [
        "nvidia-smi",
        "--query-gpu=name,pci.device_id,driver_version",
        "--format=csv,noheader",
    ],
    "audio": {"read": "/proc/asound/cards"},
    "midi": ["aconnect", "-l"],
    "shell": False,
    "mutating": False,
}
HISTORICAL_PHYSICAL_EVIDENCE = {
    "classification": "historical-only",
    "archive_id": "20260902T112439Z-5eabac896f53",
    "head": "7fd5eed229fae95e839e6b9556cd7f4782506d2a",
    "purpose": "preserve pre-migration physical Gate A/B evidence without freshness claims",
}

ANCHORS = {
    "gpu": {
        "observation_keys": ("gpu",),
        "needles": ("geforce rtx 4070 ti super",),
        "label": "RTX 4070 Ti SUPER",
    },
    "audio": {
        "observation_keys": ("audio",),
        "needles": ("motu m2",),
        "label": "MOTU M2",
    },
    "midi": {
        # USB enumeration alone is not enough; this requires the ALSA MIDI surface.
        "observation_keys": ("midi",),
        "needles": ("fp-30x",),
        "label": "Roland FP-30X MIDI path",
    },
}


class AcceptanceError(ValueError):
    """Raised when hardware evidence cannot support a current acceptance decision."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _run_probe_command(argv: list[str]) -> str:
    """Run one fixed read-only probe without shell interpretation."""

    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        return f"ERROR:command-not-found:{argv[0]}"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"ERROR:probe-failed:{argv[0]}:{type(exc).__name__}"
    if completed.returncode != 0:
        return f"ERROR:probe-returncode:{argv[0]}:{completed.returncode}"
    text = completed.stdout.strip()
    return text if text else f"ERROR:probe-empty:{argv[0]}"


def _read_probe_file(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        return f"ERROR:read-failed:{path}:{type(exc).__name__}"
    return text if text else f"ERROR:read-empty:{path}"


def probe_current_hardware(source_revision: str) -> dict[str, Any]:
    """Create fresh runtime facts from the fixed local read-only probe definition.

    The caller supplies only the exact reviewed source revision. Observation source,
    commands, files and observation time are owned by this producer and cannot be
    substituted by CLI input.
    """

    observations = {
        "gpu": _run_probe_command(list(PROBE_DEFINITION["gpu"])),
        "audio": _read_probe_file(Path(PROBE_DEFINITION["audio"]["read"])),
        "midi": _run_probe_command(list(PROBE_DEFINITION["midi"])),
    }
    try:
        return runtime_facts(
            source_revision=source_revision,
            source=HARDWARE_SOURCE_ID,
            observed_at=_utc_now(),
            freshness_seconds=900,
            observations=observations,
        )
    except FactsError as exc:
        raise AcceptanceError(str(exc)) from exc


def _observation_text(facts: Mapping[str, Any], keys: tuple[str, ...]) -> str:
    observations = facts.get("observations")
    if not isinstance(observations, Mapping):
        return ""
    values: list[str] = []
    for key in keys:
        item = observations.get(key)
        if isinstance(item, Mapping) and isinstance(item.get("value"), str):
            values.append(item["value"])
    return "\n".join(values).casefold()


def evaluate_hardware_acceptance(
    facts: Mapping[str, Any],
    *,
    expected_revision: str,
    now: str,
    max_age_seconds: int = 900,
) -> dict[str, Any]:
    """Return a deterministic acceptance report for the canonical 2026 anchors."""

    try:
        validation = validate_runtime_facts(
            facts,
            expected_revision=expected_revision,
            now=now,
            max_age_seconds=max_age_seconds,
        )
    except FactsError as exc:
        raise AcceptanceError(str(exc)) from exc
    if facts.get("source") != HARDWARE_SOURCE_ID:
        raise AcceptanceError(
            "hardware acceptance requires the canonical read-only hardware probe source"
        )

    checks: dict[str, dict[str, Any]] = {}
    for name, spec in ANCHORS.items():
        haystack = _observation_text(facts, spec["observation_keys"])
        matched = all(needle in haystack for needle in spec["needles"])
        checks[name] = {
            "label": spec["label"],
            "status": "pass" if matched else "fail",
            "observationKeys": list(spec["observation_keys"]),
        }

    passed = all(item["status"] == "pass" for item in checks.values())
    return {
        "schema_version": 1,
        "kind": "heim_pc.nixos_hardware_acceptance",
        "host": "heim-pc",
        "profile": "nixos-executor-2026",
        "sourceRevision": validation["sourceRevision"],
        "source": HARDWARE_SOURCE_ID,
        "probeDefinitionSha256": sha256_json(PROBE_DEFINITION),
        "runtimeEvidence": {
            "ageSeconds": validation["ageSeconds"],
            "effectiveFreshnessSeconds": validation["effectiveFreshnessSeconds"],
            "observationsSha256": validation["observationsSha256"],
        },
        "checks": checks,
        "status": "pass" if passed else "fail",
        "historicalEvidence": HISTORICAL_PHYSICAL_EVIDENCE.copy(),
        "historicalEvidenceIsCurrent": False,
        "productionEffectsAuthorized": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--max-age-seconds", type=int, default=900)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        facts = probe_current_hardware(args.expected_revision)
        result = evaluate_hardware_acceptance(
            facts,
            expected_revision=args.expected_revision,
            now=_utc_now(),
            max_age_seconds=args.max_age_seconds,
        )
    except AcceptanceError as exc:
        parser.error(str(exc))
    output = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_hardware_probe_result",
        "sourceRevision": args.expected_revision,
        "probeDefinitionSha256": sha256_json(PROBE_DEFINITION),
        "runtimeFactsSha256": sha256_json(facts),
        "observedAt": facts["observedAt"],
        "acceptance": result,
    }
    print(json.dumps(output, sort_keys=True, indent=2))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())