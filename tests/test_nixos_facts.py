from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.nixos_facts import (
    BUILD_RECEIPT_KIND,
    FactsError,
    declared_facts_from_build_receipt,
    runtime_facts,
    sha256_json,
    validate_runtime_facts,
)

REVISION = "a" * 40
CONTROL_DIGEST = "b" * 64
CLOSURE = "/nix/store/00000000000000000000000000000000-nixos-system-heim-pc-26.05"


def build_receipt() -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": BUILD_RECEIPT_KIND,
        "effect_class": "build",
        "result": "succeeded",
        "source_revision": REVISION,
        "control_release_set": {"id": "control-2026-09", "digest": CONTROL_DIGEST},
        "system_closure": CLOSURE,
        "declared_capabilities": {
            "boot": {"uefi": True},
            "gpu": {"nvidia": True},
            "audio": {"pipewire": True},
            "storage": {"encrypted": True},
        },
    }


def test_declared_facts_are_derived_and_receipt_bound() -> None:
    receipt = build_receipt()
    result = declared_facts_from_build_receipt(receipt)

    assert result["sourceRevision"] == REVISION
    assert result["systemClosure"] == CLOSURE
    assert result["controlReleaseSet"] == {
        "id": "control-2026-09",
        "digest": CONTROL_DIGEST,
    }
    assert result["binding"]["buildReceiptSha256"] == sha256_json(receipt)
    assert result["binding"]["derivation"] == "managed-nixos-build-receipt"


def test_declared_facts_reject_noncanonical_nix_store_closures() -> None:
    for bad in (
        "/nix/store/../../etc/x-nixos-system-y",
        "/nix/store/abc-nixos-system-heim-pc",
        "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-nixos-system-heim-pc",
        "/nix/store/00000000000000000000000000000000-not-a-system",
    ):
        candidate = build_receipt()
        candidate["system_closure"] = bad
        with pytest.raises(FactsError, match="canonical immutable NixOS"):
            declared_facts_from_build_receipt(candidate)


def test_declared_facts_fail_closed_on_unbound_or_mutable_build_inputs() -> None:
    receipt = build_receipt()
    receipt["source_revision"] = "main"
    with pytest.raises(FactsError, match="immutable"):
        declared_facts_from_build_receipt(receipt)

    receipt = build_receipt()
    receipt["system_closure"] = "./result"
    with pytest.raises(FactsError, match="/nix/store"):
        declared_facts_from_build_receipt(receipt)

    receipt = build_receipt()
    receipt["effect_class"] = "activation"
    with pytest.raises(FactsError, match="build-effect"):
        declared_facts_from_build_receipt(receipt)


def test_runtime_facts_are_separate_source_freshness_and_hash_bound() -> None:
    result = runtime_facts(
        source_revision=REVISION,
        source="heim-pc:read-only-hardware-probe:v1",
        observed_at="2026-09-04T07:00:00Z",
        freshness_seconds=900,
        observations={"pci": "NVIDIA GeForce RTX 4070 Ti SUPER", "usb": "MOTU M2"},
    )

    assert result["kind"] == "RuntimeFacts"
    assert result["binding"]["truthClass"] == "volatile-runtime-observation"
    assert result["observations"]["pci"]["value"].startswith("NVIDIA")
    validation = validate_runtime_facts(
        result,
        expected_revision=REVISION,
        now="2026-09-04T07:05:00Z",
    )
    assert validation["valid"] is True
    assert validation["ageSeconds"] == 300


def test_runtime_facts_reject_stale_revision_and_tampered_observation() -> None:
    result = runtime_facts(
        source_revision=REVISION,
        source="probe",
        observed_at="2026-09-04T07:00:00Z",
        freshness_seconds=60,
        observations={"pci": "NVIDIA GeForce RTX 4070 Ti SUPER"},
    )
    with pytest.raises(FactsError, match="stale"):
        validate_runtime_facts(
            result,
            expected_revision=REVISION,
            now="2026-09-04T07:02:00Z",
        )
    with pytest.raises(FactsError, match="reviewed revision"):
        validate_runtime_facts(
            result,
            expected_revision="c" * 40,
            now="2026-09-04T07:00:30Z",
        )

    result["observations"]["pci"]["value"] = "different"
    with pytest.raises(FactsError, match="hash mismatch"):
        validate_runtime_facts(
            result,
            expected_revision=REVISION,
            now="2026-09-04T07:00:30Z",
        )


def test_contract_tracks_definition_not_current_truth_file() -> None:
    contract_path = Path(__file__).parents[1] / "nixos" / "facts" / "contract-v1.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    example = contract["x-heim-pc-example"]
    assert example["runtime"]["storage"] == "outside-git"
    assert example["truth_policy"] == {
        "declared_facts_current_file_in_git": False,
        "runtime_may_rewrite_declared_truth": False,
        "fixtures_are_current_truth": False,
    }


def test_declared_and_runtime_cli_paths_emit_bound_json(tmp_path, capsys) -> None:
    from scripts.nixos_facts import main

    receipt_path = tmp_path / "build-receipt.json"
    receipt_path.write_text(json.dumps(build_receipt()), encoding="utf-8")
    assert main(["declared", "--build-receipt", str(receipt_path)]) == 0
    declared = json.loads(capsys.readouterr().out)
    assert declared["sourceRevision"] == REVISION
    assert declared["binding"]["derivation"] == "managed-nixos-build-receipt"

    pci = tmp_path / "pci.txt"
    pci.write_text("NVIDIA GeForce RTX 4070 Ti SUPER", encoding="utf-8")
    assert main([
        "runtime",
        "--source-revision", REVISION,
        "--source", "probe",
        "--observed-at", "2026-09-04T07:00:00Z",
        "--freshness-seconds", "900",
        "--observation", f"pci={pci}",
    ]) == 0
    runtime = json.loads(capsys.readouterr().out)
    assert runtime["sourceRevision"] == REVISION
    assert runtime["observations"]["pci"]["value"] == "NVIDIA GeForce RTX 4070 Ti SUPER"


def test_contract_required_bindings_match_emitted_output_paths() -> None:
    contract_path = Path(__file__).parents[1] / "nixos" / "facts" / "contract-v1.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    example = contract["x-heim-pc-example"]
    assert example["declared"]["required_bindings"] == [
        "sourceRevision", "controlReleaseSet", "systemClosure", "binding.buildReceiptSha256"
    ]
    assert example["runtime"]["required_bindings"] == [
        "sourceRevision", "source", "observedAt", "freshnessSeconds", "binding.observationsSha256"
    ]
