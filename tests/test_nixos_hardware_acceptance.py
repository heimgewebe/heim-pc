from __future__ import annotations

import hashlib
import json

import pytest

from scripts import nixos_hardware_acceptance as hardware
from scripts.nixos_facts import runtime_facts, sha256_json
from scripts.nixos_hardware_acceptance import (
    AcceptanceError,
    HARDWARE_SOURCE_ID,
    HISTORICAL_PHYSICAL_EVIDENCE,
    PROBE_DEFINITION,
    evaluate_hardware_acceptance,
    probe_current_hardware,
)

REVISION = "d" * 40


def current_hardware_facts():
    return runtime_facts(
        source_revision=REVISION,
        source=HARDWARE_SOURCE_ID,
        observed_at="2026-09-04T07:00:00Z",
        freshness_seconds=900,
        observations={
            "gpu": "NVIDIA GeForce RTX 4070 Ti SUPER, 0x270510DE, 595.84",
            "audio": " 2 [M2             ]: USB-Audio - MOTU M2",
            "midi": "client 24: 'FP-30X' [type=kernel,card=2]",
            "midi_usb": "card=2 usb=0582:01b1",
        },
    )


def set_observation(facts, key: str, value: str) -> None:
    facts["observations"][key]["value"] = value
    facts["observations"][key]["sha256"] = hashlib.sha256(value.encode()).hexdigest()
    facts["binding"]["observationsSha256"] = sha256_json(facts["observations"])


def test_acceptance_requires_fresh_exact_reviewed_revision_and_all_anchors() -> None:
    result = evaluate_hardware_acceptance(
        current_hardware_facts(),
        expected_revision=REVISION,
        now="2026-09-04T07:05:00Z",
        max_age_seconds=600,
    )

    assert result["status"] == "pass"
    assert {name: check["status"] for name, check in result["checks"].items()} == {
        "gpu": "pass",
        "audio": "pass",
        "midi": "pass",
    }
    assert result["sourceRevision"] == REVISION
    assert result["source"] == HARDWARE_SOURCE_ID
    assert result["probeDefinitionSha256"] == sha256_json(PROBE_DEFINITION)
    assert result["productionEffectsAuthorized"] is False


def test_missing_anchor_fails_without_turning_history_into_current_truth() -> None:
    facts = current_hardware_facts()
    set_observation(facts, "midi", "no MIDI device")

    result = evaluate_hardware_acceptance(
        facts,
        expected_revision=REVISION,
        now="2026-09-04T07:05:00Z",
    )
    assert result["status"] == "fail"
    assert result["checks"]["midi"]["status"] == "fail"
    assert result["historicalEvidence"]["classification"] == "historical-only"
    assert result["historicalEvidenceIsCurrent"] is False


def test_midi_anchor_requires_accepted_roland_kernel_client_on_same_line() -> None:
    facts = current_hardware_facts()
    set_observation(
        facts,
        "midi",
        "client 24: 'FP-30X' [type=user,pid=1234]\n"
        "client 32: 'Other Hardware' [type=kernel,card=2]",
    )

    result = evaluate_hardware_acceptance(
        facts,
        expected_revision=REVISION,
        now="2026-09-04T07:05:00Z",
    )
    assert result["status"] == "fail"
    assert result["checks"]["midi"]["status"] == "fail"


def test_midi_anchor_accepts_kernel_roland_digital_piano_alias_with_fp30x_usb_id() -> None:
    facts = current_hardware_facts()
    set_observation(facts, "midi", "client 28: 'Roland Digital Piano' [type=kernel,card=3]")
    set_observation(facts, "midi_usb", "card=3 usb=0582:01b1")

    result = evaluate_hardware_acceptance(
        facts,
        expected_revision=REVISION,
        now="2026-09-04T07:05:00Z",
    )
    assert result["status"] == "pass"
    assert result["checks"]["midi"]["status"] == "pass"


def test_midi_anchor_rejects_generic_roland_alias_with_other_usb_product() -> None:
    facts = current_hardware_facts()
    set_observation(facts, "midi", "client 28: 'Roland Digital Piano' [type=kernel,card=3]")
    set_observation(facts, "midi_usb", "card=3 usb=0582:ffff")

    result = evaluate_hardware_acceptance(
        facts,
        expected_revision=REVISION,
        now="2026-09-04T07:05:00Z",
    )
    assert result["status"] == "fail"
    assert result["checks"]["midi"]["status"] == "fail"


def test_midi_anchor_rejects_fp30x_usb_id_on_different_card() -> None:
    facts = current_hardware_facts()
    set_observation(facts, "midi", "client 28: 'Roland Digital Piano' [type=kernel,card=3]")
    set_observation(facts, "midi_usb", "card=2 usb=0582:01b1")

    result = evaluate_hardware_acceptance(
        facts,
        expected_revision=REVISION,
        now="2026-09-04T07:05:00Z",
    )
    assert result["status"] == "fail"
    assert result["checks"]["midi"]["status"] == "fail"


def test_midi_anchor_rejects_user_roland_alias_with_unrelated_kernel_markers() -> None:
    facts = current_hardware_facts()
    set_observation(
        facts,
        "midi",
        "client 28: 'Roland Digital Piano' [type=user,pid=1234]\n"
        "client 32: 'Other Hardware' [type=kernel,card=3]",
    )
    set_observation(facts, "midi_usb", "card=3 usb=0582:01b1")

    result = evaluate_hardware_acceptance(
        facts,
        expected_revision=REVISION,
        now="2026-09-04T07:05:00Z",
    )
    assert result["status"] == "fail"
    assert result["checks"]["midi"]["status"] == "fail"


def test_wrong_probe_source_is_not_hardware_authority() -> None:
    facts = current_hardware_facts()
    facts["source"] = "caller-supplied:looks-valid"
    with pytest.raises(AcceptanceError, match="canonical read-only hardware probe"):
        evaluate_hardware_acceptance(
            facts,
            expected_revision=REVISION,
            now="2026-09-04T07:01:00Z",
        )


def test_stale_or_wrong_revision_is_a_hard_acceptance_error() -> None:
    with pytest.raises(AcceptanceError, match="stale"):
        evaluate_hardware_acceptance(
            current_hardware_facts(),
            expected_revision=REVISION,
            now="2026-09-04T08:00:00Z",
        )
    with pytest.raises(AcceptanceError, match="reviewed revision"):
        evaluate_hardware_acceptance(
            current_hardware_facts(),
            expected_revision="e" * 40,
            now="2026-09-04T07:01:00Z",
        )


def test_historical_gate_ab_reference_is_exact_and_never_current() -> None:
    assert HISTORICAL_PHYSICAL_EVIDENCE == {
        "classification": "historical-only",
        "archive_id": "20260902T112439Z-5eabac896f53",
        "head": "7fd5eed229fae95e839e6b9556cd7f4782506d2a",
        "purpose": "preserve pre-migration physical Gate A/B evidence without freshness claims",
    }


def test_live_probe_owns_commands_source_and_clock(monkeypatch) -> None:
    commands: list[tuple[str, ...]] = []

    def fake_run(argv: list[str]) -> str:
        commands.append(tuple(argv))
        if argv[0] == "nvidia-smi":
            return "NVIDIA GeForce RTX 4070 Ti SUPER, 0x270510DE, 595.84"
        if argv[0] == "aconnect":
            return "client 24: 'FP-30X' [type=kernel,card=2]"
        raise AssertionError(argv)

    monkeypatch.setattr(hardware, "_run_probe_command", fake_run)
    monkeypatch.setattr(
        hardware, "_read_probe_file", lambda path: " 2 [M2]: USB-Audio - MOTU M2"
    )
    monkeypatch.setattr(
        hardware, "_probe_midi_usb_identities", lambda midi: "card=2 usb=0582:01b1"
    )
    monkeypatch.setattr(hardware, "_utc_now", lambda: "2026-09-04T07:00:00Z")

    facts = probe_current_hardware(REVISION)
    assert facts["source"] == HARDWARE_SOURCE_ID
    assert facts["observedAt"] == "2026-09-04T07:00:00Z"
    assert commands == [
        tuple(PROBE_DEFINITION["gpu"]),
        tuple(PROBE_DEFINITION["midi"]),
    ]
    assert facts["observations"]["audio"]["value"].endswith("MOTU M2")
    assert facts["observations"]["midi_usb"]["value"] == "card=2 usb=0582:01b1"


def test_midi_usb_probe_resolves_only_kernel_card_headers(monkeypatch) -> None:
    seen: list[str] = []

    def fake_identity(card: str) -> str:
        seen.append(card)
        return f"card={card} usb=0582:01b1"

    monkeypatch.setattr(hardware, "_sound_card_usb_identity", fake_identity)
    result = hardware._probe_midi_usb_identities(
        "client 4: 'User Alias' [type=user,pid=12]\n"
        "client 28: 'Roland Digital Piano' [type=kernel,card=3]"
    )
    assert result == "card=3 usb=0582:01b1"
    assert seen == ["3"]


def test_probe_command_ignores_caller_path_and_loader_environment(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_subprocess_run(argv, **kwargs):
        captured["argv"] = argv
        captured["env"] = kwargs["env"]
        return hardware.subprocess.CompletedProcess(argv, 0, stdout="trusted output", stderr="")

    monkeypatch.setenv("PATH", "/tmp/attacker-controlled")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/attacker.so")
    monkeypatch.setattr(
        hardware,
        "_resolve_probe_executable",
        lambda executable: f"/trusted/{executable}",
    )
    monkeypatch.setattr(hardware.subprocess, "run", fake_subprocess_run)

    assert hardware._run_probe_command(["nvidia-smi", "--query-gpu=name"]) == "trusted output"
    assert captured["argv"] == ["/trusted/nvidia-smi", "--query-gpu=name"]
    assert captured["env"] == PROBE_DEFINITION["environment"]
    assert "LD_PRELOAD" not in captured["env"]
    assert "/tmp/attacker-controlled" not in captured["env"]["PATH"]


def test_probe_failure_becomes_explicit_fail_closed_observation(monkeypatch) -> None:
    monkeypatch.setattr(
        hardware,
        "_run_probe_command",
        lambda argv: "ERROR:probe-returncode:nvidia-smi:1"
        if argv[0] == "nvidia-smi"
        else "ERROR:probe-returncode:aconnect:1",
    )
    monkeypatch.setattr(
        hardware,
        "_read_probe_file",
        lambda path: "ERROR:read-failed:/proc/asound/cards:OSError",
    )
    monkeypatch.setattr(hardware, "_utc_now", lambda: "2026-09-04T07:00:00Z")

    facts = probe_current_hardware(REVISION)
    result = evaluate_hardware_acceptance(
        facts,
        expected_revision=REVISION,
        now="2026-09-04T07:00:01Z",
    )
    assert result["status"] == "fail"
    assert all(check["status"] == "fail" for check in result["checks"].values())


def test_production_cli_accepts_no_runtime_facts_or_clock_override(monkeypatch, capsys) -> None:
    monkeypatch.setattr(hardware, "_utc_now", lambda: "2026-09-04T07:00:00Z")
    monkeypatch.setattr(
        hardware, "probe_current_hardware", lambda revision: current_hardware_facts()
    )

    assert hardware.main(["--expected-revision", REVISION]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["kind"] == "heim_pc.nixos_hardware_probe_result"
    assert output["sourceRevision"] == REVISION
    assert output["acceptance"]["status"] == "pass"
    assert len(output["runtimeFactsSha256"]) == 64

    for forbidden in (
        ["--runtime-facts", "/tmp/forged.json"],
        ["--now", "2020-01-01T00:00:00Z"],
    ):
        with pytest.raises(SystemExit):
            hardware.main(["--expected-revision", REVISION, *forbidden])
