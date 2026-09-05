from __future__ import annotations

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
        },
    )


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
    facts["observations"]["midi"]["value"] = "no MIDI device"
    import hashlib

    facts["observations"]["midi"]["sha256"] = hashlib.sha256(
        b"no MIDI device"
    ).hexdigest()
    facts["binding"]["observationsSha256"] = sha256_json(facts["observations"])

    result = evaluate_hardware_acceptance(
        facts,
        expected_revision=REVISION,
        now="2026-09-04T07:05:00Z",
    )
    assert result["status"] == "fail"
    assert result["checks"]["midi"]["status"] == "fail"
    assert result["historicalEvidence"]["classification"] == "historical-only"
    assert result["historicalEvidenceIsCurrent"] is False


def test_midi_anchor_requires_fp30x_kernel_client_on_same_line() -> None:
    facts = current_hardware_facts()
    midi = (
        "client 24: 'FP-30X' [type=user,pid=1234]\n"
        "client 32: 'Other Hardware' [type=kernel,card=2]"
    )
    import hashlib

    facts["observations"]["midi"]["value"] = midi
    facts["observations"]["midi"]["sha256"] = hashlib.sha256(midi.encode()).hexdigest()
    facts["binding"]["observationsSha256"] = sha256_json(facts["observations"])

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
    monkeypatch.setattr(hardware, "_utc_now", lambda: "2026-09-04T07:00:00Z")

    facts = probe_current_hardware(REVISION)
    assert facts["source"] == HARDWARE_SOURCE_ID
    assert facts["observedAt"] == "2026-09-04T07:00:00Z"
    assert commands == [
        tuple(PROBE_DEFINITION["gpu"]),
        tuple(PROBE_DEFINITION["midi"]),
    ]
    assert facts["observations"]["audio"]["value"].endswith("MOTU M2")


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
