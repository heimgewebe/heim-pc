import json
import sys
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import asr_engine


def test_policy_contract_and_default():
    policy = asr_engine.load_policy()
    assert policy["id"] == "asr-engine-policy.v1"
    assert policy["default_engine"] == "qwen"
    assert policy["invariants"]["zero_incremental_cost"] is True
    assert policy["invariants"]["paid_or_metered_api_allowed"] is False

    qwen = policy["engines"]["qwen"]
    assert qwen["model"] == "Qwen/Qwen3-ASR-1.7B"
    assert qwen["package"] == "qwen-asr==0.0.6"
    assert qwen["license"] == "Apache-2.0"
    assert qwen["german_support"] is True
    assert qwen["runnable"] is True

    comparator = policy["engines"]["faster-whisper"]
    assert comparator["model"] == "Systran/faster-whisper-large-v3"
    assert comparator["package"] == "faster-whisper==1.2.1"
    assert comparator["legacy_comparator"] is True

    assert policy["engines"]["parakeet"]["german_support"] is True
    assert policy["engines"]["parakeet"]["runnable"] is False
    assert policy["engines"]["moss"]["remote_code_risk"] is True

    cohere = policy["engines"]["cohere"]
    assert cohere["model"] == "CohereLabs/cohere-transcribe-03-2026"
    assert cohere["type"] == "local"
    assert cohere["cost"] == "zero"
    assert cohere["gated"] is True
    assert cohere["manual_only"] is True


def test_gated_and_unadapted_engines_fail_closed():
    policy = asr_engine.load_policy()
    with pytest.raises(ValueError, match="gated"):
        asr_engine.check_runnable(policy["engines"]["cohere"], "cohere")
    with pytest.raises(ValueError, match="no validated local adapter"):
        asr_engine.check_runnable(policy["engines"]["moss"], "moss")
    with pytest.raises(ValueError, match="no validated local adapter"):
        asr_engine.check_runnable(policy["engines"]["parakeet"], "parakeet")


def test_nonzero_cost_fails_closed():
    engine = asr_engine.load_policy()["engines"]["qwen"].copy()
    engine["cost"] = "metered"
    with pytest.raises(ValueError, match="zero-cost"):
        asr_engine.check_runnable(engine, "qwen")


def test_no_simulation_or_dry_run_surface():
    parser = asr_engine.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["benchmark", "--audio", "/tmp/a.wav", "--dry-run"])
    source = Path(asr_engine.__file__).read_text(encoding="utf-8").casefold()
    assert "simulating inference" not in source
    assert "dummy implementation" not in source


def test_qwen_child_uses_official_qwen_asr_api():
    assert "Qwen3ASRModel.from_pretrained" in asr_engine.QWEN_CHILD
    assert 'dtype=torch.bfloat16' in asr_engine.QWEN_CHILD
    assert 'device_map="cuda:0"' in asr_engine.QWEN_CHILD
    assert "model.transcribe" in asr_engine.QWEN_CHILD
    assert '"ffmpeg"' in asr_engine.QWEN_CHILD
    assert '"-ar", "16000"' in asr_engine.QWEN_CHILD
    assert "audio=(audio, 16000)" in asr_engine.QWEN_CHILD
    assert "result.text" in asr_engine.QWEN_CHILD


def test_wer_cer_metrics():
    wer, cer = asr_engine.compute_wer_cer("Hallo Welt", "hallo Welt")
    assert wer == 0.0
    assert cer == 0.0
    wer, cer = asr_engine.compute_wer_cer("eins zwei", "eins drei")
    assert wer == 0.5
    assert 0.0 < cer <= 1.0


def test_benchmark_success_persists_metrics_not_text(tmp_path, monkeypatch):
    monkeypatch.setattr(asr_engine, "STATE_DIR", tmp_path / "state")
    audio = tmp_path / "private-audio.wav"
    audio.write_bytes(b"audio bytes")
    reference = tmp_path / "reference.txt"
    reference.write_text("Hallo Welt", encoding="utf-8")

    monkeypatch.setattr(asr_engine, "get_audio_duration", lambda _path: 2.0)
    monkeypatch.setattr(asr_engine, "get_repo_head", lambda: "a" * 40)
    monkeypatch.setattr(asr_engine, "get_repo_dirty", lambda: False)
    monkeypatch.setattr(asr_engine, "policy_sha256", lambda: "b" * 64)
    monkeypatch.setattr(
        asr_engine,
        "run_inference",
        lambda *_args: {
            "text": "Hallo Welt",
            "language": "German",
            "version": "0.0.6",
            "gpu_memory_used_peak_mib_observed": 4321,
        },
    )

    asr_engine.cmd_benchmark(
        Namespace(engine="qwen", audio=audio, reference=reference)
    )
    digest = asr_engine.file_sha256(audio)
    evidence_path = asr_engine.STATE_DIR / f"{digest}_qwen.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    serialized = evidence_path.read_text(encoding="utf-8")

    assert evidence["outcome"] == "success"
    assert evidence["wer"] == 0.0
    assert evidence["cer"] == 0.0
    assert evidence["reference_digest"] == asr_engine.file_sha256(reference)
    assert evidence["rtf"] >= 0.0
    assert evidence["repo_dirty"] is False
    assert evidence["adapter_sha256"] == asr_engine.file_sha256(Path(asr_engine.__file__).resolve())
    assert evidence["gpu_memory_used_peak_mib_observed"] == 4321
    assert "Hallo Welt" not in serialized
    assert "private-audio.wav" not in serialized
    assert "reference.txt" not in serialized
    assert "transcript" not in evidence
    assert "reference_text" not in evidence


def test_benchmark_failure_writes_evidence_and_exits_nonzero_semantics(tmp_path, monkeypatch):
    monkeypatch.setattr(asr_engine, "STATE_DIR", tmp_path / "state")
    audio = tmp_path / "audio.wav"
    audio.write_bytes(b"audio")
    monkeypatch.setattr(asr_engine, "get_audio_duration", lambda _path: 1.0)
    monkeypatch.setattr(asr_engine, "get_repo_head", lambda: "c" * 40)
    monkeypatch.setattr(asr_engine, "get_repo_dirty", lambda: True)
    monkeypatch.setattr(asr_engine, "policy_sha256", lambda: "d" * 64)
    monkeypatch.setattr(asr_engine, "current_gpu_memory_mib", lambda: 100)

    def fail(*_args):
        raise asr_engine.BackendError("private backend detail")

    monkeypatch.setattr(asr_engine, "run_inference", fail)
    with pytest.raises(asr_engine.BackendError, match="Benchmark failed"):
        asr_engine.cmd_benchmark(Namespace(engine="qwen", audio=audio, reference=None))

    digest = asr_engine.file_sha256(audio)
    evidence_path = asr_engine.STATE_DIR / f"{digest}_qwen.json"
    serialized = evidence_path.read_text(encoding="utf-8")
    evidence = json.loads(serialized)
    assert evidence["outcome"] == "error"
    assert evidence["failure_class"] == "BackendError"
    assert "private backend detail" not in serialized


def test_transcribe_outputs_only_to_stdout(tmp_path, monkeypatch, capsys):
    state = tmp_path / "state"
    monkeypatch.setattr(asr_engine, "STATE_DIR", state)
    audio = tmp_path / "audio.wav"
    audio.write_bytes(b"audio")
    monkeypatch.setattr(
        asr_engine,
        "run_inference",
        lambda *_args: {
            "text": "nur stdout",
            "language": "German",
            "version": "0.0.6",
            "gpu_memory_used_peak_mib_observed": 1,
        },
    )
    asr_engine.cmd_transcribe(Namespace(engine="qwen", audio=audio))
    assert capsys.readouterr().out == "nur stdout\n"
    assert not state.exists()


def test_doctor_is_read_only(monkeypatch):
    monkeypatch.setattr(asr_engine.shutil, "which", lambda _tool: "/usr/bin/tool")
    monkeypatch.setattr(asr_engine, "package_probe", lambda _engine: (True, "0.0.6"))
    monkeypatch.setattr(asr_engine, "model_cache_ready", lambda _engine: True)
    with patch.object(asr_engine.subprocess, "run") as run:
        assert asr_engine.cmd_doctor(Namespace(engine="qwen")) is True
        run.assert_not_called()


def test_setup_is_explicit_and_uses_isolated_qwen_package(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    monkeypatch.setattr(asr_engine, "CACHE_DIR", cache)
    monkeypatch.setattr(asr_engine, "HF_HOME_DIR", cache / "hf_home")
    monkeypatch.setattr(asr_engine, "HF_HUB_CACHE_DIR", cache / "hf_home" / "hub")
    monkeypatch.setattr(asr_engine.shutil, "which", lambda _tool: "/usr/bin/uv")
    monkeypatch.setattr(asr_engine, "package_probe", lambda _engine: (True, "0.0.6"))
    monkeypatch.setattr(asr_engine, "model_cache_ready", lambda _engine: True)

    with patch.object(asr_engine.subprocess, "run") as run:
        asr_engine.cmd_setup(Namespace(engine="qwen"))
    commands = [call.args[0] for call in run.call_args_list]
    assert commands[0][:4] == ["uv", "venv", "--python", "3.12"]
    assert any("qwen-asr==0.0.6" in command for command in commands)
    assert any(
        len(command) > 2 and command[1] == "-c" and "snapshot_download" in command[2]
        for command in commands
    )


def test_run_inference_forces_offline_mode(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    venv = cache / "venv_qwen" / "bin"
    venv.mkdir(parents=True)
    python = venv / "python"
    python.write_text("", encoding="utf-8")
    monkeypatch.setattr(asr_engine, "CACHE_DIR", cache)
    monkeypatch.setattr(asr_engine, "HF_HOME_DIR", cache / "hf_home")
    monkeypatch.setattr(asr_engine, "HF_HUB_CACHE_DIR", cache / "hf_home" / "hub")
    monkeypatch.setattr(asr_engine, "model_cache_ready", lambda _engine: True)

    observed = {}

    def child(argv, env):
        observed["argv"] = argv
        observed["env"] = env
        return 0, json.dumps({"text": "x", "language": "German", "version": "0.0.6"}), "", 42

    monkeypatch.setattr(asr_engine, "run_child_with_gpu_observation", child)
    result = asr_engine.run_inference(
        "qwen", asr_engine.load_policy()["engines"]["qwen"], tmp_path / "a.wav"
    )
    assert result["text"] == "x"
    assert observed["env"]["HF_HUB_OFFLINE"] == "1"
    assert observed["env"]["TRANSFORMERS_OFFLINE"] == "1"
    assert "Qwen3ASRModel.from_pretrained" in observed["argv"][2]


def test_qwen_cache_requires_all_indexed_shards(tmp_path, monkeypatch):
    hub = tmp_path / "hub"
    snapshot = hub / "models--Qwen--Qwen3-ASR-1.7B" / "snapshots" / "rev"
    snapshot.mkdir(parents=True)
    (snapshot / "config.json").write_text("{}", encoding="utf-8")
    (snapshot / "model.safetensors.index.json").write_text(
        json.dumps({"weight_map": {"a": "model-00001-of-00002.safetensors", "b": "model-00002-of-00002.safetensors"}}),
        encoding="utf-8",
    )
    (snapshot / "model-00002-of-00002.safetensors").write_bytes(b"two")
    monkeypatch.setattr(asr_engine, "HF_HUB_CACHE_DIR", hub)
    assert asr_engine.model_cache_ready("qwen") is False
    (snapshot / "model-00001-of-00002.safetensors").write_bytes(b"one")
    assert asr_engine.model_cache_ready("qwen") is True


def test_faster_whisper_cache_requires_model_and_metadata(tmp_path, monkeypatch):
    root = tmp_path / "fw"
    snapshot = root / "models--Systran--faster-whisper-large-v3" / "snapshots" / "rev"
    snapshot.mkdir(parents=True)
    (snapshot / "config.json").write_text("{}", encoding="utf-8")
    (snapshot / "tokenizer.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(asr_engine, "FASTER_WHISPER_MODEL_DIR", root)
    assert asr_engine.model_cache_ready("faster-whisper") is False
    (snapshot / "model.bin").write_bytes(b"model")
    assert asr_engine.model_cache_ready("faster-whisper") is True
