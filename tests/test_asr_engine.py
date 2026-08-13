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

    parakeet = policy["engines"]["parakeet"]
    assert parakeet["german_support"] is True
    assert parakeet["runnable"] is True
    assert parakeet["adapter"] == "transformers_tdt_cuda"
    assert parakeet["package"] == "transformers[torch,accelerate]==5.15.0"
    assert parakeet["package_version"] == "5.15.0"
    assert parakeet["dependencies"] == ["librosa==0.11.0"]
    assert parakeet["model_revision"] == "541d1f99c6b0c3cd0b11a95167540bb8edefd82b"
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


def test_parakeet_child_uses_transformers_tdt_offline_contract():
    source = asr_engine.PARAKEET_CHILD
    assert "AutoModelForTDT.from_pretrained" in source
    assert "AutoProcessor.from_pretrained" in source
    assert "revision=revision" in source
    assert "local_files_only=True" in source
    assert "model.generate" in source
    assert "processor.decode" in source
    assert "chunk_samples = 60 * 16000" in source


def test_parakeet_cache_requires_exact_revision_and_core_files(tmp_path, monkeypatch):
    policy = asr_engine.load_policy()
    revision = policy["engines"]["parakeet"]["model_revision"]
    hub = tmp_path / "hub"
    snapshot = hub / "models--nvidia--parakeet-tdt-0.6b-v3" / "snapshots" / revision
    snapshot.mkdir(parents=True)
    monkeypatch.setattr(asr_engine, "HF_HUB_CACHE_DIR", hub)
    for name in ("config.json", "model.safetensors", "processor_config.json"):
        (snapshot / name).write_bytes(b"x")
    assert asr_engine.model_cache_ready("parakeet") is False
    (snapshot / "tokenizer.json").write_bytes(b"x")
    assert asr_engine.model_cache_ready("parakeet") is True


def test_setup_parakeet_pins_package_and_model_revision(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    monkeypatch.setattr(asr_engine, "CACHE_DIR", cache)
    monkeypatch.setattr(asr_engine, "HF_HOME_DIR", cache / "hf_home")
    monkeypatch.setattr(asr_engine, "HF_HUB_CACHE_DIR", cache / "hf_home" / "hub")
    monkeypatch.setattr(asr_engine.shutil, "which", lambda _tool: "/usr/bin/uv")
    monkeypatch.setattr(asr_engine, "package_probe", lambda _engine: (True, "5.15.0"))
    monkeypatch.setattr(asr_engine, "model_cache_ready", lambda _engine: True)
    with patch.object(asr_engine.subprocess, "run") as run:
        asr_engine.cmd_setup(Namespace(engine="parakeet"))
    commands = [call.args[0] for call in run.call_args_list]
    assert any("transformers[torch,accelerate]==5.15.0" in command for command in commands)
    assert any("librosa==0.11.0" in command for command in commands)
    download = next(command for command in commands if len(command) > 2 and command[1] == "-c" and "snapshot_download" in command[2])
    assert "nvidia/parakeet-tdt-0.6b-v3" in download
    assert "541d1f99c6b0c3cd0b11a95167540bb8edefd82b" in download


def test_run_inference_parakeet_forces_offline_and_revision(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    venv = cache / "venv_parakeet" / "bin"
    venv.mkdir(parents=True)
    (venv / "python").write_text("", encoding="utf-8")
    monkeypatch.setattr(asr_engine, "CACHE_DIR", cache)
    monkeypatch.setattr(asr_engine, "HF_HOME_DIR", cache / "hf_home")
    monkeypatch.setattr(asr_engine, "HF_HUB_CACHE_DIR", cache / "hf_home" / "hub")
    monkeypatch.setattr(asr_engine, "model_cache_ready", lambda _engine: True)
    observed = {}
    def child(argv, env):
        observed["argv"] = argv
        observed["env"] = env
        return 0, json.dumps({"text": "x", "language": None, "version": "5.15.0"}), "", 512
    monkeypatch.setattr(asr_engine, "run_child_with_gpu_observation", child)
    conf = asr_engine.load_policy()["engines"]["parakeet"]
    result = asr_engine.run_inference("parakeet", conf, tmp_path / "a.wav")
    assert result["text"] == "x"
    assert observed["env"]["HF_HUB_OFFLINE"] == "1"
    assert observed["env"]["TRANSFORMERS_OFFLINE"] == "1"
    assert conf["model"] in observed["argv"]
    assert conf["model_revision"] in observed["argv"]



def _transcript(engine: str, text: str, *, segments=None):
    policy = asr_engine.load_policy()
    conf = policy["engines"].get(engine) or policy["cloud_engines"][engine]
    return asr_engine.normalize_transcript_result(
        provider="local" if engine in policy["engines"] else "openai",
        engine_name=engine,
        engine_conf=conf,
        payload={
            "text": text,
            "language": "de",
            "version": "test",
            "segments": segments,
        },
    )


def _write_golden_manifest(root: Path, count: int, *, reference_kind="human-corrected") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    categories = asr_engine.load_golden_contract()["required_quality_categories"]
    items = []
    for index in range(count):
        audio = root / f"audio-{index}.wav"
        reference = root / f"reference-{index}.txt"
        audio.write_bytes(f"audio-{index}".encode())
        reference.write_text(f"Referenz {index}", encoding="utf-8")
        items.append(
            {
                "id": f"sample-{index}",
                "categories": [categories[index % len(categories)]],
                "audio": audio.name,
                "reference": reference.name,
                "reference_kind": reference_kind,
            }
        )
    manifest = root / "golden.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "heim-pc.asr-golden-corpus",
                "items": items,
            }
        ),
        encoding="utf-8",
    )
    return manifest


def test_policy_local_first_and_cloud_is_explicit_only():
    policy = asr_engine.load_policy()
    assert policy["default_engine"] == "qwen"
    routing = policy["routing"]
    assert routing["default_strategy"] == "local-first"
    assert routing["default_local_engine"] == "qwen"
    assert routing["automatic_cloud_escalation"] is False
    assert routing["local_engines"] == ["qwen", "parakeet", "faster-whisper"]
    assert policy["invariants"]["paid_or_metered_api_allowed"] is False
    assert policy["invariants"]["automatic_cloud_escalation_allowed"] is False
    assert policy["invariants"]["metered_cloud_allowed_with_explicit_per_run_opt_in"] is True
    assert policy["invariants"]["paid_or_metered_api_semantics"] == "not-allowed-without-explicit-per-run-opt-in"
    for model in (
        "gpt-4o-transcribe",
        "gpt-4o-mini-transcribe",
        "gpt-4o-transcribe-diarize",
    ):
        cloud = policy["cloud_engines"][model]
        assert cloud["provider"] == "openai"
        assert cloud["cost"] == "metered"
        assert cloud["requires_explicit_metered_opt_in"] is True


def test_normalized_result_does_not_invent_unsupported_metadata():
    result = asr_engine.normalize_transcript_result(
        provider="local",
        engine_name="qwen",
        engine_conf=asr_engine.load_policy()["engines"]["qwen"],
        payload={"text": "Hallo", "language": None, "version": "0.0.6"},
    )
    assert result["kind"] == "heim-pc.asr-transcript"
    assert result["language"] is None
    assert result["segments"] == []
    assert result["model_revision"] is None


def test_faster_whisper_child_exports_real_segment_timestamps():
    source = asr_engine.FASTER_WHISPER_CHILD
    assert "segment_items" in source
    assert '"start": float(segment.start)' in source
    assert '"end": float(segment.end)' in source
    assert '"speaker": None' in source


def test_cloud_without_metered_opt_in_never_reaches_network(tmp_path, monkeypatch):
    audio = tmp_path / "a.wav"
    audio.write_bytes(b"audio")
    called = False

    def forbidden(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("network must not be reached")

    monkeypatch.setattr(asr_engine.urllib.request, "urlopen", forbidden)
    monkeypatch.setenv("OPENAI_API_KEY", "should-not-be-read-for-authorization")
    with pytest.raises(asr_engine.CloudCostAuthorizationError, match="allow-metered-cloud"):
        asr_engine.run_openai_transcription(
            "gpt-4o-transcribe", audio, allow_metered_cloud=False
        )
    assert called is False


def test_cloud_opt_in_without_key_still_fails_before_network(tmp_path, monkeypatch):
    audio = tmp_path / "a.wav"
    audio.write_bytes(b"audio")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with patch.object(asr_engine.urllib.request, "urlopen") as urlopen:
        with pytest.raises(asr_engine.CloudCostAuthorizationError, match="OPENAI_API_KEY"):
            asr_engine.run_openai_transcription(
                "gpt-4o-transcribe", audio, allow_metered_cloud=True
            )
        urlopen.assert_not_called()


def test_openai_adapter_normalizes_json_without_leaking_key(tmp_path, monkeypatch):
    audio = tmp_path / "a.wav"
    audio.write_bytes(b"audio")
    monkeypatch.setenv("OPENAI_API_KEY", "private-test-key")
    observed = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({"text": "Hallo Cloud", "language": "de"}).encode()

    def fake_urlopen(request, timeout):
        observed["authorization"] = request.headers.get("Authorization")
        observed["timeout"] = timeout
        return Response()

    monkeypatch.setattr(asr_engine.urllib.request, "urlopen", fake_urlopen)
    result = asr_engine.run_openai_transcription(
        "gpt-4o-transcribe", audio, allow_metered_cloud=True
    )
    assert result["provider"] == "openai"
    assert result["engine"] == "gpt-4o-transcribe"
    assert result["text"] == "Hallo Cloud"
    assert result["segments"] == []
    assert "private-test-key" not in json.dumps(result)
    assert observed["authorization"] == "Bearer private-test-key"


def test_openai_diarized_result_preserves_speaker_segments(tmp_path, monkeypatch):
    audio = tmp_path / "a.wav"
    audio.write_bytes(b"audio")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps(
                {
                    "text": "A B",
                    "segments": [
                        {"start": 0.0, "end": 1.2, "speaker": "A", "text": "A"},
                        {"start": 1.2, "end": 2.0, "speaker": "B", "text": "B"},
                    ],
                }
            ).encode()

    monkeypatch.setattr(asr_engine.urllib.request, "urlopen", lambda *_a, **_k: Response())
    result = asr_engine.run_openai_transcription(
        "gpt-4o-transcribe-diarize", audio, allow_metered_cloud=True
    )
    assert [item["speaker"] for item in result["segments"]] == ["A", "B"]
    assert result["segments"][0]["start"] == 0.0


def test_local_first_router_calls_only_primary_local(tmp_path, monkeypatch):
    audio = tmp_path / "a.wav"
    audio.write_bytes(b"audio")
    calls = []

    def local(engine, _audio):
        calls.append(engine)
        return _transcript(engine, "lokal")

    monkeypatch.setattr(asr_engine, "run_local_transcription", local)
    with patch.object(asr_engine, "run_openai_transcription") as cloud:
        result = asr_engine.route_transcription(audio)
    assert calls == ["qwen"]
    assert result["selected"]["engine"] == "qwen"
    assert result["cloud_used"] is False
    cloud.assert_not_called()


def test_dual_local_disagreement_only_recommends_cloud(tmp_path, monkeypatch):
    audio = tmp_path / "a.wav"
    audio.write_bytes(b"audio")

    def local(engine, _audio):
        text = "eins zwei drei" if engine == "qwen" else "ganz anderer text"
        return _transcript(engine, text)

    monkeypatch.setattr(asr_engine, "run_local_transcription", local)
    with patch.object(asr_engine, "run_openai_transcription") as cloud:
        result = asr_engine.route_transcription(
            audio, strategy="dual-local", disagreement_threshold=0.1
        )
    assert result["cloud_recommended"] is True
    assert result["cloud_used"] is False
    assert result["selected"]["engine"] == "qwen"
    cloud.assert_not_called()



def test_dual_local_evidence_is_digest_only(tmp_path, monkeypatch):
    audio = tmp_path / "private-name.wav"
    audio.write_bytes(b"private-audio")
    monkeypatch.setattr(asr_engine, "get_repo_head", lambda: "a" * 40)
    monkeypatch.setattr(asr_engine, "get_repo_dirty", lambda: False)
    monkeypatch.setattr(asr_engine, "policy_sha256", lambda: "b" * 64)
    first = _transcript("qwen", "geheimer erster text")
    second = _transcript("parakeet", "geheimer zweiter text")
    result = {
        "strategy": "dual-local",
        "comparison": {
            "primary": first,
            "secondary": second,
            "disagreement_rate": 0.5,
            "threshold": 0.18,
        },
        "cloud_recommended": True,
        "cloud_used": False,
    }
    evidence = asr_engine.dual_local_evidence(audio, result)
    serialized = json.dumps(evidence, ensure_ascii=False)
    assert evidence["primary"]["transcript_sha256"]
    assert evidence["secondary"]["transcript_sha256"]
    assert "geheimer" not in serialized
    assert "private-name.wav" not in serialized
    assert str(tmp_path) not in serialized
    assert evidence["audio_sha256"] == asr_engine.file_sha256(audio)


def test_dual_local_explicit_escalation_still_requires_metered_gate(tmp_path, monkeypatch):
    audio = tmp_path / "a.wav"
    audio.write_bytes(b"audio")

    def local(engine, _audio):
        return _transcript(engine, "eins" if engine == "qwen" else "zwei")

    monkeypatch.setattr(asr_engine, "run_local_transcription", local)
    with pytest.raises(asr_engine.CloudCostAuthorizationError):
        asr_engine.route_transcription(
            audio,
            strategy="dual-local",
            disagreement_threshold=0.0,
            escalate_to_cloud=True,
            allow_metered_cloud=False,
        )


def test_golden_manifest_inside_repo_is_rejected(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(asr_engine, "REPO_ROOT", repo)
    manifest = _write_golden_manifest(repo, 1)
    with pytest.raises(ValueError, match="must remain outside"):
        asr_engine.golden_manifest_summary(manifest)


def test_golden_manifest_rejects_machine_generated_reference(tmp_path):
    manifest = _write_golden_manifest(tmp_path, 1, reference_kind="machine-generated")
    with pytest.raises(ValueError, match="human-corrected"):
        asr_engine.golden_manifest_summary(manifest)


def test_golden_quality_gate_requires_20_samples_and_category_coverage(tmp_path):
    small = _write_golden_manifest(tmp_path / "small", 5)
    small_summary = asr_engine.golden_manifest_summary(small)
    assert small_summary["sample_count"] == 5
    assert small_summary["quality_gate_eligible"] is False

    full_root = tmp_path / "full"
    full_root.mkdir()
    full = _write_golden_manifest(full_root, 20)
    full_summary = asr_engine.golden_manifest_summary(full)
    assert full_summary["sample_count"] == 20
    assert full_summary["missing_quality_categories"] == []
    assert full_summary["quality_gate_eligible"] is True
    assert full_summary["automatic_default_change_allowed"] is False


def test_golden_benchmark_evidence_contains_no_private_text_or_paths(tmp_path, monkeypatch):
    corpus = tmp_path / "private-corpus"
    corpus.mkdir()
    manifest = _write_golden_manifest(corpus, 5)
    monkeypatch.setattr(asr_engine, "get_repo_head", lambda: "a" * 40)
    monkeypatch.setattr(asr_engine, "get_repo_dirty", lambda: False)
    monkeypatch.setattr(asr_engine, "policy_sha256", lambda: "b" * 64)

    def measurement(engine, _audio, _reference):
        return {
            "outcome": "success",
            "model": engine,
            "model_revision": None,
            "backend_version": "test",
            "detected_language": "de",
            "wer": 0.1 if engine == "qwen" else 0.2,
            "cer": 0.05,
            "wall_time_seconds": 0.1,
            "rtf": 0.1,
            "gpu_memory_used_peak_mib_observed": 100,
        }

    monkeypatch.setattr(asr_engine, "_golden_engine_measurement", measurement)
    evidence = asr_engine.run_golden_benchmark(manifest, ["qwen", "parakeet"])
    serialized = json.dumps(evidence, ensure_ascii=False)
    assert evidence["quality_gate_eligible"] is False
    assert evidence["best_local_engine_by_mean_wer"] is None
    assert evidence["current_default_engine"] == "qwen"
    assert "Referenz" not in serialized
    assert "sample-" not in serialized
    assert str(corpus) not in serialized
    assert "audio-0.wav" not in serialized
    assert "reference-0.txt" not in serialized


def test_parser_exposes_cloud_only_as_explicit_flags():
    parser = asr_engine.build_parser()
    args = parser.parse_args(["route", "--audio", "/tmp/a.wav"])
    assert args.strategy == "local-first"
    assert args.escalate_to_cloud is False
    assert args.allow_metered_cloud is False
    assert asr_engine.load_policy()["default_engine"] == "qwen"
