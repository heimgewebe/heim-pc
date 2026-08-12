import json
from pathlib import Path
import pytest
import sys
import subprocess

# We can import functions from scripts.asr_engine directly if we put scripts in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import asr_engine

def test_load_policy():
    policy = asr_engine.load_policy()
    assert policy["id"] == "asr-engine-policy.v1"
    assert "engines" in policy
    
    # Test default selection
    assert policy["default_engine"] == "qwen"
    assert policy["engines"]["qwen"]["model"] == "Qwen3-ASR-1.7B"

def test_zero_cost_invariant():
    policy = asr_engine.load_policy()
    qwen = policy["engines"]["qwen"]
    assert qwen["cost"] == "zero"
    
    cohere = policy["engines"]["cohere"]
    assert cohere["cost"] == "metered"
    
    # ensure exception on non-zero cost
    with pytest.raises(ValueError, match="violates zero-cost"):
        asr_engine.check_gated_and_cost(cohere, "cohere")

def test_gated_rejection():
    policy = asr_engine.load_policy()
    cohere = policy["engines"]["cohere"]
    assert cohere["gated"] is True
    
    # Even if cost was artificially set to zero, gated should block
    cohere_dummy = cohere.copy()
    cohere_dummy["cost"] = "zero"
    with pytest.raises(ValueError, match="is gated and rejected"):
        asr_engine.check_gated_and_cost(cohere_dummy, "cohere")

def test_benchmark_dry_run_and_privacy_safe_evidence(tmp_path, monkeypatch):
    # Mock STATE_DIR to be a temp dir
    monkeypatch.setattr(asr_engine, "STATE_DIR", tmp_path)
    
    # Create dummy audio
    audio_file = tmp_path / "dummy.mp4"
    audio_file.write_bytes(b"dummy audio content")
    
    class DummyArgs:
        command = "benchmark"
        audio = audio_file
        engine = "qwen"
        dry_run = True
    
    asr_engine.cmd_benchmark(DummyArgs())
    
    # Verify evidence was written
    import hashlib
    h = hashlib.sha256(b"dummy audio content").hexdigest()
    
    evidence_file = tmp_path / f"{h}_qwen.json"
    assert evidence_file.exists(), "Privacy-safe evidence file must be created"
    
    with open(evidence_file, "r") as f:
        evidence = json.load(f)
        
    assert evidence["input_digest"] == h
    assert evidence["engine"] == "qwen"
    assert evidence["model"] == "Qwen3-ASR-1.7B"
    assert evidence["repo_identity"] == "heim-pc"
    assert evidence["outcome"] == "success"
    # Ensure reference text is not persisted
    assert "reference_text" not in evidence
    assert "transcript" not in evidence

def test_doctor(caplog):
    import logging
    caplog.set_level(logging.INFO)
    class DummyArgs:
        command = "doctor"
    asr_engine.cmd_doctor(DummyArgs())
    # doctor must not download weights, just lists status
    assert "Doctor complete. No model weights were downloaded." in caplog.text
