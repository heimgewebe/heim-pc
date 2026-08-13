#!/usr/bin/env python3
"""Canonical local-first ASR CLI for the heim-pc."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import threading
import time
import unicodedata
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "manifest" / "asr-engine-policy.v1.json"
TRANSCRIPT_CONTRACT_PATH = REPO_ROOT / "manifest" / "asr-transcript-contract.v1.json"
GOLDEN_CONTRACT_PATH = REPO_ROOT / "manifest" / "asr-golden-corpus-contract.v1.json"
STATE_DIR = Path.home() / ".local" / "state" / "heim-pc" / "asr-open-engine"
CACHE_DIR = Path.home() / ".local" / "cache" / "heim-pc" / "asr-open-engine"
HF_HOME_DIR = CACHE_DIR / "hf_home"
HF_HUB_CACHE_DIR = HF_HOME_DIR / "hub"
FASTER_WHISPER_MODEL_DIR = CACHE_DIR / "fw_models"
FASTER_WHISPER_SIZE = "large-v3"

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


class BackendError(RuntimeError):
    """An ASR backend could not complete inference."""


class CloudCostAuthorizationError(RuntimeError):
    """A metered cloud path was requested without explicit per-run authorization."""


def load_json_contract(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Contract {path.name} must be a JSON object")
    return value


def load_transcript_contract() -> dict[str, Any]:
    return load_json_contract(TRANSCRIPT_CONTRACT_PATH)


def load_golden_contract() -> dict[str, Any]:
    return load_json_contract(GOLDEN_CONTRACT_PATH)


def get_cloud_engine(policy: dict[str, Any], model_name: str) -> dict[str, Any]:
    engines = policy.get("cloud_engines", {})
    if model_name not in engines:
        raise ValueError(f"Unknown cloud ASR model: {model_name}")
    value = engines[model_name]
    if not isinstance(value, dict):
        raise ValueError(f"Cloud ASR model {model_name} has invalid policy")
    return value


def _optional_number(value: Any) -> float | None:
    if value is None:
        return None
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise BackendError("ASR segment timestamp is invalid")
    return float(value)


def normalize_segments(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise BackendError("ASR segments must be a list when present")
    segments: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("text"), str):
            raise BackendError("ASR segment is invalid")
        speaker = item.get("speaker")
        if speaker is not None and not isinstance(speaker, str):
            raise BackendError("ASR segment speaker is invalid")
        segments.append({
            "start": _optional_number(item.get("start")),
            "end": _optional_number(item.get("end")),
            "speaker": speaker,
            "text": item["text"],
        })
    return segments


def normalize_transcript_result(*, provider: str, engine_name: str, engine_conf: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    text = payload.get("text")
    if not isinstance(text, str):
        raise BackendError("ASR backend returned no transcript text")
    language = payload.get("language")
    if language is not None and not isinstance(language, str):
        raise BackendError("ASR backend returned invalid language metadata")
    version = payload.get("version")
    if version is not None and not isinstance(version, str):
        raise BackendError("ASR backend returned invalid version metadata")
    result = {
        "schema_version": 1,
        "kind": "heim-pc.asr-transcript",
        "provider": provider,
        "engine": engine_name,
        "model": engine_conf.get("model"),
        "model_revision": engine_conf.get("model_revision"),
        "backend_version": version,
        "text": text,
        "language": language,
        "segments": normalize_segments(payload.get("segments")),
    }
    validate_transcript_result(result)
    return result


def validate_transcript_result(result: dict[str, Any]) -> None:
    contract = load_transcript_contract()
    if result.get("schema_version") != 1 or result.get("kind") != contract.get("kind"):
        raise BackendError("Transcript result contract identity mismatch")
    missing = [key for key in contract.get("required_fields", []) if key not in result]
    if missing:
        raise BackendError(f"Transcript result missing fields: {missing}")
    if not isinstance(result.get("text"), str):
        raise BackendError("Transcript result text is invalid")
    normalize_segments(result.get("segments"))


def validate_policy(policy: dict[str, Any]) -> None:
    invariants = policy.get("invariants")
    if not isinstance(invariants, dict):
        raise ValueError("ASR policy invariants must be an object")
    ambiguous_legacy_flags = {
        "zero_incremental_cost",
        "local_inference_only",
        "paid_or_metered_api_allowed",
    }
    present = sorted(ambiguous_legacy_flags.intersection(invariants))
    if present:
        raise ValueError(f"ASR policy contains ambiguous legacy cost flags: {present}")
    if invariants.get("default_path_zero_incremental_cost") is not True:
        raise ValueError("ASR default path must remain zero-incremental-cost")
    if invariants.get("default_path_local_inference_only") is not True:
        raise ValueError("ASR default path must remain local-only")
    if invariants.get("paid_or_metered_api_allowed_without_explicit_per_run_opt_in") is not False:
        raise ValueError("Metered ASR must remain blocked without explicit per-run opt-in")
    if invariants.get("metered_cloud_requires_explicit_per_run_opt_in") is not True:
        raise ValueError("Metered cloud ASR must require explicit per-run opt-in")
    if invariants.get("metered_cloud_allowed_with_explicit_per_run_opt_in") is not True:
        raise ValueError("Explicit per-run metered cloud ASR must remain representable")
    if invariants.get("automatic_cloud_escalation_allowed") is not False:
        raise ValueError("Automatic cloud escalation must remain disabled")

    engines = policy.get("engines")
    routing = policy.get("routing")
    if not isinstance(engines, dict) or not isinstance(routing, dict):
        raise ValueError("ASR policy engines and routing must be objects")
    default_engine = policy.get("default_engine")
    default_local = routing.get("default_local_engine")
    fallback_local = routing.get("local_fallback_engine")
    secondary_local = routing.get("dual_local_default_secondary")
    speed_local = routing.get("speed_local_engine")
    local_engines = routing.get("local_engines")
    if default_engine != default_local:
        raise ValueError("ASR default engine and default local route must match")
    if not isinstance(local_engines, list) or not local_engines:
        raise ValueError("ASR routing local_engines must be a non-empty list")
    for role, engine_name in (
        ("default", default_engine),
        ("fallback", fallback_local),
        ("dual-local secondary", secondary_local),
        ("speed", speed_local),
    ):
        if not isinstance(engine_name, str) or engine_name not in engines:
            raise ValueError(f"ASR {role} engine is not registered")
        if engine_name not in local_engines:
            raise ValueError(f"ASR {role} engine is not in local_engines")
    if default_engine == fallback_local or default_engine == secondary_local:
        raise ValueError("ASR fallback/secondary must differ from the default engine")

    selection = policy.get("selection")
    if not isinstance(selection, dict):
        raise ValueError("ASR policy selection must be an object")
    if selection.get("quality_default_engine") != default_engine:
        raise ValueError("ASR selection quality default must match the routed default")
    if selection.get("quality_fallback_engine") != fallback_local:
        raise ValueError("ASR selection quality fallback must match routing")
    if selection.get("speed_low_vram_engine") != speed_local:
        raise ValueError("ASR selection speed engine must match routing")
    if selection.get("automatic_default_change_allowed") is not False:
        raise ValueError("ASR selection may not authorize automatic default mutation")


def load_policy() -> dict[str, Any]:
    policy = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if not isinstance(policy, dict):
        raise ValueError("ASR policy must be a JSON object")
    validate_policy(policy)
    return policy


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def policy_sha256() -> str:
    return file_sha256(MANIFEST_PATH)


def get_repo_head() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Cannot resolve exact heim-pc Git HEAD")
    return result.stdout.strip()


def get_repo_dirty() -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Cannot determine heim-pc Git dirty state")
    return bool(result.stdout.strip())


def get_engine(policy: dict[str, Any], engine_name: str) -> dict[str, Any]:
    engines = policy.get("engines", {})
    if engine_name not in engines:
        raise ValueError(f"Unknown ASR engine: {engine_name}")
    return engines[engine_name]


def check_runnable(engine_conf: dict[str, Any], engine_name: str) -> None:
    if engine_conf.get("cost") != "zero":
        raise ValueError(f"Engine {engine_name} violates zero-cost invariant")
    if engine_conf.get("gated"):
        raise ValueError(f"Engine {engine_name} is gated and rejected for unattended use")
    if not engine_conf.get("runnable"):
        raise ValueError(f"Engine {engine_name} has no validated local adapter")
    if not engine_conf.get("automatic_inference_support"):
        raise ValueError(f"Engine {engine_name} is not allowed for automatic local inference")


def get_venv_path(engine_name: str) -> Path:
    return CACHE_DIR / f"venv_{engine_name}"


def backend_env(*, offline: bool) -> dict[str, str]:
    env = os.environ.copy()
    env["HF_HOME"] = str(HF_HOME_DIR)
    env["HF_HUB_CACHE"] = str(HF_HUB_CACHE_DIR)
    env["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    if offline:
        env["HF_HUB_OFFLINE"] = "1"
        env["TRANSFORMERS_OFFLINE"] = "1"
    else:
        env.pop("HF_HUB_OFFLINE", None)
        env.pop("TRANSFORMERS_OFFLINE", None)
    return env


def get_audio_duration(audio_path: Path) -> float:
    result = subprocess.run(
        [
            "ffprobe",
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "default=noprint_wrappers=1:nokey=1",
            str(audio_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("ffprobe could not determine media duration")
    duration = float(result.stdout.strip())
    if duration <= 0:
        raise RuntimeError("media duration must be positive")
    return duration


def current_gpu_memory_mib() -> int | None:
    if not shutil.which("nvidia-smi"):
        return None
    result = subprocess.run(
        ["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.splitlines()[0].strip())
    except (IndexError, ValueError):
        return None


def run_child_with_gpu_observation(
    argv: list[str], env: dict[str, str]
) -> tuple[int, str, str, int | None]:
    process = subprocess.Popen(
        argv,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    captured: dict[str, tuple[str, str]] = {}

    def communicate() -> None:
        captured["io"] = process.communicate()

    thread = threading.Thread(target=communicate, daemon=True)
    thread.start()
    peak = current_gpu_memory_mib()
    while thread.is_alive():
        sample = current_gpu_memory_mib()
        if sample is not None:
            peak = sample if peak is None else max(peak, sample)
        thread.join(0.25)
    stdout, stderr = captured.get("io", ("", ""))
    return process.returncode, stdout, stderr, peak


def parse_child_json(stdout: str) -> dict[str, Any]:
    for line in reversed(stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and "text" in value:
            return value
    raise BackendError("local ASR backend returned no parseable result")


def _qwen_snapshot_complete(snapshot: Path) -> bool:
    index_path = snapshot / "model.safetensors.index.json"
    if not index_path.is_file() or not (snapshot / "config.json").is_file():
        return False
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
        shards = set(index["weight_map"].values())
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return False
    return bool(shards) and all((snapshot / shard).is_file() for shard in shards)


def _faster_whisper_snapshot_complete(snapshot: Path) -> bool:
    required = ("model.bin", "config.json", "tokenizer.json")
    return all((snapshot / name).is_file() for name in required)


def _parakeet_snapshot_complete(snapshot: Path) -> bool:
    required = (
        "config.json",
        "model.safetensors",
        "processor_config.json",
        "tokenizer.json",
    )
    return all((snapshot / name).is_file() for name in required)


def model_cache_ready(engine_name: str) -> bool:
    if engine_name == "qwen":
        snapshots = (
            HF_HUB_CACHE_DIR
            / "models--Qwen--Qwen3-ASR-1.7B"
            / "snapshots"
        )
        validator = _qwen_snapshot_complete
    elif engine_name == "faster-whisper":
        snapshots = (
            FASTER_WHISPER_MODEL_DIR
            / "models--Systran--faster-whisper-large-v3"
            / "snapshots"
        )
        validator = _faster_whisper_snapshot_complete
    elif engine_name == "parakeet":
        engine_conf = get_engine(load_policy(), engine_name)
        revision = engine_conf.get("model_revision")
        if not isinstance(revision, str) or len(revision) != 40:
            return False
        snapshot = (
            HF_HUB_CACHE_DIR
            / "models--nvidia--parakeet-tdt-0.6b-v3"
            / "snapshots"
            / revision
        )
        return snapshot.is_dir() and _parakeet_snapshot_complete(snapshot)
    else:
        return False
    if not snapshots.is_dir():
        return False
    return any(path.is_dir() and validator(path) for path in snapshots.iterdir())


def package_probe(engine_name: str) -> tuple[bool, str]:
    venv_python = get_venv_path(engine_name) / "bin" / "python"
    if not venv_python.is_file():
        return False, "venv-missing"
    if engine_name == "qwen":
        distribution = "qwen-asr"
        code = (
            "import importlib.metadata as m; import qwen_asr; import torch; "
            "assert torch.cuda.is_available(), 'torch-cuda-unavailable'; "
            f"print(m.version('{distribution}'))"
        )
    elif engine_name == "faster-whisper":
        distribution = "faster-whisper"
        code = (
            "import importlib.metadata as m; import faster_whisper; import ctranslate2; "
            "assert ctranslate2.get_cuda_device_count() > 0, 'ctranslate2-cuda-unavailable'; "
            f"print(m.version('{distribution}'))"
        )
    elif engine_name == "parakeet":
        distribution = "transformers"
        code = (
            "import importlib.metadata as m; import librosa; import torch; "
            "from transformers import AutoModelForTDT, AutoProcessor; "
            "assert torch.cuda.is_available(), 'torch-cuda-unavailable'; "
            f"print(m.version('{distribution}'))"
        )
    else:
        return False, "adapter-unsupported"
    result = subprocess.run(
        [str(venv_python), "-c", code],
        env=backend_env(offline=True),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return False, "package-or-cuda-probe-failed"
    observed_version = result.stdout.strip()
    expected_version = get_engine(load_policy(), engine_name).get("package_version")
    if isinstance(expected_version, str) and observed_version != expected_version:
        return False, "package-version-mismatch"
    return True, observed_version


def cmd_doctor(args: argparse.Namespace) -> bool:
    policy = load_policy()
    engine_name = args.engine or policy["default_engine"]
    engine_conf = get_engine(policy, engine_name)
    check_runnable(engine_conf, engine_name)

    ok = True
    for tool in ("ffmpeg", "ffprobe", "python3", "uv", "nvidia-smi"):
        present = shutil.which(tool) is not None
        logging.info("%s %s", "[OK]" if present else "[MISSING]", tool)
        ok = ok and present

    package_ok, package_state = package_probe(engine_name)
    logging.info(
        "%s %s runtime: %s",
        "[OK]" if package_ok else "[MISSING]",
        engine_name,
        package_state,
    )
    cache_ok = model_cache_ready(engine_name)
    logging.info(
        "%s %s model cache",
        "[OK]" if cache_ok else "[MISSING]",
        engine_name,
    )
    logging.info("Doctor complete; no packages or model weights were downloaded")
    return ok and package_ok and cache_ok


def cmd_setup(args: argparse.Namespace) -> None:
    policy = load_policy()
    engine_name = args.engine
    engine_conf = get_engine(policy, engine_name)
    check_runnable(engine_conf, engine_name)
    if not engine_conf.get("automatic_setup_support"):
        raise ValueError(f"Engine {engine_name} is not allowed for automatic setup")
    if not shutil.which("uv"):
        raise RuntimeError("uv is required for isolated ASR setup")

    venv_path = get_venv_path(engine_name)
    CACHE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    HF_HUB_CACHE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    subprocess.run(
        ["uv", "venv", "--python", "3.12", "--clear", str(venv_path)],
        check=True,
    )
    python_exec = str(venv_path / "bin" / "python")
    env = backend_env(offline=False)

    if engine_name == "qwen":
        subprocess.run(
            [
                "uv",
                "pip",
                "install",
                "--python",
                python_exec,
                engine_conf["package"],
            ],
            env=env,
            check=True,
        )
        download_code = (
            "from huggingface_hub import snapshot_download; import sys; "
            "snapshot_download(repo_id=sys.argv[1], cache_dir=sys.argv[2])"
        )
        subprocess.run(
            [python_exec, "-c", download_code, engine_conf["model"], str(HF_HUB_CACHE_DIR)],
            env=env,
            check=True,
        )
    elif engine_name == "faster-whisper":
        subprocess.run(
            [
                "uv",
                "pip",
                "install",
                "--python",
                python_exec,
                engine_conf["package"],
            ],
            env=env,
            check=True,
        )
        download_code = (
            "from faster_whisper import WhisperModel; import sys; "
            "WhisperModel(sys.argv[1], device='cpu', compute_type='int8', "
            "download_root=sys.argv[2])"
        )
        subprocess.run(
            [python_exec, "-c", download_code, FASTER_WHISPER_SIZE, str(FASTER_WHISPER_MODEL_DIR)],
            env=env,
            check=True,
        )
    elif engine_name == "parakeet":
        revision = engine_conf.get("model_revision")
        if not isinstance(revision, str) or len(revision) != 40:
            raise ValueError("Parakeet requires an exact 40-character model revision")
        subprocess.run(
            [
                "uv",
                "pip",
                "install",
                "--python",
                python_exec,
                engine_conf["package"],
                *engine_conf.get("dependencies", []),
            ],
            env=env,
            check=True,
        )
        download_code = (
            "from huggingface_hub import snapshot_download; import sys; "
            "snapshot_download(repo_id=sys.argv[1], revision=sys.argv[2], cache_dir=sys.argv[3], allow_patterns=['config.json', 'generation_config.json', 'model.safetensors', 'processor_config.json', 'tokenizer.json', 'tokenizer_config.json'])"
        )
        subprocess.run(
            [
                python_exec,
                "-c",
                download_code,
                engine_conf["model"],
                revision,
                str(HF_HUB_CACHE_DIR),
            ],
            env=env,
            check=True,
        )
    else:
        raise ValueError(f"Setup adapter missing for {engine_name}")

    package_ok, _ = package_probe(engine_name)
    if not package_ok or not model_cache_ready(engine_name):
        raise RuntimeError(f"Setup verification failed for {engine_name}")
    logging.info("Local setup complete for %s", engine_name)


QWEN_CHILD = r'''
import importlib.metadata as metadata
import json
import subprocess
import sys

import numpy as np
import torch
from qwen_asr import Qwen3ASRModel

decoded = subprocess.run(
    [
        "ffmpeg", "-v", "error", "-i", sys.argv[2],
        "-vn", "-ac", "1", "-ar", "16000",
        "-f", "f32le", "-acodec", "pcm_f32le", "pipe:1",
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
if decoded.returncode != 0 or not decoded.stdout:
    raise RuntimeError("ffmpeg could not decode input media for Qwen ASR")
audio = np.frombuffer(decoded.stdout, dtype="<f4")

model = Qwen3ASRModel.from_pretrained(
    sys.argv[1],
    dtype=torch.bfloat16,
    device_map="cuda:0",
    max_inference_batch_size=1,
    max_new_tokens=4096,
)
result = model.transcribe(audio=(audio, 16000), language=None)[0]
print(json.dumps({
    "text": result.text,
    "language": result.language,
    "version": metadata.version("qwen-asr"),
}, ensure_ascii=False))
'''


FASTER_WHISPER_CHILD = r'''
import importlib.metadata as metadata
import json
import sys
from faster_whisper import WhisperModel

model = WhisperModel(
    "large-v3",
    device="cuda",
    compute_type="float16",
    download_root=sys.argv[2],
    local_files_only=True,
)
segments, info = model.transcribe(
    sys.argv[1],
    language=None,
    vad_filter=True,
    no_repeat_ngram_size=3,
)
segment_items = []
texts = []
for segment in segments:
    texts.append(segment.text)
    segment_items.append({
        "start": float(segment.start),
        "end": float(segment.end),
        "speaker": None,
        "text": segment.text,
    })
print(json.dumps({
    "text": "".join(texts).strip(),
    "language": info.language,
    "version": metadata.version("faster-whisper"),
    "segments": segment_items,
}, ensure_ascii=False))
'''


PARAKEET_CHILD = r'''
import importlib.metadata as metadata
import json
import subprocess
import sys
import types

import numpy as np
import torch
from transformers import AutoModelForTDT, AutoProcessor
from transformers.audio_utils import mel_filter_bank
import transformers.models.parakeet.feature_extraction_parakeet as parakeet_features


def _jit_free_mel(*, sr, n_fft, n_mels, fmin, fmax, norm):
    return mel_filter_bank(
        num_frequency_bins=n_fft // 2 + 1,
        num_mel_filters=n_mels,
        min_frequency=fmin,
        max_frequency=fmax,
        sampling_rate=sr,
        norm=norm,
        mel_scale="slaney",
    ).T.astype(np.float32)


# Transformers 5.15 only needs librosa for this matrix construction.  Avoid
# importing librosa.filters -> numba/llvmlite so inference also works inside
# hardened runtimes that forbid executable JIT memory.
parakeet_features.librosa = types.SimpleNamespace(
    filters=types.SimpleNamespace(mel=_jit_free_mel)
)

decoded = subprocess.run(
    [
        "ffmpeg", "-v", "error", "-i", sys.argv[3],
        "-vn", "-ac", "1", "-ar", "16000",
        "-f", "f32le", "-acodec", "pcm_f32le", "pipe:1",
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
if decoded.returncode != 0 or not decoded.stdout:
    raise RuntimeError("ffmpeg could not decode input media for Parakeet ASR")
audio = np.frombuffer(decoded.stdout, dtype="<f4")

model_id = sys.argv[1]
revision = sys.argv[2]
processor = AutoProcessor.from_pretrained(
    model_id, revision=revision, local_files_only=True
)
model = AutoModelForTDT.from_pretrained(
    model_id,
    revision=revision,
    local_files_only=True,
    dtype=torch.float16,
    device_map="cuda:0",
)

# Bound memory on the 16-GB heim-pc GPU while preserving the full input.
chunk_samples = 60 * 16000
texts = []
for start in range(0, len(audio), chunk_samples):
    chunk = audio[start:start + chunk_samples]
    inputs = processor(
        chunk, sampling_rate=processor.feature_extractor.sampling_rate, return_tensors="pt"
    )
    inputs.to(device=model.device, dtype=model.dtype)
    with torch.inference_mode():
        output = model.generate(**inputs, return_dict_in_generate=True)
    decoded_text = processor.decode(output.sequences, skip_special_tokens=True)
    if isinstance(decoded_text, list):
        decoded_text = " ".join(str(item) for item in decoded_text)
    decoded_text = str(decoded_text).strip()
    if decoded_text:
        texts.append(decoded_text)

print(json.dumps({
    "text": " ".join(texts).strip(),
    "language": None,
    "version": metadata.version("transformers"),
}, ensure_ascii=False))
'''


def run_inference(
    engine_name: str, engine_conf: dict[str, Any], audio_path: Path
) -> dict[str, Any]:
    python_exec = get_venv_path(engine_name) / "bin" / "python"
    if not python_exec.is_file():
        raise BackendError(f"{engine_name} is not setup")
    if not model_cache_ready(engine_name):
        raise BackendError(f"{engine_name} model cache is incomplete; run explicit setup")

    env = backend_env(offline=True)
    if engine_name == "qwen":
        argv = [str(python_exec), "-c", QWEN_CHILD, engine_conf["model"], str(audio_path)]
    elif engine_name == "faster-whisper":
        argv = [
            str(python_exec),
            "-c",
            FASTER_WHISPER_CHILD,
            str(audio_path),
            str(FASTER_WHISPER_MODEL_DIR),
        ]
    elif engine_name == "parakeet":
        revision = engine_conf.get("model_revision")
        if not isinstance(revision, str) or len(revision) != 40:
            raise BackendError("Parakeet model revision is not exact")
        argv = [
            str(python_exec),
            "-c",
            PARAKEET_CHILD,
            engine_conf["model"],
            revision,
            str(audio_path),
        ]
    else:
        raise BackendError(f"No inference adapter for {engine_name}")

    returncode, stdout, _stderr, peak = run_child_with_gpu_observation(argv, env)
    if returncode != 0:
        raise BackendError(f"{engine_name} local backend exited with status {returncode}")
    payload = parse_child_json(stdout)
    payload["gpu_memory_used_peak_mib_observed"] = peak
    return payload



def run_local_transcription(engine_name: str, audio_path: Path) -> dict[str, Any]:
    policy = load_policy()
    engine_conf = get_engine(policy, engine_name)
    check_runnable(engine_conf, engine_name)
    payload = run_inference(engine_name, engine_conf, audio_path)
    return normalize_transcript_result(
        provider="local",
        engine_name=engine_name,
        engine_conf=engine_conf,
        payload=payload,
    )


def _cloud_api_key(*, allow_metered_cloud: bool) -> str:
    if not allow_metered_cloud:
        raise CloudCostAuthorizationError(
            "Metered cloud ASR requires explicit --allow-metered-cloud for this run"
        )
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not key:
        raise CloudCostAuthorizationError(
            "OPENAI_API_KEY is required after explicit metered-cloud authorization"
        )
    return key


def _multipart_form(audio_path: Path, fields: dict[str, str]) -> tuple[bytes, str]:
    supported = {
        ".flac", ".mp3", ".mp4", ".mpeg", ".mpga",
        ".m4a", ".ogg", ".wav", ".webm",
    }
    suffix = audio_path.suffix.casefold()
    if suffix not in supported:
        raise BackendError(f"OpenAI transcription does not accept media suffix {suffix!r}")
    boundary = f"----heimpc-asr-{uuid.uuid4().hex}"
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.extend([
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
            value.encode("utf-8"),
            b"\r\n",
        ])
    chunks.extend([
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="file"; filename="input{suffix}"\r\n'.encode(),
        b"Content-Type: application/octet-stream\r\n\r\n",
        audio_path.read_bytes(),
        b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ])
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def run_openai_transcription(
    model_name: str,
    audio_path: Path,
    *,
    allow_metered_cloud: bool,
) -> dict[str, Any]:
    policy = load_policy()
    invariants = policy.get("invariants", {})
    if (
        invariants.get("metered_cloud_registered") is not True
        or invariants.get("metered_cloud_requires_explicit_per_run_opt_in") is not True
        or invariants.get("metered_cloud_allowed_with_explicit_per_run_opt_in") is not True
        or invariants.get("automatic_cloud_escalation_allowed") is not False
    ):
        raise BackendError("Top-level cloud cost policy is invalid")
    engine_conf = get_cloud_engine(policy, model_name)
    if engine_conf.get("provider") != "openai" or engine_conf.get("cost") != "metered":
        raise BackendError("Cloud ASR policy is invalid")
    if not engine_conf.get("runnable") or not engine_conf.get("requires_explicit_metered_opt_in"):
        raise BackendError("Cloud ASR model is not enabled by policy")
    api_key = _cloud_api_key(allow_metered_cloud=allow_metered_cloud)
    fields = {
        "model": model_name,
        "response_format": str(engine_conf.get("response_format", "json")),
    }
    chunking = engine_conf.get("chunking_strategy")
    if isinstance(chunking, str) and chunking:
        fields["chunking_strategy"] = chunking
    body, content_type = _multipart_form(audio_path, fields)
    request = urllib.request.Request(
        str(engine_conf["endpoint"]),
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": content_type,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raise BackendError(f"OpenAI transcription HTTP status {exc.code}") from None
    except urllib.error.URLError as exc:
        raise BackendError("OpenAI transcription network request failed") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackendError("OpenAI transcription returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise BackendError("OpenAI transcription returned invalid payload")
    payload["version"] = None
    return normalize_transcript_result(
        provider="openai",
        engine_name=model_name,
        engine_conf=engine_conf,
        payload=payload,
    )


def transcript_disagreement_rate(first: str, second: str) -> float:
    a = normalize_text(first).split()
    b = normalize_text(second).split()
    denominator = max(len(a), len(b), 1)
    return edit_distance(a, b) / denominator


def route_transcription(
    audio_path: Path,
    *,
    strategy: str = "local-first",
    primary_engine: str | None = None,
    secondary_engine: str | None = None,
    disagreement_threshold: float | None = None,
    cloud_model: str | None = None,
    escalate_to_cloud: bool = False,
    allow_metered_cloud: bool = False,
) -> dict[str, Any]:
    policy = load_policy()
    routing = policy["routing"]
    primary = primary_engine or routing["default_local_engine"]
    fallback = routing["local_fallback_engine"]
    secondary = secondary_engine or routing["dual_local_default_secondary"]
    threshold = (
        float(disagreement_threshold)
        if disagreement_threshold is not None
        else float(routing["dual_local_disagreement_threshold"])
    )
    cloud_name = cloud_model or routing["default_cloud_model"]
    if threshold < 0 or threshold > 1:
        raise ValueError("disagreement threshold must be between 0 and 1")

    if strategy == "cloud":
        selected = run_openai_transcription(
            cloud_name, audio_path, allow_metered_cloud=allow_metered_cloud
        )
        return {
            "schema_version": 1,
            "kind": "heim-pc.asr-route-result",
            "strategy": strategy,
            "selected": selected,
            "comparison": None,
            "cloud_recommended": True,
            "cloud_used": True,
        }

    try:
        first = run_local_transcription(primary, audio_path)
    except BackendError as primary_error:
        if strategy == "local-first" and fallback != primary:
            try:
                selected = run_local_transcription(fallback, audio_path)
            except BackendError as fallback_error:
                if not escalate_to_cloud:
                    raise BackendError(
                        "Primary and local fallback ASR engines both failed"
                    ) from fallback_error
            else:
                return {
                    "schema_version": 1,
                    "kind": "heim-pc.asr-route-result",
                    "strategy": strategy,
                    "selected": selected,
                    "comparison": None,
                    "cloud_recommended": False,
                    "cloud_used": False,
                    "local_primary_failed": True,
                    "local_fallback_used": True,
                    "primary_local_engine": primary,
                    "fallback_local_engine": fallback,
                }
        if not escalate_to_cloud:
            raise primary_error
        selected = run_openai_transcription(
            cloud_name, audio_path, allow_metered_cloud=allow_metered_cloud
        )
        return {
            "schema_version": 1,
            "kind": "heim-pc.asr-route-result",
            "strategy": strategy,
            "selected": selected,
            "comparison": None,
            "cloud_recommended": True,
            "cloud_used": True,
            "local_failure_escalated": True,
        }

    if strategy == "local-first":
        return {
            "schema_version": 1,
            "kind": "heim-pc.asr-route-result",
            "strategy": strategy,
            "selected": first,
            "comparison": None,
            "cloud_recommended": False,
            "cloud_used": False,
        }
    if strategy != "dual-local":
        raise ValueError(f"Unknown ASR routing strategy: {strategy}")
    if primary == secondary:
        raise ValueError("dual-local routing requires two different local engines")

    second = run_local_transcription(secondary, audio_path)
    disagreement = transcript_disagreement_rate(first["text"], second["text"])
    recommended = disagreement > threshold
    selected = first
    cloud_used = False
    if recommended and escalate_to_cloud:
        selected = run_openai_transcription(
            cloud_name, audio_path, allow_metered_cloud=allow_metered_cloud
        )
        cloud_used = True
    return {
        "schema_version": 1,
        "kind": "heim-pc.asr-route-result",
        "strategy": strategy,
        "selected": selected,
        "comparison": {
            "primary": first,
            "secondary": second,
            "disagreement_rate": disagreement,
            "threshold": threshold,
        },
        "cloud_recommended": recommended,
        "cloud_used": cloud_used,
    }


def dual_local_evidence(audio_path: Path, result: dict[str, Any]) -> dict[str, Any]:
    if result.get("strategy") != "dual-local":
        raise ValueError("dual-local evidence requires a dual-local route result")
    comparison = result.get("comparison")
    if not isinstance(comparison, dict):
        raise ValueError("dual-local route result has no comparison")
    primary = comparison.get("primary")
    secondary = comparison.get("secondary")
    if not isinstance(primary, dict) or not isinstance(secondary, dict):
        raise ValueError("dual-local route comparison is invalid")
    return {
        "schema_version": 1,
        "kind": "heim-pc.asr-dual-local-evidence",
        "repo_head": get_repo_head(),
        "repo_dirty": get_repo_dirty(),
        "policy_sha256": policy_sha256(),
        "adapter_sha256": file_sha256(Path(__file__).resolve()),
        "audio_sha256": file_sha256(audio_path),
        "primary": {
            "engine": primary.get("engine"),
            "model": primary.get("model"),
            "model_revision": primary.get("model_revision"),
            "backend_version": primary.get("backend_version"),
            "transcript_sha256": hashlib.sha256(
                primary["text"].encode("utf-8")
            ).hexdigest(),
        },
        "secondary": {
            "engine": secondary.get("engine"),
            "model": secondary.get("model"),
            "model_revision": secondary.get("model_revision"),
            "backend_version": secondary.get("backend_version"),
            "transcript_sha256": hashlib.sha256(
                secondary["text"].encode("utf-8")
            ).hexdigest(),
        },
        "disagreement_rate": comparison.get("disagreement_rate"),
        "threshold": comparison.get("threshold"),
        "cloud_recommended": bool(result.get("cloud_recommended")),
        "cloud_used": bool(result.get("cloud_used")),
    }


def write_dual_local_evidence(evidence: dict[str, Any]) -> Path:
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    identity = json_sha256(
        {
            "audio_sha256": evidence["audio_sha256"],
            "primary": evidence["primary"]["transcript_sha256"],
            "secondary": evidence["secondary"]["transcript_sha256"],
            "policy_sha256": evidence["policy_sha256"],
        }
    )
    path = STATE_DIR / f"dual_local_{identity}.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    return path

def normalize_text(value: str) -> str:
    return " ".join(value.casefold().split())


def normalize_lexical_text(value: str) -> str:
    joined_punctuation = {"'", "’", "-", "‐", "‑", "‒", "–", "—"}
    normalized: list[str] = []
    for character in value.casefold():
        if unicodedata.category(character).startswith("P"):
            if character not in joined_punctuation:
                normalized.append(" ")
            continue
        normalized.append(character)
    return " ".join("".join(normalized).split())


def edit_distance(reference: Sequence[str], hypothesis: Sequence[str]) -> int:
    previous = list(range(len(hypothesis) + 1))
    for ref_index, ref_item in enumerate(reference, start=1):
        current = [ref_index]
        for hyp_index, hyp_item in enumerate(hypothesis, start=1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[hyp_index] + 1,
                    previous[hyp_index - 1] + (ref_item != hyp_item),
                )
            )
        previous = current
    return previous[-1]


def error_rate(reference: Sequence[str], hypothesis: Sequence[str]) -> float:
    if not reference:
        return 0.0 if not hypothesis else 1.0
    return edit_distance(reference, hypothesis) / len(reference)


def compute_wer_cer(reference: str, hypothesis: str) -> tuple[float, float]:
    ref = normalize_text(reference)
    hyp = normalize_text(hypothesis)
    wer = error_rate(ref.split(), hyp.split())
    cer = error_rate(list(ref.replace(" ", "")), list(hyp.replace(" ", "")))
    return wer, cer


def compute_lexical_wer_cer(reference: str, hypothesis: str) -> tuple[float, float]:
    ref = normalize_lexical_text(reference)
    hyp = normalize_lexical_text(hypothesis)
    wer = error_rate(ref.split(), hyp.split())
    cer = error_rate(list(ref.replace(" ", "")), list(hyp.replace(" ", "")))
    return wer, cer



def json_sha256(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _path_is_within_repo(path: Path) -> bool:
    try:
        path.resolve().relative_to(REPO_ROOT.resolve())
        return True
    except ValueError:
        return False


def load_private_golden_manifest(
    manifest_path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    contract = load_golden_contract()
    path = manifest_path.expanduser().resolve(strict=True)
    if _path_is_within_repo(path):
        raise ValueError("Golden corpus manifest must remain outside the repository")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Golden corpus manifest must be a JSON object")
    if (
        raw.get("schema_version") != 1
        or raw.get("kind") != contract["private_manifest_kind"]
    ):
        raise ValueError("Golden corpus manifest identity mismatch")
    items = raw.get("items")
    if not isinstance(items, list) or not items:
        raise ValueError("Golden corpus manifest requires at least one item")
    allowed_categories = set(contract["required_quality_categories"])
    seen_ids: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Golden corpus item must be an object")
        missing = [field for field in contract["item_fields"] if field not in item]
        if missing:
            raise ValueError(f"Golden corpus item is missing fields: {missing}")
        item_id = item.get("id")
        if (
            not isinstance(item_id, str)
            or not item_id.strip()
            or item_id in seen_ids
        ):
            raise ValueError("Golden corpus item id is invalid or duplicated")
        seen_ids.add(item_id)
        categories = item.get("categories")
        if (
            not isinstance(categories, list)
            or not categories
            or not all(isinstance(value, str) for value in categories)
        ):
            raise ValueError("Golden corpus item categories are invalid")
        category_set = set(categories)
        if not category_set <= allowed_categories:
            raise ValueError("Golden corpus item uses unsupported category labels")
        if item.get("reference_kind") != contract["required_reference_kind"]:
            raise ValueError("Golden corpus reference_kind must be human-corrected")
        audio = (path.parent / str(item["audio"])).expanduser().resolve(strict=True)
        reference = (path.parent / str(item["reference"])).expanduser().resolve(strict=True)
        if _path_is_within_repo(audio) or _path_is_within_repo(reference):
            raise ValueError(
                "Golden corpus private media/reference must remain outside repository"
            )
        if not audio.is_file() or not reference.is_file():
            raise ValueError("Golden corpus media/reference must be regular files")
        normalized.append(
            {
                "id": item_id,
                "categories": sorted(category_set),
                "audio": audio,
                "reference": reference,
            }
        )
    return raw, normalized


def golden_manifest_summary(manifest_path: Path) -> dict[str, Any]:
    contract = load_golden_contract()
    raw, items = load_private_golden_manifest(manifest_path)
    counts = {category: 0 for category in contract["required_quality_categories"]}
    for item in items:
        for category in item["categories"]:
            counts[category] += 1
    missing = sorted(category for category, count in counts.items() if count == 0)
    eligible = len(items) >= int(contract["minimum_quality_samples"]) and not missing
    return {
        "schema_version": 1,
        "kind": "heim-pc.asr-golden-corpus-summary",
        "manifest_sha256": json_sha256(raw),
        "sample_count": len(items),
        "category_counts": counts,
        "missing_quality_categories": missing,
        "minimum_quality_samples": int(contract["minimum_quality_samples"]),
        "quality_gate_eligible": eligible,
        "automatic_default_change_allowed": False,
    }


def _golden_engine_measurement(
    engine_name: str,
    audio_path: Path,
    reference_path: Path,
) -> dict[str, Any]:
    policy = load_policy()
    conf = get_engine(policy, engine_name)
    check_runnable(conf, engine_name)
    duration = get_audio_duration(audio_path)
    reference = reference_path.read_text(encoding="utf-8")
    start = time.monotonic()
    payload = run_inference(engine_name, conf, audio_path)
    wall = time.monotonic() - start
    wer, cer = compute_wer_cer(reference, payload["text"])
    lexical_wer, lexical_cer = compute_lexical_wer_cer(reference, payload["text"])
    return {
        "outcome": "success",
        "model": conf["model"],
        "model_revision": conf.get("model_revision"),
        "backend_version": payload.get("version"),
        "detected_language": payload.get("language"),
        "metric_schema_version": 2,
        "wer": wer,
        "cer": cer,
        "lexical_wer": lexical_wer,
        "lexical_cer": lexical_cer,
        "wall_time_seconds": wall,
        "rtf": wall / duration,
        "gpu_memory_used_peak_mib_observed": payload.get(
            "gpu_memory_used_peak_mib_observed"
        ),
    }


def run_golden_benchmark(
    manifest_path: Path, engines: Sequence[str]
) -> dict[str, Any]:
    summary = golden_manifest_summary(manifest_path)
    _raw, items = load_private_golden_manifest(manifest_path)
    if not engines:
        raise ValueError("Golden benchmark requires at least one local engine")
    local_allowed = set(load_policy()["routing"]["local_engines"])
    unique_engines = list(dict.fromkeys(engines))
    if any(engine not in local_allowed for engine in unique_engines):
        raise ValueError("Golden benchmark accepts local engines only")
    samples: list[dict[str, Any]] = []
    failed = False
    for item in items:
        audio_digest = file_sha256(item["audio"])
        reference_digest = file_sha256(item["reference"])
        sample_digest = json_sha256(
            {
                "audio_sha256": audio_digest,
                "reference_sha256": reference_digest,
                "categories": item["categories"],
            }
        )
        measurements: dict[str, Any] = {}
        for engine in unique_engines:
            try:
                measurements[engine] = _golden_engine_measurement(
                    engine, item["audio"], item["reference"]
                )
            except Exception as exc:
                failed = True
                measurements[engine] = {
                    "outcome": "error",
                    "failure_class": type(exc).__name__,
                }
        samples.append(
            {
                "sample_sha256": sample_digest,
                "audio_sha256": audio_digest,
                "reference_sha256": reference_digest,
                "categories": item["categories"],
                "engines": measurements,
            }
        )
    aggregates: dict[str, Any] = {}
    for engine in unique_engines:
        successful = [
            sample["engines"][engine]
            for sample in samples
            if sample["engines"][engine].get("outcome") == "success"
        ]
        if not successful:
            aggregates[engine] = {"success_count": 0}
            continue
        gpu_samples = [
            item["gpu_memory_used_peak_mib_observed"]
            for item in successful
            if item["gpu_memory_used_peak_mib_observed"] is not None
        ]
        aggregates[engine] = {
            "success_count": len(successful),
            "mean_wer": sum(item["wer"] for item in successful) / len(successful),
            "mean_cer": sum(item["cer"] for item in successful) / len(successful),
            "mean_lexical_wer": sum(item["lexical_wer"] for item in successful) / len(successful),
            "mean_lexical_cer": sum(item["lexical_cer"] for item in successful) / len(successful),
            "mean_rtf": sum(item["rtf"] for item in successful) / len(successful),
            "max_gpu_memory_used_peak_mib_observed": (
                max(gpu_samples) if gpu_samples else None
            ),
        }
    complete = not failed and all(
        aggregates.get(engine, {}).get("success_count") == len(samples)
        for engine in unique_engines
    )
    best_strict = None
    best_lexical = None
    if summary["quality_gate_eligible"] and complete:
        best_strict = min(unique_engines, key=lambda name: aggregates[name]["mean_wer"])
        best_lexical = min(
            unique_engines, key=lambda name: aggregates[name]["mean_lexical_wer"]
        )
    return {
        "schema_version": 1,
        "kind": "heim-pc.asr-golden-benchmark",
        "manifest_sha256": summary["manifest_sha256"],
        "repo_head": get_repo_head(),
        "repo_dirty": get_repo_dirty(),
        "policy_sha256": policy_sha256(),
        "adapter_sha256": file_sha256(Path(__file__).resolve()),
        "sample_count": summary["sample_count"],
        "category_counts": summary["category_counts"],
        "quality_gate_eligible": summary["quality_gate_eligible"],
        "all_measurements_complete": complete,
        "engines": unique_engines,
        "aggregates": aggregates,
        "samples": samples,
        "current_default_engine": load_policy()["default_engine"],
        "metric_schema_version": 2,
        "default_review_metric": "mean_lexical_wer",
        "best_local_engine_by_mean_wer": best_strict,
        "best_local_engine_by_mean_lexical_wer": best_lexical,
        "eligible_for_default_review": bool(best_lexical),
        "automatic_default_change_allowed": False,
    }


def write_golden_evidence(evidence: dict[str, Any]) -> Path:
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = STATE_DIR / f"golden_{evidence['manifest_sha256']}.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    return path


def cmd_golden_check(args: argparse.Namespace) -> None:
    print(
        json.dumps(
            golden_manifest_summary(args.manifest),
            ensure_ascii=False,
            sort_keys=True,
        )
    )


def cmd_golden_benchmark(args: argparse.Namespace) -> None:
    engines = args.engine or load_policy()["routing"]["local_engines"]
    evidence = run_golden_benchmark(args.manifest, engines)
    path = write_golden_evidence(evidence)
    logging.info("Privacy-safe golden benchmark evidence written: %s", path)
    if not evidence["all_measurements_complete"]:
        raise BackendError("Golden benchmark had one or more local backend failures")

def write_evidence(engine_name: str, audio_digest: str, evidence: dict[str, Any]) -> Path:
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = STATE_DIR / f"{audio_digest}_{engine_name}.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    return path


def cmd_transcribe(args: argparse.Namespace) -> None:
    audio_path = args.audio.expanduser().resolve(strict=True)
    if args.engine is None:
        result = route_transcription(audio_path, strategy="local-first")["selected"]
        print(result["text"])
        return
    policy = load_policy()
    engine_name = args.engine
    engine_conf = get_engine(policy, engine_name)
    check_runnable(engine_conf, engine_name)
    result = run_inference(engine_name, engine_conf, audio_path)
    print(result["text"])


def cmd_route(args: argparse.Namespace) -> None:
    audio_path = args.audio.expanduser().resolve(strict=True)
    result = route_transcription(
        audio_path,
        strategy=args.strategy,
        primary_engine=args.primary,
        secondary_engine=args.secondary,
        disagreement_threshold=args.disagreement_threshold,
        cloud_model=args.cloud_model,
        escalate_to_cloud=args.escalate_to_cloud,
        allow_metered_cloud=args.allow_metered_cloud,
    )
    if result["strategy"] == "dual-local":
        evidence_path = write_dual_local_evidence(dual_local_evidence(audio_path, result))
        logging.info("Privacy-safe dual-local evidence written: %s", evidence_path)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print(result["selected"]["text"])



def cmd_benchmark(args: argparse.Namespace) -> None:
    policy = load_policy()
    engine_name = args.engine or policy["default_engine"]
    engine_conf = get_engine(policy, engine_name)
    check_runnable(engine_conf, engine_name)
    audio_path = args.audio.expanduser().resolve(strict=True)
    audio_digest = file_sha256(audio_path)
    duration = get_audio_duration(audio_path)
    evidence: dict[str, Any] = {
        "schema_version": 1,
        "input_digest": audio_digest,
        "input_bytes": audio_path.stat().st_size,
        "technical_duration_seconds": duration,
        "engine": engine_name,
        "model": engine_conf["model"],
        "model_revision": engine_conf.get("model_revision"),
        "package": engine_conf.get("package"),
        "repo_head": get_repo_head(),
        "repo_dirty": get_repo_dirty(),
        "policy_sha256": policy_sha256(),
        "adapter_sha256": file_sha256(Path(__file__).resolve()),
        "reference_digest": None,
        "metric_schema_version": 2,
        "wer_semantics": "strict-casefold-whitespace-v1",
        "lexical_wer_semantics": "punctuation-normalized-v2",
        "wer": None,
        "cer": None,
        "lexical_wer": None,
        "lexical_cer": None,
    }

    start = time.monotonic()
    failure: Exception | None = None
    try:
        result = run_inference(engine_name, engine_conf, audio_path)
        evidence["outcome"] = "success"
        evidence["backend_version"] = result["version"]
        evidence["detected_language"] = result.get("language")
        evidence["gpu_memory_used_peak_mib_observed"] = result.get(
            "gpu_memory_used_peak_mib_observed"
        )
        if args.reference is not None:
            reference_path = args.reference.expanduser().resolve(strict=True)
            reference = reference_path.read_text(encoding="utf-8")
            evidence["reference_digest"] = file_sha256(reference_path)
            evidence["wer"], evidence["cer"] = compute_wer_cer(
                reference, result["text"]
            )
            evidence["lexical_wer"], evidence["lexical_cer"] = (
                compute_lexical_wer_cer(reference, result["text"])
            )
    except Exception as exc:  # evidence is still emitted, but the command fails closed
        failure = exc
        evidence["outcome"] = "error"
        evidence["failure_class"] = type(exc).__name__
        evidence["backend_version"] = None
        evidence["detected_language"] = None
        evidence["gpu_memory_used_peak_mib_observed"] = current_gpu_memory_mib()

    evidence["wall_time_seconds"] = time.monotonic() - start
    evidence["rtf"] = evidence["wall_time_seconds"] / duration
    path = write_evidence(engine_name, audio_digest, evidence)
    logging.info("Privacy-safe benchmark evidence written: %s", path)
    if failure is not None:
        raise BackendError(f"Benchmark failed for {engine_name}: {type(failure).__name__}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="heim-pc ASR engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    local_choices = ("qwen", "faster-whisper", "parakeet")
    cloud_choices = (
        "gpt-4o-transcribe",
        "gpt-4o-mini-transcribe",
        "gpt-4o-transcribe-diarize",
    )

    doctor = subparsers.add_parser("doctor", help="Read-only local ASR readiness check")
    doctor.add_argument("--engine", choices=local_choices)

    setup = subparsers.add_parser("setup", help="Explicitly install one local ASR engine")
    setup.add_argument("--engine", required=True, choices=local_choices)

    transcribe = subparsers.add_parser("transcribe", help="Transcribe locally to stdout only")
    transcribe.add_argument("--audio", type=Path, required=True)
    transcribe.add_argument("--engine", choices=local_choices)

    route = subparsers.add_parser(
        "route",
        help="Route transcription local-first; metered cloud requires explicit per-run opt-in",
    )
    route.add_argument("--audio", type=Path, required=True)
    route.add_argument(
        "--strategy",
        choices=("local-first", "dual-local", "cloud"),
        default="local-first",
    )
    route.add_argument("--primary", choices=local_choices)
    route.add_argument("--secondary", choices=local_choices)
    route.add_argument("--disagreement-threshold", type=float)
    route.add_argument("--cloud-model", choices=cloud_choices)
    route.add_argument("--escalate-to-cloud", action="store_true")
    route.add_argument("--allow-metered-cloud", action="store_true")
    route.add_argument("--json", action="store_true")

    benchmark = subparsers.add_parser(
        "benchmark", help="Run real local inference and persist privacy-safe metrics only"
    )
    benchmark.add_argument("--audio", type=Path, required=True)
    benchmark.add_argument("--engine", choices=local_choices)
    benchmark.add_argument("--reference", type=Path)

    golden_check = subparsers.add_parser(
        "golden-check", help="Validate a private human-corrected ASR corpus manifest"
    )
    golden_check.add_argument("--manifest", type=Path, required=True)

    golden_benchmark = subparsers.add_parser(
        "golden-benchmark",
        help="Benchmark local engines against a private human-corrected corpus",
    )
    golden_benchmark.add_argument("--manifest", type=Path, required=True)
    golden_benchmark.add_argument(
        "--engine", choices=local_choices, action="append"
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        if args.command == "doctor":
            if not cmd_doctor(args):
                raise RuntimeError("ASR doctor found an incomplete local runtime")
        elif args.command == "setup":
            cmd_setup(args)
        elif args.command == "transcribe":
            cmd_transcribe(args)
        elif args.command == "route":
            cmd_route(args)
        elif args.command == "benchmark":
            cmd_benchmark(args)
        elif args.command == "golden-check":
            cmd_golden_check(args)
        elif args.command == "golden-benchmark":
            cmd_golden_benchmark(args)
    except Exception as exc:
        logging.error("%s", exc)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
