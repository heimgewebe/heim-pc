#!/usr/bin/env python3
"""Canonical zero-incremental-cost local ASR CLI for the heim-pc."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "manifest" / "asr-engine-policy.v1.json"
STATE_DIR = Path.home() / ".local" / "state" / "heim-pc" / "asr-open-engine"
CACHE_DIR = Path.home() / ".local" / "cache" / "heim-pc" / "asr-open-engine"
HF_HOME_DIR = CACHE_DIR / "hf_home"
HF_HUB_CACHE_DIR = HF_HOME_DIR / "hub"
FASTER_WHISPER_MODEL_DIR = CACHE_DIR / "fw_models"
FASTER_WHISPER_SIZE = "large-v3"

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


class BackendError(RuntimeError):
    """A local backend could not complete inference."""


def load_policy() -> dict[str, Any]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


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
segments, info = model.transcribe(sys.argv[1], language=None, vad_filter=True)
text = "".join(segment.text for segment in segments).strip()
print(json.dumps({
    "text": text,
    "language": info.language,
    "version": metadata.version("faster-whisper"),
}, ensure_ascii=False))
'''


PARAKEET_CHILD = r'''
import importlib.metadata as metadata
import json
import subprocess
import sys

import numpy as np
import torch
from transformers import AutoModelForTDT, AutoProcessor

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


def normalize_text(value: str) -> str:
    return " ".join(value.casefold().split())


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
    policy = load_policy()
    engine_name = args.engine or policy["default_engine"]
    engine_conf = get_engine(policy, engine_name)
    check_runnable(engine_conf, engine_name)
    audio_path = args.audio.expanduser().resolve(strict=True)
    result = run_inference(engine_name, engine_conf, audio_path)
    print(result["text"])


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
        "wer": None,
        "cer": None,
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
    parser = argparse.ArgumentParser(description="heim-pc local ASR engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="Read-only ASR readiness check")
    doctor.add_argument("--engine", choices=("qwen", "faster-whisper", "parakeet"))

    setup = subparsers.add_parser("setup", help="Explicitly install one local ASR engine")
    setup.add_argument("--engine", required=True)

    transcribe = subparsers.add_parser("transcribe", help="Transcribe to stdout only")
    transcribe.add_argument("--audio", type=Path, required=True)
    transcribe.add_argument("--engine")

    benchmark = subparsers.add_parser(
        "benchmark", help="Run real local inference and persist privacy-safe metrics only"
    )
    benchmark.add_argument("--audio", type=Path, required=True)
    benchmark.add_argument("--engine")
    benchmark.add_argument("--reference", type=Path)
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
        elif args.command == "benchmark":
            cmd_benchmark(args)
    except Exception as exc:
        logging.error("%s", exc)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
