#!/usr/bin/env python3
"""
Canonical CLI for ASR Engine Policy and Execution
"""
import argparse
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict

# Constants
MANIFEST_PATH = Path(__file__).parent.parent / "manifest" / "asr-engine-policy.v1.json"
STATE_DIR = Path.home() / ".local" / "state" / "heim-pc" / "asr-open-engine"

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def load_policy() -> Dict[str, Any]:
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(f"Policy manifest not found at {MANIFEST_PATH}")
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def check_gated_and_cost(engine_conf: Dict[str, Any], engine_name: str) -> None:
    if engine_conf.get("cost") != "zero":
        raise ValueError(f"Engine {engine_name} violates zero-cost invariant.")
    if engine_conf.get("gated"):
        raise ValueError(f"Engine {engine_name} is gated and rejected for unattended setup/inference.")


def cmd_doctor(args: argparse.Namespace) -> None:
    policy = load_policy()
    logging.info(f"Loaded policy: {policy.get('id')}")
    for name, conf in policy.get("engines", {}).items():
        cost = conf.get("cost")
        gated = conf.get("gated")
        model = conf.get("model")
        status = "OK"
        if cost != "zero":
            status = "REJECTED (non-zero cost)"
        elif gated:
            status = "REJECTED (gated)"
        logging.info(f"Engine: {name} | Model: {model} | Cost: {cost} | Status: {status}")
    logging.info("Doctor complete. No model weights were downloaded.")


def cmd_benchmark(args: argparse.Namespace) -> None:
    policy = load_policy()
    engine_name = args.engine or policy.get("default_engine")
    engines = policy.get("engines", {})
    if engine_name not in engines:
        raise ValueError(f"Engine {engine_name} not found in policy.")
    
    engine_conf = engines[engine_name]
    check_gated_and_cost(engine_conf, engine_name)
    
    if not args.audio.exists():
        raise FileNotFoundError(f"Audio file {args.audio} not found.")
        
    logging.info(f"Starting benchmark with {engine_name} ({engine_conf['model']}) on {args.audio}")
    
    sha256_hash = hashlib.sha256()
    with open(args.audio, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    audio_digest = sha256_hash.hexdigest()
    
    start_time = time.time()
    if args.dry_run:
        logging.info("Dry run: Skipping actual inference.")
        time.sleep(0.1)
    else:
        # In a real implementation, ASR inference would happen here
        logging.info("Simulating inference (missing weights/engine in this dummy implementation)...")
        # We simulate failure if we aren't explicitly avoiding it because this is a fake harness
        time.sleep(0.5)
        
    end_time = time.time()
    wall_time = end_time - start_time
    
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    evidence = {
        "timestamp": start_time,
        "input_digest": audio_digest,
        "technical_duration": None,
        "engine": engine_name,
        "model": engine_conf["model"],
        "repo_identity": "heim-pc",
        "wall_time": wall_time,
        "outcome": "success" if args.dry_run else "error_no_backend",
        "wer": None,
        "cer": None,
        "gpu_memory": "0MiB"
    }
    
    evidence_path = STATE_DIR / f"{audio_digest}_{engine_name}.json"
    with open(evidence_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)
        
    logging.info(f"Evidence saved to {evidence_path}")
    if not args.dry_run:
        # Fails softly in CLI or throws if we strictly want success
        logging.warning("Actual inference blocked because no real ASR backend is available locally.")


def main() -> None:
    parser = argparse.ArgumentParser(description="ASR Engine CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    _doc_parser = subparsers.add_parser("doctor", help="Check engine policy without downloading weights")
    
    bench_parser = subparsers.add_parser("benchmark", help="Run benchmark")
    bench_parser.add_argument("--audio", type=Path, required=True, help="Path to explicitly passed audio file")
    bench_parser.add_argument("--engine", type=str, help="Engine to use")
    bench_parser.add_argument("--dry-run", action="store_true", help="Dry run without inference")
    
    args = parser.parse_args()
    
    try:
        if args.command == "doctor":
            cmd_doctor(args)
        elif args.command == "benchmark":
            cmd_benchmark(args)
    except Exception as e:
        logging.error(str(e))
        exit(1)


if __name__ == "__main__":
    main()
