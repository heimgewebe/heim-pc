from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "asr_engine.py"


def _run_wrapper(home: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["HOME"] = str(home)
    return subprocess.run(
        [sys.executable, str(WRAPPER), *args],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


def test_compatibility_wrapper_fails_closed_when_generic_authority_is_missing(tmp_path):
    result = _run_wrapper(tmp_path, "doctor")
    assert result.returncode == 127
    assert "canonical generic ASR entry is missing" in result.stderr


def test_compatibility_wrapper_forwards_argv_to_generic_authority(tmp_path):
    target = tmp_path / "repos" / "asr" / "scripts" / "asr_engine.py"
    target.parent.mkdir(parents=True)
    target.write_text(
        "import json, sys\nprint(json.dumps(sys.argv[1:]))\n",
        encoding="utf-8",
    )
    result = _run_wrapper(tmp_path, "route", "--audio", "/tmp/a.m4a", "--json")
    assert result.returncode == 0
    assert json.loads(result.stdout) == ["route", "--audio", "/tmp/a.m4a", "--json"]


def test_compatibility_wrapper_contains_no_engine_or_cloud_policy():
    source = WRAPPER.read_text(encoding="utf-8").lower()
    for forbidden in (
        "faster-whisper",
        "qwen",
        "parakeet",
        "openai_api_key",
        "allow-metered-cloud",
        "engine-policy",
    ):
        assert forbidden not in source
    assert 'repos" / "asr" / "scripts" / "asr_engine.py' in source
