from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "asr_engine.py"
CANONICAL_OPERATOR_ENTRY = ROOT / "manifest" / "operator-entry.v1.json"


def _generic_target(home: Path) -> Path:
    target = home / "repos" / "asr" / "scripts" / "asr_engine.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        "import json, sys\nprint(json.dumps(sys.argv[1:]))\n",
        encoding="utf-8",
    )
    return target


def _install_projection(home: Path, value: bytes) -> None:
    target = home / ".config" / "heimgewebe" / "operator-entry.v1.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(value)


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


def test_compatibility_wrapper_warns_when_installed_projection_is_missing(tmp_path):
    _generic_target(tmp_path)
    result = _run_wrapper(tmp_path, "doctor")
    assert result.returncode == 0
    assert "operator-entry projection is missing or drifted" in result.stderr
    assert "--apply --replace-existing" in result.stderr
    assert "--require-installed" in result.stderr


def test_compatibility_wrapper_warns_when_installed_projection_is_stale(tmp_path):
    _generic_target(tmp_path)
    _install_projection(tmp_path, b"{\"schemaVersion\":1}\n")
    result = _run_wrapper(tmp_path, "doctor")
    assert result.returncode == 0
    assert "operator-entry projection is missing or drifted" in result.stderr


def test_compatibility_wrapper_is_quiet_when_projection_matches(tmp_path):
    _generic_target(tmp_path)
    _install_projection(tmp_path, CANONICAL_OPERATOR_ENTRY.read_bytes())
    result = _run_wrapper(tmp_path, "route", "--audio", "/tmp/a.m4a", "--json")
    assert result.returncode == 0
    assert json.loads(result.stdout) == ["route", "--audio", "/tmp/a.m4a", "--json"]
    assert result.stderr == ""


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
