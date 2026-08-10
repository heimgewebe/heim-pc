from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT_D = ROOT / "systemd/environment.d/60-heim-pc-pytest-temp-hygiene.conf"


def _pytest_addopts() -> str:
    for raw_line in ENVIRONMENT_D.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("PYTEST_ADDOPTS="):
            value = line.split("=", 1)[1]
            parsed = shlex.split(value)
            assert len(parsed) == 1
            return parsed[0]
    raise AssertionError("PYTEST_ADDOPTS is missing")


def _numbered_sessions(temproot: Path) -> list[Path]:
    sessions: list[Path] = []
    for user_root in temproot.glob("pytest-of-*"):
        for path in user_root.glob("pytest-*"):
            suffix = path.name.removeprefix("pytest-")
            if suffix.isdigit() and path.is_dir():
                sessions.append(path)
    return sessions


def _run_nested_pytest(temproot: Path, test_file: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTEST_ADDOPTS"] = _pytest_addopts()
    env["PYTEST_DEBUG_TEMPROOT"] = str(temproot)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", str(test_file)],
        text=True,
        capture_output=True,
        check=False,
        env=env,
        cwd=test_file.parent,
    )


def test_successful_session_removes_tmp_path_evidence(tmp_path: Path) -> None:
    temproot = tmp_path / "temproot"
    temproot.mkdir()
    nested = tmp_path / "nested-ok"
    nested.mkdir()
    test_file = nested / "test_ok.py"
    test_file.write_text(
        "def test_ok(tmp_path):\n"
        "    (tmp_path / 'payload').write_bytes(b'x' * 4096)\n",
        encoding="utf-8",
    )

    completed = _run_nested_pytest(temproot, test_file)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert _numbered_sessions(temproot) == []


def test_failed_sessions_are_bounded_to_one(tmp_path: Path) -> None:
    temproot = tmp_path / "temproot"
    temproot.mkdir()
    nested = tmp_path / "nested-fail"
    nested.mkdir()
    test_file = nested / "test_fail.py"
    test_file.write_text(
        "def test_fail(tmp_path):\n"
        "    (tmp_path / 'evidence').write_text('keep me')\n"
        "    assert False\n",
        encoding="utf-8",
    )

    first = _run_nested_pytest(temproot, test_file)
    second = _run_nested_pytest(temproot, test_file)

    assert first.returncode == 1
    assert second.returncode == 1
    sessions = _numbered_sessions(temproot)
    assert len(sessions) <= 1
    assert sessions
