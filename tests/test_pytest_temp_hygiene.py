from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

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


def test_active_session_is_not_removed_by_concurrent_cleanup(tmp_path: Path) -> None:
    temproot = tmp_path / "temproot"
    temproot.mkdir()
    active_dir = tmp_path / "nested-active"
    active_dir.mkdir()
    ready_file = tmp_path / "active-ready"
    active_test = active_dir / "test_active.py"
    active_test.write_text(
        "from pathlib import Path\n"
        "import time\n"
        "def test_active(tmp_path):\n"
        "    payload = tmp_path / 'payload'\n"
        "    payload.write_text('alive')\n"
        f"    Path({str(ready_file)!r}).write_text(str(payload))\n"
        "    time.sleep(2)\n"
        "    assert payload.read_text() == 'alive'\n",
        encoding="utf-8",
    )
    peer_dir = tmp_path / "nested-peer"
    peer_dir.mkdir()
    peer_test = peer_dir / "test_peer.py"
    peer_test.write_text(
        "def test_peer(tmp_path):\n"
        "    (tmp_path / 'peer').write_text('ok')\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PYTEST_ADDOPTS"] = _pytest_addopts()
    env["PYTEST_DEBUG_TEMPROOT"] = str(temproot)
    active = subprocess.Popen(
        [sys.executable, "-m", "pytest", "-q", str(active_test)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=active_dir,
    )
    deadline = time.monotonic() + 10
    while not ready_file.exists() and active.poll() is None and time.monotonic() < deadline:
        time.sleep(0.02)
    assert ready_file.exists(), active.communicate()[0:2]
    active_payload = Path(ready_file.read_text(encoding="utf-8"))
    assert active_payload.read_text(encoding="utf-8") == "alive"

    peer = _run_nested_pytest(temproot, peer_test)
    assert peer.returncode == 0, peer.stdout + peer.stderr
    assert active_payload.read_text(encoding="utf-8") == "alive"

    stdout, stderr = active.communicate(timeout=10)
    assert active.returncode == 0, stdout + stderr
