from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pytest_temp_gc", ROOT / "scripts/pytest_temp_gc.py")
assert SPEC and SPEC.loader
gc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gc)


def garbage(root: Path) -> Path:
    path = root / f"garbage-{uuid.uuid4()}"
    path.mkdir()
    return path


def test_dead_lock_pid_removes_read_only_tree() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        candidate = garbage(root)
        nested = candidate / "nested"
        nested.mkdir()
        payload = nested / "payload"
        payload.write_text("x", encoding="utf-8")
        os.chmod(nested, 0o555)
        lock = candidate / ".lock"
        lock.write_text("2147483647", encoding="ascii")
        old = time.time() - 1200
        os.utime(lock, (old, old))

        report = gc.collect(root, now=time.time(), min_age_seconds=600, mounts=[])

        assert report["status"] == "ok"
        assert report["removed"] == 1
        assert not candidate.exists()


def test_missing_lock_is_never_removed() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        candidate = garbage(root)
        old = time.time() - 1200
        os.utime(candidate, (old, old))

        report = gc.collect(root, now=time.time(), min_age_seconds=600, mounts=[])

        assert candidate.exists()
        assert report["removed"] == 0
        assert report["candidates"][0]["reason"] == "missing_lock"


def test_live_lock_pid_is_never_removed() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        candidate = garbage(root)
        lock = candidate / ".lock"
        lock.write_text(str(os.getpid()), encoding="ascii")
        old = time.time() - 1200
        os.utime(lock, (old, old))

        report = gc.collect(root, now=time.time(), min_age_seconds=600, mounts=[])

        assert candidate.exists()
        assert report["removed"] == 0
        assert report["candidates"][0]["reason"] == "lock_pid_alive"


def test_young_dead_lock_is_not_removed() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        candidate = garbage(root)
        lock = candidate / ".lock"
        lock.write_text("2147483647", encoding="ascii")

        report = gc.collect(root, now=time.time(), min_age_seconds=600, mounts=[])

        assert candidate.exists()
        assert report["candidates"][0]["reason"] == "too_young"


def test_non_garbage_pytest_sessions_are_out_of_scope() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        numbered = root / "pytest-123"
        numbered.mkdir()
        (numbered / ".lock").write_text("2147483647", encoding="ascii")
        current = root / "pytest-current"
        current.symlink_to(numbered.name)

        report = gc.collect(root, now=time.time() + 10000, min_age_seconds=600, mounts=[])

        assert report["candidates"] == []
        assert numbered.exists()
        assert current.is_symlink()


def test_mount_or_foreign_owner_invariant_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        candidate = garbage(root)
        lock = candidate / ".lock"
        lock.write_text("2147483647", encoding="ascii")
        old = time.time() - 1200
        os.utime(lock, (old, old))

        report = gc.collect(
            root,
            now=time.time(),
            min_age_seconds=600,
            mounts=[candidate / "nested-mount"],
        )

        assert candidate.exists()
        assert report["candidates"][0]["reason"] == "mount_present"


def test_special_files_fail_closed() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        candidate = garbage(root)
        fifo = candidate / "fifo"
        os.mkfifo(fifo)
        lock = candidate / ".lock"
        lock.write_text("2147483647", encoding="ascii")
        old = time.time() - 1200
        os.utime(lock, (old, old))

        report = gc.collect(root, now=time.time(), min_age_seconds=600, mounts=[])

        assert candidate.exists()
        assert report["candidates"][0]["reason"] == "special_file"


def test_tree_entry_limit_stops_lazy_fanout_early() -> None:
    consumed = 0
    closed = False
    uid = os.getuid()
    root_dev = 123

    class Entry:
        def __init__(self, number: int):
            self.path = f"/candidate/file-{number}"

        def stat(self, *, follow_symlinks: bool):
            assert follow_symlinks is False
            return SimpleNamespace(
                st_uid=uid,
                st_dev=root_dev,
                st_mode=stat.S_IFREG | 0o600,
            )

    def entries(_path):
        nonlocal consumed
        for number in range(10_000):
            consumed += 1
            yield Entry(number)

    class Scan:
        def __init__(self, path):
            self.entries = entries(path)

        def __iter__(self):
            return self

        def __next__(self):
            return next(self.entries)

        def __enter__(self):
            return self

        def __exit__(self, *exception):
            nonlocal closed
            self.entries.close()
            closed = True

    with patch.object(gc.os, "scandir", side_effect=Scan):
        safe, reason, seen = gc._tree_safety(
            Path("/candidate"), uid, root_dev, max_entries=4
        )

    assert (safe, reason, seen) == (False, "entry_limit_exceeded", 5)
    assert consumed == 5
    assert closed


def test_process_reference_scans_proc_and_fds_lazily() -> None:
    candidate = Path("/tmp/candidate")
    proc_root = Path("/test-proc")
    uid = os.getuid()
    proc_consumed = 0
    fd_consumed = 0
    process_probed = False
    fd_probed = False

    def proc_entries():
        nonlocal proc_consumed
        proc_consumed += 1
        yield SimpleNamespace(name="100", path=str(proc_root / "100"))
        proc_consumed += 1
        assert process_probed

    def fd_entries():
        nonlocal fd_consumed
        fd_consumed += 1
        yield SimpleNamespace(name="3", path=str(proc_root / "100" / "fd" / "3"))
        fd_consumed += 1
        assert fd_probed

    class Scan:
        def __init__(self, path):
            path = Path(path)
            if path == proc_root:
                self.entries = proc_entries()
            elif path == proc_root / "100" / "fd":
                self.entries = fd_entries()
            else:
                raise AssertionError(f"unexpected scan: {path}")

        def __iter__(self):
            return self

        def __next__(self):
            return next(self.entries)

        def __enter__(self):
            return self

        def __exit__(self, *exception):
            self.entries.close()

    def target(link: Path):
        nonlocal process_probed, fd_probed
        if link.parent == proc_root / "100":
            process_probed = True
        if link.parent == proc_root / "100" / "fd":
            fd_probed = True
        return None

    with (
        patch.object(gc.os, "scandir", side_effect=Scan),
        patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=uid)),
        patch.object(gc, "_target_from_proc_link", side_effect=target),
    ):
        refs = gc.process_references(candidate, uid, proc_root=proc_root)

    assert refs == []
    assert (proc_consumed, fd_consumed) == (2, 2)
    assert process_probed
    assert fd_probed


def test_collect_starts_candidate_evaluation_before_full_root_enumeration() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        first = root / f"garbage-{uuid.uuid4()}"
        consumed = 0
        evaluated = False

        def entries(path):
            nonlocal consumed
            assert Path(path) == root
            consumed += 1
            yield SimpleNamespace(name=first.name, path=str(first))
            consumed += 1
            assert evaluated

        class Scan:
            def __init__(self, path):
                self.entries = entries(path)

            def __iter__(self):
                return self

            def __next__(self):
                return next(self.entries)

            def __enter__(self):
                return self

            def __exit__(self, *exception):
                self.entries.close()

        def evaluate(candidate: Path, **_kwargs):
            nonlocal evaluated
            evaluated = True
            return {
                "path": str(candidate),
                "name": candidate.name,
                "decision": "skip",
                "reason": "test",
            }

        with (
            patch.object(gc.os, "scandir", side_effect=Scan),
            patch.object(gc, "evaluate_candidate", side_effect=evaluate),
        ):
            report = gc.collect(
                root,
                now=time.time(),
                min_age_seconds=600,
                mounts=[],
            )

    assert report["status"] == "ok"
    assert consumed == 2
    assert evaluated


def test_systemd_service_sees_host_tmp_and_runs_as_alex() -> None:
    service = (ROOT / "systemd/system/heim-pc-pytest-temp-gc.service").read_text(encoding="utf-8")
    timer = (ROOT / "systemd/system/heim-pc-pytest-temp-gc.timer").read_text(encoding="utf-8")

    assert "User=alex" in service
    assert "Group=alex" in service
    assert "PrivateTmp=no" in service
    assert "ProtectSystem=strict" in service
    assert "ReadOnlyPaths=/tmp" in service
    assert "ReadWritePaths=-/tmp/pytest-of-alex" in service
    assert "ExecStart=/usr/local/bin/heim-pc-pytest-temp-gc --min-age-seconds 600" in service
    assert "OnBootSec=10min" in timer
    assert "OnUnitActiveSec=10min" in timer


def test_dry_run_reports_eligible_without_claiming_removal() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        candidate = garbage(root)
        lock = candidate / ".lock"
        lock.write_text("2147483647", encoding="ascii")
        old = time.time() - 1200
        os.utime(lock, (old, old))

        report = gc.collect(
            root, now=time.time(), min_age_seconds=600, mounts=[], dry_run=True
        )

        assert candidate.exists()
        assert report["eligible"] == 1
        assert report["removed"] == 0


def test_live_process_cwd_inside_candidate_blocks_removal() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        candidate = garbage(root)
        lock = candidate / ".lock"
        lock.write_text("2147483647", encoding="ascii")
        old = time.time() - 1200
        os.utime(lock, (old, old))
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"], cwd=candidate
        )
        try:
            report = gc.collect(
                root, now=time.time(), min_age_seconds=600, mounts=[]
            )
            assert candidate.exists()
            assert report["removed"] == 0
            assert report["candidates"][0]["reason"] == "process_reference"
            assert any(
                reference == f"pid={process.pid}:cwd"
                for reference in report["candidates"][0]["references"]
            )
        finally:
            process.terminate()
            process.wait(timeout=10)
