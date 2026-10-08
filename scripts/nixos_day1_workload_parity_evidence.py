#!/usr/bin/env python3
"""Build fail-closed Day-1 workload-parity runtime evidence.

This helper does not classify workloads and never grants readiness. It only
validates one fresh, bounded heim-pc inventory observation against the reviewed
Day-1 contract and can bind that evidence into ``inventory.current_binding``.
"""
from __future__ import annotations

import argparse
import copy
from contextlib import closing, contextmanager
import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "nixos/production/day1-workload-parity-contract-v1.json"
DEFAULT_EVIDENCE = (
    ROOT / "nixos/production/day1-workload-parity-current-evidence-v1.json"
)
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TASK_ID_RE = re.compile(r"^[0-9a-f]{16,64}$")
TASK_STATE_ROOT = Path.home() / ".local/state/grabowski"


class Day1EvidenceError(RuntimeError):
    pass


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _snapshot_output_bytes(path: Path, *, max_bytes: int = 32 * 1024 * 1024) -> bytes:
    """Read one regular output from a stable descriptor and path identity."""
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    def identity(info: os.stat_result) -> tuple[int, ...]:
        return (
            info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_uid, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
        )

    if not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise Day1EvidenceError(f"inventory output path must be absolute and normalized: {path}")

    # O_NOFOLLOW on the final component alone does not protect runtime/ or
    # any other ancestor. Traverse every component from / using directory
    # descriptors and refuse symlinks at every level.
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    try:
        directory_fd = os.open("/", directory_flags)
        try:
            for component in path.parts[1:-1]:
                next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            linked_before = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(linked_before.st_mode)
                or linked_before.st_nlink != 1
                or linked_before.st_uid != os.getuid()
                or linked_before.st_size > max_bytes
            ):
                raise Day1EvidenceError(f"unsafe inventory output: {path}")
            descriptor = os.open(path.name, flags, dir_fd=directory_fd)
            try:
                opened_before = os.fstat(descriptor)
                if identity(linked_before) != identity(opened_before):
                    raise Day1EvidenceError(f"inventory output changed during open: {path}")
                chunks: list[bytes] = []
                remaining = opened_before.st_size
                while remaining:
                    chunk = os.read(descriptor, min(65536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                opened_after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            linked_after = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise Day1EvidenceError(f"cannot read stable inventory output: {path}") from exc
    if (
        remaining != 0
        or identity(opened_before) != identity(opened_after)
        or identity(opened_before) != identity(linked_after)
    ):
        raise Day1EvidenceError(f"inventory output changed during snapshot: {path}")
    return b"".join(chunks)


def _verify_current_output_snapshots(root: Path, snapshots: dict[str, bytes]) -> None:
    for relpath, original in snapshots.items():
        if _snapshot_output_bytes(root / relpath) != original:
            raise Day1EvidenceError(f"bound output changed after verified snapshot: {relpath}")


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Day1EvidenceError(f"invalid RFC3339 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise Day1EvidenceError(f"timestamp has no timezone: {value!r}")
    return parsed.astimezone(timezone.utc)


def _frontmatter(path: Path, *, snapshot: bytes | None = None) -> dict[str, str]:
    try:
        lines = (snapshot if snapshot is not None else path.read_bytes()).decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise Day1EvidenceError(f"{path} is not UTF-8") from exc
    if not lines or lines[0] != "---":
        raise Day1EvidenceError(f"{path} is missing YAML frontmatter")
    out: dict[str, str] = {}
    for line in lines[1:]:
        if line == "---":
            return out
        if not line or line.startswith((" ", "\t")) or ":" not in line:
            continue
        key, raw = line.split(":", 1)
        value = raw.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        out[key.strip()] = value
    raise Day1EvidenceError(f"{path} has unterminated YAML frontmatter")


def _bool_field(value: str | None, *, field: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise Day1EvidenceError(f"{field} must be true or false")


def _git_blob(root: Path, revision: str, relpath: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), "show", f"{revision}:{relpath}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise Day1EvidenceError(
            f"cannot read {relpath} from source revision {revision}: {detail}"
        )
    return completed.stdout


def _reviewed_source_bytes(root: Path, revision: str, relpath: str) -> bytes:
    source = _git_blob(root, revision, relpath)
    worktree = (root / relpath).read_bytes()
    if _sha256_bytes(worktree) != _sha256_bytes(source):
        raise Day1EvidenceError(
            f"{relpath} does not match reviewed source revision {revision}"
        )
    return source


def _source_file_digest(root: Path, revision: str, relpath: str) -> str:
    return _sha256_bytes(_reviewed_source_bytes(root, revision, relpath))


def _require_hex(value: str, pattern: re.Pattern[str], *, field: str) -> str:
    if not pattern.fullmatch(value):
        raise Day1EvidenceError(f"{field} has invalid digest/revision format")
    return value


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )


def _single_option_value(values: list[str], option: str, *, field: str) -> str:
    positions = [index for index, value in enumerate(values) if value == option]
    if len(positions) != 1:
        raise Day1EvidenceError(f"{field} argv must bind exactly one {option}")
    index = positions[0]
    if index + 1 >= len(values):
        raise Day1EvidenceError(f"{field} argv is missing a value for {option}")
    return values[index + 1]


def _require_argv_binding(
    argv: Iterable[str],
    *,
    root: Path,
    expected_script: str,
    required_options: dict[str, str],
    field: str,
) -> list[str]:
    values = list(argv)
    if len(values) < 2:
        raise Day1EvidenceError(f"{field} argv is incomplete")
    if values[0] != "/usr/bin/python3" or values[1] != expected_script:
        raise Day1EvidenceError(
            f"{field} must execute /usr/bin/python3 {expected_script} directly"
        )
    expected_argv = ["/usr/bin/python3", expected_script]
    for option, expected in required_options.items():
        actual = _single_option_value(values, option, field=field)
        if actual != expected:
            raise Day1EvidenceError(f"{field} argv does not bind {option}")
        expected_argv.extend((option, expected))
    if values != expected_argv:
        raise Day1EvidenceError(
            f"{field} argv is not the complete allowed command shape"
        )
    return values



def _validate_private_file(path: Path, *, max_bytes: int) -> None:
    """Check a private regular task artifact before opening it."""
    try:
        info = path.lstat()
    except OSError as exc:
        raise Day1EvidenceError("authoritative Grabowski task artifact is missing") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
        or info.st_size > max_bytes
    ):
        raise Day1EvidenceError("Grabowski task artifact fails private-file checks")


def _trusted_task_file(path: Path, *, max_bytes: int) -> bytes:
    _validate_private_file(path, max_bytes=max_bytes)
    return path.read_bytes()


def _authoritative_task_record(
    *,
    task_id: str,
    attempt: int,
    unit: str,
    host: str,
    cwd: Path,
    argv: list[str],
    argv_sha256: str,
    receipt_sha256: str,
) -> tuple[bytes, int, int]:
    """Resolve task outcome against the persistent operator ledger and receipt.

    Direct caller-provided receipt projections are not an authority source.
    The production store path is fixed by the executing operator user; tests
    replace TASK_STATE_ROOT with a private fixture, not via a CLI flag.
    """
    store = TASK_STATE_ROOT
    db_path = store / "tasks.sqlite3"
    # The file identity is checked before SQLite opens it, without eagerly
    # copying a potentially large task database into the binder's memory.
    _validate_private_file(db_path, max_bytes=128 * 1024 * 1024)
    try:
        with closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as db:
            db.row_factory = sqlite3.Row
            row = db.execute(
                "SELECT task_id, attempt, unit, authoritative_unit, host, cwd, "
                "state, argv_json, argv_sha256, lifecycle_receipt_sha256, "
                "created_at_unix, terminalized_at_unix, last_observation_json "
                "FROM tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
    except (sqlite3.Error, OSError) as exc:
        raise Day1EvidenceError("cannot resolve task in authoritative Grabowski ledger") from exc

    if row is None:
        raise Day1EvidenceError("task absent from authoritative Grabowski ledger")
    try:
        stored_argv = json.loads(row["argv_json"])
        observation = json.loads(row["last_observation_json"])
    except (ValueError, TypeError) as exc:
        raise Day1EvidenceError("Grabowski task ledger has malformed execution evidence") from exc
    if (
        row["task_id"] != task_id
        or row["attempt"] != attempt
        or row["unit"] != unit
        or row["authoritative_unit"] != unit
        or row["host"] != host
        or row["cwd"] != str(cwd)
        or row["state"] != "completed"
        or stored_argv != argv
        or row["argv_sha256"] != argv_sha256
        or row["lifecycle_receipt_sha256"] != receipt_sha256
        or not isinstance(row["created_at_unix"], int)
        or row["created_at_unix"] < 1
        or not isinstance(row["terminalized_at_unix"], int)
        or row["terminalized_at_unix"] < row["created_at_unix"]
        or observation.get("state") != "completed"
        or observation.get("properties", {}).get("Result") != "success"
        or observation.get("properties", {}).get("ExecMainStatus") != "0"
    ):
        raise Day1EvidenceError("task projection differs from authoritative Grabowski ledger")

    receipt_path = store / "tasks.outcomes" / f"{task_id}.json"
    try:
        outcome = json.loads(_trusted_task_file(receipt_path, max_bytes=128 * 1024))
    except (ValueError, UnicodeDecodeError) as exc:
        raise Day1EvidenceError("Grabowski lifecycle receipt is invalid JSON") from exc
    expected_receipt = outcome.get("receipt_sha256")
    unsigned = dict(outcome)
    unsigned.pop("receipt_sha256", None)
    calculated = _sha256_bytes(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    if (
        expected_receipt != receipt_sha256
        or calculated != receipt_sha256
        or outcome.get("kind") != "grabowski_task_lifecycle_receipt"
        or outcome.get("schema_version") != 2
        or outcome.get("task_id") != task_id
        or outcome.get("attempt") != attempt
        or outcome.get("unit") != unit
        or outcome.get("authoritative_unit") != unit
        or outcome.get("argv_sha256") != argv_sha256
        or outcome.get("state") != "completed"
        or outcome.get("observed_at_unix") != row["terminalized_at_unix"]
        or outcome.get("observation", {}).get("state") != "completed"
    ):
        raise Day1EvidenceError("authoritative Grabowski lifecycle receipt mismatch")

    stdout_path = (
        store / "task-output" / f".grabowski-task-output-{task_id}-a{attempt}" / "stdout.log"
    )
    stdout_bytes = _trusted_task_file(stdout_path, max_bytes=8 * 1024 * 1024)

    # Do not mistake a fresh hash of mutable stdout.log for task-time
    # authenticity. Legacy lifecycle receipts lack terminal stdout sealing.
    sealed_sha = outcome.get("captured_stdout_sha256")
    sealed_size = outcome.get("captured_stdout_bytes")
    if (
        not isinstance(sealed_sha, str)
        or HEX64.fullmatch(sealed_sha) is None
        or isinstance(sealed_size, bool)
        or not isinstance(sealed_size, int)
        or sealed_size < 0
    ):
        raise Day1EvidenceError(
            "Grabowski lifecycle receipt lacks terminally sealed stdout digest"
        )
    if sealed_size != len(stdout_bytes) or sealed_sha != _sha256_bytes(stdout_bytes):
        raise Day1EvidenceError(
            "captured stdout differs from the terminally sealed lifecycle receipt"
        )
    return (stdout_bytes, row["created_at_unix"], row["terminalized_at_unix"])


def _captured_json(stdout: bytes, *, field: str) -> dict[str, Any]:
    try:
        value = json.loads(stdout.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise Day1EvidenceError(f"{field} captured output is not valid JSON") from exc
    if not isinstance(value, dict):
        raise Day1EvidenceError(f"{field} captured output must be a JSON object")
    return value


def _verify_renderer_stdout(
    captured_stdout: bytes, *,
    host: str, observation_id: str, generated_at: str,
    summary_bytes: bytes, json_bytes: bytes,
) -> None:
    """Require the exact renderer-runtime stdout claim about complete files.

    This binds syntax and bytes to the existing lifecycle receipt. It is NOT
    independent same-UID authentication until Grabowski supplies a separately
    protected terminal-stdout proof and an immutable evidence consumer.
    """
    expected = {
        "kind": "heim_pc.program_renderer_output",
        "schema_version": 1,
        "host": host,
        "observation_id": observation_id,
        "generated_at": generated_at,
        "generated_at_source": "renderer_runtime_clock",
        "summary_sha256": _sha256_bytes(summary_bytes),
        "summary_bytes": len(summary_bytes),
        "json_sha256": _sha256_bytes(json_bytes),
        "json_bytes": len(json_bytes),
    }
    exact_stdout = (
        json.dumps(expected, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    if len(captured_stdout) > 2048 or captured_stdout != exact_stdout:
        raise Day1EvidenceError(
            "renderer captured stdout does not bind runtime generated_at "
            "and complete program summary/JSON output bytes"
        )


def _verify_execution_receipt(
    receipt: dict[str, Any],
    *,
    root: Path,
    authoritative_host: str,
    expected_script: str,
    required_options: dict[str, str],
    field: str,
) -> dict[str, Any]:
    task_id = receipt.get("task_id")
    if not isinstance(task_id, str) or TASK_ID_RE.fullmatch(task_id) is None:
        raise Day1EvidenceError(f"{field} receipt task_id is invalid")
    attempt = receipt.get("attempt")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise Day1EvidenceError(f"{field} receipt attempt is invalid")
    expected_unit = f"grabowski-task-{task_id}-a{attempt}.service"
    if receipt.get("unit") != expected_unit:
        raise Day1EvidenceError(f"{field} receipt unit is not task/attempt bound")
    if receipt.get("host") != authoritative_host:
        raise Day1EvidenceError(f"{field} receipt host is not authoritative heim-pc")
    if receipt.get("state") != "completed":
        raise Day1EvidenceError(f"{field} receipt is not terminal successful")
    cwd = receipt.get("cwd")
    if not isinstance(cwd, str) or Path(cwd).resolve() != root:
        raise Day1EvidenceError(f"{field} receipt cwd is not the bound repository root")

    argv = receipt.get("argv")
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        raise Day1EvidenceError(f"{field} receipt argv must be an array of strings")
    argv = _require_argv_binding(
        argv,
        root=root,
        expected_script=expected_script,
        required_options=required_options,
        field=field,
    )
    argv_sha256 = receipt.get("argv_sha256")
    if not isinstance(argv_sha256, str) or HEX64.fullmatch(argv_sha256) is None:
        raise Day1EvidenceError(f"{field} receipt argv_sha256 is invalid")
    if argv_sha256 != _sha256_json(argv):
        raise Day1EvidenceError(f"{field} receipt argv_sha256 does not authenticate argv")

    lifecycle_receipt_sha256 = receipt.get("lifecycle_receipt_sha256")
    if (
        not isinstance(lifecycle_receipt_sha256, str)
        or HEX64.fullmatch(lifecycle_receipt_sha256) is None
    ):
        raise Day1EvidenceError(f"{field} lifecycle receipt digest is invalid")
    captured_stdout, task_created_at_unix, task_terminalized_at_unix = _authoritative_task_record(
        task_id=task_id,
        attempt=attempt,
        unit=expected_unit,
        host=authoritative_host,
        cwd=root,
        argv=argv,
        argv_sha256=argv_sha256,
        receipt_sha256=lifecycle_receipt_sha256,
    )

    return {
        "task_id": task_id,
        "attempt": attempt,
        "unit": expected_unit,
        "host": authoritative_host,
        "state": "completed",
        "cwd": str(root),
        "argv": argv,
        "argv_sha256": argv_sha256,
        "lifecycle_receipt_sha256": lifecycle_receipt_sha256,
        "task_created_at_unix": task_created_at_unix,
        "task_terminalized_at_unix": task_terminalized_at_unix,
        "captured_stdout_sha256": _sha256_bytes(captured_stdout),
        "captured_stdout": captured_stdout,
    }


def _raw_manifest_sha256(raw_dir: Path) -> tuple[str, int]:
    entries: list[tuple[str, str]] = []
    paths = sorted(raw_dir.iterdir(), key=lambda item: item.name)
    if len(paths) > 256:
        raise Day1EvidenceError("program raw evidence has too many entries")
    for path in paths:
        if path.name in {"run-result.json", "SUMMARY.md"}:
            continue
        entries.append((
            path.name,
            _sha256_bytes(_snapshot_output_bytes(path, max_bytes=64 * 1024 * 1024)),
        ))
    payload = "".join(f"{name}\0{digest}\n" for name, digest in entries).encode()
    return _sha256_bytes(payload), len(entries)

@contextmanager
def _snapshot_program_raw_dir(raw_dir: Path) -> Iterator[Path]:
    """Boundedly copy raw evidence once so manifest and renderer see one byte set.

    The private copy is *not* an independent same-UID attestation. It prevents
    unintended mixing of collection bytes between two verification steps.
    """
    with tempfile.TemporaryDirectory(prefix="heim-pc-day1-raw-") as tmp:
        copied_dir = Path(tmp) / "raw"
        copied_dir.mkdir(mode=0o700)
        try:
            entries = sorted(raw_dir.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            raise Day1EvidenceError("program raw evidence directory is inaccessible") from exc
        if len(entries) > 256:
            raise Day1EvidenceError("program raw evidence has too many entries")
        total = 0
        for entry in entries:
            raw = _snapshot_output_bytes(entry, max_bytes=64 * 1024 * 1024)
            total += len(raw)
            if total > 256 * 1024 * 1024:
                raise Day1EvidenceError("program raw evidence exceeds snapshot bound")
            with (copied_dir / entry.name).open("xb") as handle:
                handle.write(raw)
        yield copied_dir


def _verify_program_raw_run(
    raw_dir: Path,
    *,
    recorded_raw_dir: Path | None = None,
    authoritative_host: str,
    observation_id: str,
    observed_at: str,
    collector_sha256: str,
    raw_manifest_sha256: str,
    raw_artifact_count: int,
) -> dict[str, Any]:
    if not raw_dir.is_dir():
        raise Day1EvidenceError("program raw inventory directory is missing")
    run_result_path = raw_dir / "run-result.json"
    try:
        run_result = json.loads(run_result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Day1EvidenceError("program raw run-result is missing or invalid") from exc
    expected = {
        "out": str(recorded_raw_dir if recorded_raw_dir is not None else raw_dir),
        "host": authoritative_host,
        "observation_id": observation_id,
        "observed_at": observed_at,
        "collector_sha256": collector_sha256,
        "raw_manifest_sha256": raw_manifest_sha256,
        "raw_artifact_count": raw_artifact_count,
        "binding_eligible": True,
    }
    for key, value in expected.items():
        if run_result.get(key) != value:
            raise Day1EvidenceError(f"program raw run-result mismatches {key}")
    manifest, count = _raw_manifest_sha256(raw_dir)
    if manifest != raw_manifest_sha256 or count != raw_artifact_count:
        raise Day1EvidenceError("program raw manifest does not match the collected raw run")
    return run_result


def _verify_renderer_outputs(
    *,
    root: Path,
    renderer_relpath: str,
    raw_dir: Path,
    generated_at: str,
    summary_bytes: bytes,
    json_bytes: bytes,
    source_inventory_path: str,
    renderer_source: bytes,
) -> None:
    with tempfile.TemporaryDirectory(prefix="heim-pc-day1-render-") as tmp:
        tmp_root = Path(tmp)
        expected_summary = tmp_root / "program-inventory-summary.md"
        expected_json = tmp_root / "program-inventory.v1.json"
        # Execute the exact reviewed Git blob over a private stdin pipe;
        # reopening the worktree script pathname after digest verification
        # would allow another same-UID process to swap its code before Python
        # loads it. The trusted wrapper restores argv and __file__ semantics.
        if not renderer_source or len(renderer_source) > 1024 * 1024:
            raise Day1EvidenceError("reviewed renderer source size is invalid")
        runner = (
            "import sys\n"
            "script_path = sys.argv[1]\n"
            "args = sys.argv[2:]\n"
            "script_source = sys.stdin.buffer.read()\n"
            "sys.argv = [script_path, *args]\n"
            "scope = {'__name__': '__main__', '__file__': script_path}\n"
            "exec(compile(script_source, script_path, 'exec'), scope)\n"
        )
        completed = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                "-c",
                runner,
                str(root / renderer_relpath),
                "--raw-dir",
                str(raw_dir),
                "--summary-out",
                str(expected_summary),
                "--json-out",
                str(expected_json),
                "--generated-at",
                generated_at,
            ],
            cwd=root,
            check=False,
            input=renderer_source,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
        if completed.returncode != 0:
            raise Day1EvidenceError(
                "program renderer verification failed: "
                + completed.stderr.decode("utf-8", errors="replace").strip()[:500]
            )
        # Rendering from a private snapshot changes only the *displayed* raw
        # source path. Normalize that field to the authenticated original path;
        # all other computed content must stay byte-for-byte identical.
        snapshot_path = str(raw_dir)
        rendered_summary = expected_summary.read_text(encoding="utf-8")
        marker = f"Raw inventory source: `{snapshot_path}`"
        if "Raw inventory source:" in rendered_summary:
            if rendered_summary.count(marker) != 1:
                raise Day1EvidenceError("renderer raw source display is ambiguous")
            rendered_summary = rendered_summary.replace(
                marker, f"Raw inventory source: `{source_inventory_path}`"
            )
        if rendered_summary.encode("utf-8") != summary_bytes:
            raise Day1EvidenceError(
                "program summary is not the deterministic render of the bound raw run"
            )
        try:
            rendered_json = json.loads(expected_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise Day1EvidenceError("program renderer output is not valid JSON") from exc
        if rendered_json.get("source_inventory_path") != snapshot_path:
            raise Day1EvidenceError("renderer raw source path does not match snapshot")
        rendered_json["source_inventory_path"] = source_inventory_path
        normalized_json = (
            json.dumps(rendered_json, indent=2, ensure_ascii=False, sort_keys=True)
            + "\n"
        ).encode("utf-8")
        if normalized_json != json_bytes:
            raise Day1EvidenceError(
                "program JSON is not the deterministic render of the bound raw run"
            )


def build_current_binding(
    *,
    root: Path,
    contract_path: Path,
    source_revision: str,
    observation_id: str,
    started_at: str,
    completed_at: str,
    software_execution_receipt: dict[str, Any],
    program_execution_receipt: dict[str, Any],
    program_renderer_execution_receipt: dict[str, Any],
) -> dict[str, Any]:
    root = root.resolve()
    _require_hex(source_revision, HEX40, field="source_revision")
    _require_hex(observation_id, HEX64, field="observation_id")

    contract_path = contract_path.resolve()
    try:
        contract_relpath = contract_path.relative_to(root).as_posix()
    except ValueError as exc:
        raise Day1EvidenceError("contract path must be inside repository root") from exc
    try:
        contract = json.loads(
            _git_blob(root, source_revision, contract_relpath).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Day1EvidenceError(
            "reviewed Day-1 contract is not valid UTF-8 JSON"
        ) from exc
    inventory = contract["inventory"]
    schema = inventory["current_binding_schema"]
    authoritative_host = inventory["authoritative_host"]


    started = _parse_time(started_at)
    completed = _parse_time(completed_at)
    if completed < started:
        raise Day1EvidenceError("observation completed_at precedes started_at")

    expected_paths = list(schema["required_output_paths"])
    if expected_paths != list(inventory["canonical_outputs"]):
        raise Day1EvidenceError("contract required outputs diverge from canonical outputs")

    # All metadata, authenticated digests and binding hashes use identical bytes.
    snapshots = {relpath: _snapshot_output_bytes(root / relpath) for relpath in expected_paths}
    outputs: list[dict[str, Any]] = []
    metadata: dict[str, dict[str, Any]] = {}

    software_path = root / "runtime/software-inventory.md"
    software_meta = _frontmatter(software_path, snapshot=snapshots["runtime/software-inventory.md"])
    software_observed_at = software_meta.get("observed_at", "")
    software_id = software_meta.get("observation_id", "")
    software_binding = _bool_field(
        software_meta.get("binding_eligible"), field="software binding_eligible"
    )
    if software_meta.get("observed_host") != authoritative_host:
        raise Day1EvidenceError("software inventory host is not authoritative heim-pc")
    if software_id != observation_id or not software_binding:
        raise Day1EvidenceError("software inventory is not binding-eligible for session")
    software_observed = _parse_time(software_observed_at)
    if not (started <= software_observed <= completed):
        raise Day1EvidenceError("software observed_at falls outside observation session")
    metadata["runtime/software-inventory.md"] = {
        "observed_at": software_observed_at,
        "observation_id": software_id,
        "binding_eligible": software_binding,
    }

    summary_path = root / "runtime/program-inventory-summary.md"
    summary_meta = _frontmatter(summary_path, snapshot=snapshots["runtime/program-inventory-summary.md"])
    summary_observed_at = summary_meta.get("observed_at", "")
    summary_id = summary_meta.get("observation_id", "")
    summary_binding = _bool_field(
        summary_meta.get("binding_eligible"), field="program summary binding_eligible"
    )
    summary_observed = _parse_time(summary_observed_at)
    if summary_id != observation_id or not summary_binding:
        raise Day1EvidenceError("program summary is not binding-eligible for session")
    if not (started <= summary_observed <= completed):
        raise Day1EvidenceError("program summary observed_at falls outside observation session")
    metadata["runtime/program-inventory-summary.md"] = {
        "observed_at": summary_observed_at,
        "observation_id": summary_id,
        "binding_eligible": summary_binding,
    }

    program_path = root / "runtime/program-inventory.v1.json"
    program = json.loads(snapshots["runtime/program-inventory.v1.json"].decode("utf-8"))
    scope = program.get("observation_scope", {})
    provenance = program.get("collection_provenance", {})
    program_observed_at = str(scope.get("observed_at", ""))
    program_generated_at = str(program.get("generated_at", ""))
    program_generated = _parse_time(program_generated_at)
    program_id = scope.get("observation_id")
    program_binding = scope.get("binding_eligible")
    program_observed = _parse_time(program_observed_at)
    if program_id != observation_id or program_binding is not True:
        raise Day1EvidenceError("program JSON is not binding-eligible for session")
    if not (started <= program_observed <= completed):
        raise Day1EvidenceError("program JSON observed_at falls outside observation session")
    if not (program_observed <= program_generated <= completed):
        raise Day1EvidenceError(
            "program generated_at falls outside session or predates program observation"
        )
    if provenance.get("host") != authoritative_host:
        raise Day1EvidenceError("program inventory host is not authoritative heim-pc")
    source_inventory_path = program.get("source_inventory_path")
    if not isinstance(source_inventory_path, str) or not source_inventory_path:
        raise Day1EvidenceError("program inventory is missing source_inventory_path")
    raw_dir = Path(source_inventory_path).expanduser().resolve()
    home = str(Path.home())
    canonical_source_path = str(raw_dir)
    if canonical_source_path == home:
        canonical_source_path = "~"
    elif canonical_source_path.startswith(home + "/"):
        canonical_source_path = "~" + canonical_source_path[len(home):]
    if source_inventory_path != canonical_source_path:
        raise Day1EvidenceError(
            "program inventory source path differs from canonical renderer path"
        )
    metadata["runtime/program-inventory.v1.json"] = {
        "observed_at": program_observed_at,
        "observation_id": program_id,
        "binding_eligible": True,
    }

    if len({item["observation_id"] for item in metadata.values()}) != 1:
        raise Day1EvidenceError("required outputs do not share one observation_id")

    software_script = schema["provenance"]["software"]["collector_path"]
    program_schema = schema["provenance"]["program"]
    program_collector = program_schema["collector_path"]
    program_renderer = program_schema["renderer_path"]
    renderer_protocol = program_schema.get("renderer_runtime_protocol")
    if renderer_protocol != {
        "kind": "heim_pc.renderer_runtime_provenance_v1",
        "live_argv_must_omit_generated_at": True,
        "generated_at_source": "renderer_runtime_clock",
        "captured_stdout_kind": "heim_pc.program_renderer_output",
        "captured_full_output_sha256_and_bytes_required": True,
        "offline_rerender_override_only": True,
        "independent_stdout_authentication_required_before_admission": True,
    }:
        raise Day1EvidenceError(
            "reviewed Day-1 renderer runtime protocol is not exact"
        )

    software_execution = _verify_execution_receipt(
        software_execution_receipt,
        root=root,
        authoritative_host=authoritative_host,
        expected_script=software_script,
        required_options={
            "--observation-id": observation_id,
            "--observed-at": software_observed_at,
        },
        field="software execution",
    )
    program_execution = _verify_execution_receipt(
        program_execution_receipt,
        root=root,
        authoritative_host=authoritative_host,
        expected_script=program_collector,
        required_options={
            "--observation-id": observation_id,
            "--observed-at": program_observed_at,
            "--output-dir": str(raw_dir),
        },
        field="program collector execution",
    )
    renderer_execution = _verify_execution_receipt(
        program_renderer_execution_receipt,
        root=root,
        authoritative_host=authoritative_host,
        expected_script=program_renderer,
        required_options={
            "--raw-dir": str(raw_dir),
            "--summary-out": str(summary_path),
            "--json-out": str(program_path),
            # Binding-eligible live executions MUST derive their generated_at
            # inside the process, not from an argv guess made before dispatch.
        },
        field="program renderer execution",
    )
    _verify_renderer_stdout(
        renderer_execution["captured_stdout"],
        host=authoritative_host,
        observation_id=observation_id,
        generated_at=program_generated_at,
        summary_bytes=snapshots["runtime/program-inventory-summary.md"],
        json_bytes=snapshots["runtime/program-inventory.v1.json"],
    )
    # These are validated *reported* fields, not independently trusted
    # task-time proof while ledger/stdout remain writable by the same UID.
    renderer_execution["reported_generated_at"] = program_generated_at
    renderer_execution["reported_generated_at_source"] = "renderer_runtime_clock"
    renderer_execution["reported_stdout_record_kind"] = "heim_pc.program_renderer_output"

    # Session assertions alone cannot establish freshness: the authoritative
    # Grabowski task ledger must place actual executions inside the window.
    execution_order = (software_execution, program_execution, renderer_execution)
    for execution in execution_order:
        begin = execution["task_created_at_unix"]
        end = execution["task_terminalized_at_unix"]
        if not (started.timestamp() <= begin <= end <= completed.timestamp()):
            raise Day1EvidenceError(
                "Grabowski task execution falls outside bounded observation session"
            )
    if not (
        software_execution["task_terminalized_at_unix"]
        <= program_execution["task_created_at_unix"]
        <= program_execution["task_terminalized_at_unix"]
        <= renderer_execution["task_created_at_unix"]
    ):
        raise Day1EvidenceError("Day-1 collector/renderer tasks are not serially ordered")
    if (
        software_execution["task_terminalized_at_unix"] < software_observed.timestamp()
        or program_execution["task_terminalized_at_unix"] < program_observed.timestamp()
        or renderer_execution["task_terminalized_at_unix"] < program_generated.timestamp()
    ):
        raise Day1EvidenceError("inventory observed/generated time postdates real task execution")
    if program_generated.timestamp() < program_execution["task_terminalized_at_unix"]:
        raise Day1EvidenceError(
            "program generated_at predates completed authenticated program collection"
        )
    if program_generated.timestamp() < renderer_execution["task_created_at_unix"]:
        raise Day1EvidenceError(
            "program generated_at predates authenticated renderer task start"
        )

    software_report = _captured_json(
        software_execution["captured_stdout"], field="software execution"
    )
    if software_report != {
        "kind": "heim_pc.software_inventory_output",
        "host": authoritative_host,
        "observed_at": software_observed_at,
        "observation_id": observation_id,
        "output_sha256": _sha256_bytes(snapshots["runtime/software-inventory.md"]),
    }:
        raise Day1EvidenceError(
            "software inventory does not match authenticated collector output"
        )

    for relpath in expected_paths:
        path = root / relpath
        if not path.is_file():
            raise Day1EvidenceError(f"required output missing: {relpath}")
        row = {"path": relpath, "sha256": _sha256_bytes(snapshots[relpath]), **metadata[relpath]}
        outputs.append(row)

    software_collector_sha = _source_file_digest(root, source_revision, software_script)
    program_collector_sha = _source_file_digest(root, source_revision, program_collector)
    reviewed_renderer_source = _reviewed_source_bytes(
        root, source_revision, program_renderer
    )
    program_renderer_sha = _sha256_bytes(reviewed_renderer_source)

    if software_meta.get("collector_sha256") != software_collector_sha:
        raise Day1EvidenceError("software output collector digest mismatches source revision")
    if provenance.get("collector_sha256") != program_collector_sha:
        raise Day1EvidenceError("program output collector digest mismatches source revision")

    raw_manifest_sha = str(provenance.get("raw_manifest_sha256", ""))
    _require_hex(raw_manifest_sha, HEX64, field="program raw_manifest_sha256")
    raw_artifact_count = provenance.get("raw_artifact_count")
    if not isinstance(raw_artifact_count, int) or raw_artifact_count < 1:
        raise Day1EvidenceError("program raw_artifact_count must be a positive integer")

    with _snapshot_program_raw_dir(raw_dir) as raw_snapshot:
        raw_run = _verify_program_raw_run(
            raw_snapshot,
            recorded_raw_dir=raw_dir,
            authoritative_host=authoritative_host,
            observation_id=observation_id,
            observed_at=program_observed_at,
            collector_sha256=program_collector_sha,
            raw_manifest_sha256=raw_manifest_sha,
            raw_artifact_count=raw_artifact_count,
        )
        if _captured_json(
            program_execution["captured_stdout"], field="program collector execution"
        ) != raw_run:
            raise Day1EvidenceError(
                "program raw run-result differs from authenticated collector output"
            )
        _verify_renderer_outputs(
            root=root,
            renderer_relpath=program_renderer,
            raw_dir=raw_snapshot,
            generated_at=program_generated_at,
            summary_bytes=snapshots["runtime/program-inventory-summary.md"],
            json_bytes=snapshots["runtime/program-inventory.v1.json"],
            source_inventory_path=source_inventory_path,
            renderer_source=reviewed_renderer_source,
        )
        if _source_file_digest(root, source_revision, program_renderer) != program_renderer_sha:
            raise Day1EvidenceError("renderer source changed during verification")
        # Preserve the authoritative raw-run reference only while it still
        # has the same manifest and exact run-result as the snapshot.
        live_run = json.loads(_snapshot_output_bytes(raw_dir / "run-result.json"))
        manifest_now, count_now = _raw_manifest_sha256(raw_dir)
        if (
            live_run != raw_run
            or manifest_now != raw_manifest_sha
            or count_now != raw_artifact_count
        ):
            raise Day1EvidenceError("program raw evidence changed during verification")
    _verify_current_output_snapshots(root, snapshots)

    # Captured stdout is used for verification only and remains local/private.
    for execution in (software_execution, program_execution, renderer_execution):
        execution.pop("captured_stdout")

    return {
        "host": authoritative_host,
        "source_revision": source_revision,
        "observation": {
            "kind": schema["observation"]["kind"],
            "id": observation_id,
            "started_at": started_at,
            "completed_at": completed_at,
        },
        "outputs": outputs,
        "provenance": {
            "software": {
                "collector_path": software_script,
                "collector_sha256": software_collector_sha,
                "execution_receipt_sha256": software_execution[
                    "lifecycle_receipt_sha256"
                ],
                "execution": software_execution,
                "argv": software_execution["argv"],
            },
            "program": {
                "collector_path": program_collector,
                "collector_sha256": program_collector_sha,
                "renderer_path": program_renderer,
                "renderer_sha256": program_renderer_sha,
                "execution_receipt_sha256": program_execution[
                    "lifecycle_receipt_sha256"
                ],
                "execution": program_execution,
                "argv": program_execution["argv"],
                "renderer_execution_receipt_sha256": renderer_execution[
                    "lifecycle_receipt_sha256"
                ],
                "renderer_execution": renderer_execution,
                "renderer_argv": renderer_execution["argv"],
                "raw_dir": str(raw_dir),
                "raw_manifest_sha256": raw_manifest_sha,
                "raw_artifact_count": raw_artifact_count,
            },
        },
    }


def write_evidence(
    *,
    root: Path,
    contract_path: Path,
    evidence_path: Path,
    binding: dict[str, Any],
    update_contract: bool,
) -> None:
    root = root.resolve()
    contract_path = contract_path.resolve()
    evidence_path = evidence_path.resolve()
    try:
        evidence_path.relative_to(root)
    except ValueError as exc:
        raise Day1EvidenceError("evidence path must be inside repository root") from exc

    try:
        contract_relpath = contract_path.relative_to(root).as_posix()
    except ValueError as exc:
        raise Day1EvidenceError("contract path must be inside repository root") from exc

    source_revision = str(binding.get("source_revision", ""))
    _require_hex(source_revision, HEX40, field="binding source_revision")
    try:
        reviewed_contract = json.loads(
            _git_blob(root, source_revision, contract_relpath).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Day1EvidenceError(
            "reviewed Day-1 contract is not valid UTF-8 JSON"
        ) from exc

    # Reject output drift between authentication and binding publication.
    bound_rows = binding.get("outputs")
    required_paths = reviewed_contract["inventory"]["canonical_outputs"]
    if (
        not isinstance(bound_rows, list)
        or len(bound_rows) != len(required_paths)
        or any(not isinstance(row, dict) for row in bound_rows)
        or [row.get("path") for row in bound_rows] != required_paths
    ):
        raise Day1EvidenceError("binding output paths differ from reviewed contract")
    for row in bound_rows:
        relpath = row["path"]
        if _sha256_bytes(_snapshot_output_bytes(root / relpath)) != row.get("sha256"):
            raise Day1EvidenceError(f"bound output changed before evidence publication: {relpath}")

    expected_bound_contract = copy.deepcopy(reviewed_contract)
    expected_bound_contract["inventory"]["current_binding"] = binding
    expected_bound_contract["admission"]["current_status"] = (
        "blocked-until-day1-classification-and-acceptance"
    )

    try:
        existing_contract = json.loads(contract_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise Day1EvidenceError("worktree Day-1 contract is not valid JSON") from exc
    if existing_contract not in (reviewed_contract, expected_bound_contract):
        raise Day1EvidenceError(
            "worktree Day-1 contract is neither the reviewed preimage nor the identical bound post-state"
        )

    payload = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_day1_workload_parity_current_evidence",
        "readiness_authorized": False,
        "classification_complete": False,
        "current_binding": binding,
    }

    if evidence_path.exists():
        try:
            existing_evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise Day1EvidenceError(
                "existing evidence file is not valid JSON and will not be overwritten"
            ) from exc
        if existing_evidence != payload:
            raise Day1EvidenceError(
                "refusing to replace different existing Day-1 evidence"
            )
    else:
        evidence_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if update_contract and existing_contract == reviewed_contract:
        contract_path.write_text(
            json.dumps(expected_bound_contract, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


def _json_object(value: str, *, field: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise Day1EvidenceError(f"{field} is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise Day1EvidenceError(f"{field} must be a JSON object")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--evidence-out", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--observation-id", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--completed-at", required=True)
    parser.add_argument("--software-execution-receipt-json", required=True)
    parser.add_argument("--program-execution-receipt-json", required=True)
    parser.add_argument("--program-renderer-execution-receipt-json", required=True)
    parser.add_argument("--update-contract", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = args.root.resolve()
    contract = args.contract
    if not contract.is_absolute():
        contract = root / contract
    evidence = args.evidence_out
    if not evidence.is_absolute():
        evidence = root / evidence
    binding = build_current_binding(
        root=root,
        contract_path=contract,
        source_revision=args.source_revision,
        observation_id=args.observation_id,
        started_at=args.started_at,
        completed_at=args.completed_at,
        software_execution_receipt=_json_object(
            args.software_execution_receipt_json,
            field="software execution receipt",
        ),
        program_execution_receipt=_json_object(
            args.program_execution_receipt_json,
            field="program execution receipt",
        ),
        program_renderer_execution_receipt=_json_object(
            args.program_renderer_execution_receipt_json,
            field="program renderer execution receipt",
        ),
    )
    write_evidence(
        root=root,
        contract_path=contract,
        evidence_path=evidence,
        binding=binding,
        update_contract=args.update_contract,
    )
    print(evidence)


if __name__ == "__main__":
    main()
