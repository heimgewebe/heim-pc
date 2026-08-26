#!/usr/bin/env python3
"""Canonical local-first document text extraction CLI for the heim-pc."""

from __future__ import annotations

import argparse
import codecs
import hashlib
import json
import os
import re
import resource
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = REPO_ROOT / "manifest" / "document-text-engine-policy.v1.json"
CONFIG_PATH = REPO_ROOT / "config" / "heim-pc.yml"
CONTRACT_PATH = REPO_ROOT / "manifest" / "document-text-contract.v1.json"
DOCLING_READINESS_PATH = (
    Path.home() / ".local" / "state" / "heim-pc" / "document-text-engine" / "docling-readiness.v1.json"
)

SOURCE_ROOT = Path.home().resolve()
ALWAYS_EXCLUDED_COMPONENTS = frozenset(
    {
        ".cache",
        ".ssh",
        ".gnupg",
        ".password-store",
        ".thunderbird",
        "keyrings",
        "node_modules",
        ".venv",
        "venv",
        "dist",
        "build",
        "target",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
    }
)
ALWAYS_EXCLUDED_PATH_SEQUENCES = (
    (".local", "share", "trash"),
    (".mozilla", "firefox"),
    (".config", "google-chrome"),
    (".config", "chromium"),
    (".config", "bravesoftware"),
    (".local", "share", "keyrings"),
    (".config", "kwallet"),
    (".config", "kwalletd5"),
)
SENSITIVE_SUFFIXES = frozenset({".key", ".pem", ".p12"})
INTERNAL_TMPFS_EXEC_OPERATION = "__bounded-tmpfs-exec"


class DocumentTextError(RuntimeError):
    """A bounded document-text operation could not be completed safely."""

    def __init__(self, code: str, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def load_policy() -> dict[str, Any]:
    policy = _load_json(POLICY_PATH)
    if policy.get("schema_version") != 1 or policy.get("kind") != "heim_pc_document_text_engine_policy":
        raise ValueError("document text policy identity mismatch")
    invariants = policy.get("invariants")
    if not isinstance(invariants, dict):
        raise ValueError("document text policy invariants must be an object")
    required_true = (
        "default_path_zero_incremental_cost",
        "default_path_local_only",
    )
    for key in required_true:
        if invariants.get(key) is not True:
            raise ValueError(f"document text policy invariant {key} must remain true")
    required_false = (
        "network_access_allowed",
        "metered_or_cloud_use_allowed",
        "automatic_docling_use_allowed",
        "source_content_persisted_by_engine",
        "extracted_text_persisted_by_engine",
    )
    for key in required_false:
        if invariants.get(key) is not False:
            raise ValueError(f"document text policy invariant {key} must remain false")
    limits = policy.get("limits")
    if not isinstance(limits, dict):
        raise ValueError("document text policy limits must be an object")
    for key in (
        "max_source_bytes",
        "max_output_bytes",
        "max_pages",
        "process_timeout_seconds",
        "max_stderr_bytes",
    ):
        value = limits.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"document text policy limit {key} must be a positive integer")
    languages = policy.get("languages")
    if not isinstance(languages, dict) or languages.get("default") not in languages.get("allowed", []):
        raise ValueError("document text policy languages are invalid")
    routing = policy.get("routing")
    if not isinstance(routing, dict):
        raise ValueError("document text policy routing must be an object")
    probe_minimum = routing.get("text_layer_probe_min_non_whitespace_chars")
    if (
        not isinstance(probe_minimum, int)
        or isinstance(probe_minimum, bool)
        or probe_minimum <= 0
    ):
        raise ValueError("document text text-layer probe minimum must be a positive integer")
    supported_inputs = policy.get("supported_inputs")
    if (
        not isinstance(supported_inputs, list)
        or set(supported_inputs) != {"pdf", "png", "jpeg", "tiff"}
        or any(not isinstance(item, str) for item in supported_inputs)
    ):
        raise ValueError("document text supported_inputs must match the implemented v1 input kinds")
    return policy


def load_contract() -> dict[str, Any]:
    contract = _load_json(CONTRACT_PATH)
    if contract.get("schema_version") != 1 or contract.get("kind") != "heim-pc.document-text":
        raise ValueError("document text result contract identity mismatch")
    return contract


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _tool_name(policy: dict[str, Any], role: str) -> str:
    tools = policy.get("tools")
    if not isinstance(tools, dict) or not isinstance(tools.get(role), str):
        raise ValueError(f"document text policy tool {role} is missing")
    return str(tools[role])


def _stderr_evidence(value: bytes, maximum: int) -> dict[str, Any]:
    bounded = value[:maximum]
    return {
        "bytes": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
        "bounded_bytes": len(bounded),
        "truncated": len(value) > maximum,
    }


def _process_stderr_evidence(
    completed: subprocess.CompletedProcess[bytes], maximum: int
) -> dict[str, Any]:
    evidence = getattr(completed, "_bounded_stderr_evidence", None)
    if isinstance(evidence, dict):
        return dict(evidence)
    value = completed.stderr if isinstance(completed.stderr, bytes) else b""
    return _stderr_evidence(value, maximum)


def _tmpfs_sandbox_tools() -> dict[str, str | None]:
    return {name: shutil.which(name) for name in ("unshare", "mount")}


def _validate_sandbox_export(
    temporary_directory: Path,
    relative_path: str,
    destination: Path,
) -> tuple[Path, Path]:
    relative = Path(relative_path)
    if (
        not relative_path
        or relative.is_absolute()
        or relative == Path(".")
        or ".." in relative.parts
        or not destination.is_absolute()
    ):
        raise ValueError("sandbox export path is invalid")
    resolved_temporary = temporary_directory.resolve()
    resolved_destination = destination.resolve()
    try:
        resolved_destination.relative_to(resolved_temporary)
    except ValueError:
        pass
    else:
        raise ValueError("sandbox export destination must be outside the mounted quota")
    return relative, resolved_destination


def _tmpfs_sandbox_command(
    argv: Sequence[str],
    temporary_directory: Path,
    maximum: int,
    *,
    export_relative_path: str | None = None,
    export_path: Path | None = None,
) -> list[str]:
    if (export_relative_path is None) != (export_path is None):
        raise ValueError("sandbox export requires both relative source and destination")
    tools = _tmpfs_sandbox_tools()
    unshare = tools["unshare"]
    mount = tools["mount"]
    missing = [name for name, executable in tools.items() if executable is None]
    if missing:
        raise DocumentTextError(
            "route_unavailable",
            "bounded temporary-storage sandbox is unavailable",
            details={"missing_tools": missing},
        )
    assert unshare is not None and mount is not None
    internal = [str(temporary_directory), str(maximum), mount]
    if export_relative_path is not None and export_path is not None:
        relative, destination = _validate_sandbox_export(
            temporary_directory, export_relative_path, export_path
        )
        internal.extend(["--export", str(relative), str(destination)])
    internal.append("--")
    internal.extend(argv)
    return [
        unshare,
        "--user",
        "--map-root-user",
        "--mount",
        "--fork",
        "--propagation",
        "private",
        sys.executable,
        str(Path(__file__).resolve()),
        INTERNAL_TMPFS_EXEC_OPERATION,
        *internal,
    ]


def _export_file_releasing_source(source: Path, destination: Path, maximum: int) -> None:
    source_flags = os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
    destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        destination_flags |= os.O_NOFOLLOW
    source_fd = os.open(source, source_flags)
    destination_fd = -1
    try:
        source_stat = os.fstat(source_fd)
        if (
            not stat.S_ISREG(source_stat.st_mode)
            or source_stat.st_size <= 0
            or source_stat.st_size > maximum
        ):
            raise OSError("sandbox export source violates its file bound")
        destination_fd = os.open(destination, destination_flags, 0o600)
        remaining = source_stat.st_size
        while remaining:
            chunk_size = min(1024 * 1024, remaining)
            offset = remaining - chunk_size
            chunk = os.pread(source_fd, chunk_size, offset)
            if len(chunk) != chunk_size:
                raise OSError("sandbox export source changed during copy")
            os.ftruncate(source_fd, offset)
            written = 0
            while written < len(chunk):
                count = os.pwrite(destination_fd, chunk[written:], offset + written)
                if count <= 0:
                    raise OSError("sandbox export write made no progress")
                written += count
            remaining = offset
        os.fsync(destination_fd)
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        os.close(source_fd)


def _exec_bounded_tmpfs(argv: Sequence[str]) -> int:
    if len(argv) < 5:
        return 125
    temporary_directory = Path(argv[0])
    try:
        maximum = int(argv[1])
    except ValueError:
        return 125
    mount = argv[2]
    export_relative_path: str | None = None
    export_destination: Path | None = None
    if argv[3] == "--":
        command = list(argv[4:])
    elif len(argv) >= 8 and argv[3] == "--export" and argv[6] == "--":
        export_relative_path = argv[4]
        export_destination = Path(argv[5])
        command = list(argv[7:])
    else:
        return 125
    if maximum <= 0 or not command or not temporary_directory.is_absolute():
        return 125
    try:
        if not temporary_directory.is_dir():
            return 125
        export_relative: Path | None = None
        if export_relative_path is not None and export_destination is not None:
            export_relative, export_destination = _validate_sandbox_export(
                temporary_directory,
                export_relative_path,
                export_destination,
            )
        mounted = subprocess.run(
            [
                mount,
                "-t",
                "tmpfs",
                "-o",
                f"size={maximum},mode=700,nosuid,nodev",
                "tmpfs",
                str(temporary_directory),
            ],
            stdin=subprocess.DEVNULL,
            check=False,
        )
        if mounted.returncode != 0:
            return 126
        environment = {**os.environ, "TMPDIR": str(temporary_directory)}
        if export_relative is None or export_destination is None:
            os.execvpe(command[0], command, environment)
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            env=environment,
            check=False,
        )
        if completed.returncode != 0:
            return completed.returncode
        _export_file_releasing_source(
            temporary_directory / export_relative,
            export_destination,
            maximum,
        )
        return 0
    except (OSError, ValueError):
        return 127
    return 127


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def _run(
    argv: Sequence[str],
    *,
    policy: dict[str, Any],
    operation: str,
    file_size_limit_bytes: int | None = None,
    temporary_directory: Path | None = None,
    temporary_storage_limit_bytes: int | None = None,
    sandbox_export_relative_path: str | None = None,
    sandbox_export_path: Path | None = None,
) -> subprocess.CompletedProcess[bytes]:
    timeout = int(policy["limits"]["process_timeout_seconds"])
    stdout_limit = int(policy["limits"]["max_output_bytes"])
    stderr_limit = int(policy["limits"]["max_stderr_bytes"])
    if timeout <= 0 or stdout_limit <= 0 or stderr_limit <= 0:
        raise ValueError("process limits must be positive")
    if temporary_storage_limit_bytes is not None and temporary_storage_limit_bytes <= 0:
        raise ValueError("process temporary-storage limit must be positive")
    if temporary_storage_limit_bytes is not None and temporary_directory is None:
        raise ValueError("process temporary-storage limit requires a temporary directory")
    if (sandbox_export_relative_path is None) != (sandbox_export_path is None):
        raise ValueError("sandbox export requires both relative source and destination")
    if sandbox_export_relative_path is not None and temporary_storage_limit_bytes is None:
        raise ValueError("sandbox export requires a temporary-storage limit")

    preexec_fn: Any = None
    if file_size_limit_bytes is not None:
        if file_size_limit_bytes <= 0:
            raise ValueError("process file-size limit must be positive")
        file_size_limit = file_size_limit_bytes

        def _apply_file_size_limit() -> None:
            resource.setrlimit(
                resource.RLIMIT_FSIZE,
                (file_size_limit, file_size_limit),
            )

        preexec_fn = _apply_file_size_limit

    environment = {**os.environ, "LC_ALL": "C.UTF-8"}
    resolved_temporary_directory: Path | None = None
    if temporary_directory is not None:
        resolved_temporary_directory = temporary_directory.resolve()
        if not resolved_temporary_directory.is_dir():
            raise ValueError("process temporary directory must exist")
        environment["TMPDIR"] = str(resolved_temporary_directory)

    process_argv = list(argv)
    if temporary_storage_limit_bytes is not None:
        assert resolved_temporary_directory is not None
        process_argv = _tmpfs_sandbox_command(
            process_argv,
            resolved_temporary_directory,
            temporary_storage_limit_bytes,
            export_relative_path=sandbox_export_relative_path,
            export_path=sandbox_export_path,
        )

    try:
        process = subprocess.Popen(
            process_argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            preexec_fn=preexec_fn,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        details: dict[str, Any] = {"error_type": type(exc).__name__}
        if isinstance(exc, OSError):
            details["errno"] = exc.errno
        raise DocumentTextError(
            "route_unavailable",
            f"{operation} could not start the required local process",
            details=details,
        ) from exc

    stdout_state: dict[str, Any] = {
        "data": bytearray(),
        "total": 0,
        "digest": hashlib.sha256(),
        "limit": stdout_limit,
    }
    stderr_state: dict[str, Any] = {
        "data": bytearray(),
        "total": 0,
        "digest": hashlib.sha256(),
        "limit": stderr_limit,
    }
    selector = selectors.DefaultSelector()
    assert process.stdout is not None and process.stderr is not None
    streams = ((process.stdout, "stdout", stdout_state), (process.stderr, "stderr", stderr_state))
    for stream, name, state in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, (name, state))

    deadline = time.monotonic() + timeout
    termination_reason: str | None = None
    try:
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            if termination_reason is None and now >= deadline:
                termination_reason = "timeout"
                _kill_process_group(process)
            select_timeout = 0.05
            if termination_reason is None:
                select_timeout = min(select_timeout, max(0.0, deadline - now))
            for key, _mask in selector.select(select_timeout):
                name, state = key.data
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                state["total"] += len(chunk)
                state["digest"].update(chunk)
                remaining = max(0, int(state["limit"]) - len(state["data"]))
                if remaining:
                    state["data"].extend(chunk[:remaining])

        try:
            returncode = process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            _kill_process_group(process)
            process.kill()
            process.wait(timeout=5)
            raise DocumentTextError(
                "extraction_failed",
                f"{operation} did not terminate after bounded process shutdown",
                details={"timeout_seconds": timeout},
            ) from exc
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()

    if termination_reason == "timeout":
        raise DocumentTextError(
            "extraction_failed",
            f"{operation} exceeded the bounded process timeout",
            details={"timeout_seconds": timeout},
        )

    stdout = bytes(stdout_state["data"])
    stderr = bytes(stderr_state["data"])
    completed = subprocess.CompletedProcess(list(argv), returncode, stdout=stdout, stderr=stderr)
    setattr(
        completed,
        "_bounded_stderr_evidence",
        {
            "bytes": int(stderr_state["total"]),
            "sha256": stderr_state["digest"].hexdigest(),
            "bounded_bytes": len(stderr),
            "truncated": int(stderr_state["total"]) > len(stderr),
        },
    )
    return completed


def _tmpfs_sandbox_readiness(policy: dict[str, Any]) -> dict[str, Any]:
    tools = _tmpfs_sandbox_tools()
    missing = [name for name, executable in tools.items() if executable is None]
    base = {
        "tools": tools,
        "enforcement": "private_tmpfs_quota",
        "probe": "user_mount_namespace",
    }
    if missing:
        return {
            **base,
            "status": "unavailable",
            "reason": "helper_missing",
            "missing_tools": missing,
        }
    probe_policy = dict(policy)
    probe_limits = dict(policy["limits"])
    probe_limits["process_timeout_seconds"] = min(
        5, int(policy["limits"]["process_timeout_seconds"])
    )
    probe_policy["limits"] = probe_limits
    with tempfile.TemporaryDirectory(prefix="heim-doc-text-sandbox-probe-") as directory:
        probe_code = (
            "from pathlib import Path; import os; "
            "Path(os.environ['TMPDIR'], 'probe').write_bytes(b'x')"
        )
        try:
            command = _tmpfs_sandbox_command(
                [sys.executable, "-c", probe_code],
                Path(directory),
                1024 * 1024,
            )
            completed = _run(
                command,
                policy=probe_policy,
                operation="tmpfs-sandbox-readiness",
            )
        except DocumentTextError as exc:
            return {
                **base,
                "status": "unavailable",
                "reason": "runtime_probe_failed",
                "error_code": exc.code,
            }
    if completed.returncode != 0:
        return {
            **base,
            "status": "unavailable",
            "reason": "runtime_probe_failed",
            "returncode": completed.returncode,
        }
    return {**base, "status": "ready", "reason": None}


def _require_tool(policy: dict[str, Any], role: str) -> str:
    name = _tool_name(policy, role)
    executable = shutil.which(name)
    if executable is None:
        raise DocumentTextError(
            "route_unavailable",
            f"required local tool is unavailable: {name}",
            details={"role": role, "tool": name},
        )
    return executable


def _source_kind(path: Path) -> str:
    suffix = path.suffix.casefold()
    if suffix == ".pdf":
        return "pdf"
    if suffix == ".png":
        return "png"
    if suffix in {".jpg", ".jpeg"}:
        return "jpeg"
    if suffix in {".tif", ".tiff"}:
        return "tiff"
    raise DocumentTextError(
        "unsupported_input",
        "document type is not supported by the local v1 contract",
        details={"suffix": suffix or None},
    )


def _source_candidate(raw_path: str) -> Path:
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return Path(os.path.abspath(candidate))


def _path_contains_sequence(parts: tuple[str, ...], sequence: tuple[str, ...]) -> bool:
    if len(sequence) > len(parts):
        return False
    return any(
        parts[index : index + len(sequence)] == sequence
        for index in range(len(parts) - len(sequence) + 1)
    )


def _configured_exclude_patterns() -> tuple[str, ...]:
    try:
        config = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise DocumentTextError(
            "source_not_authorized",
            "configured source exclusions could not be verified",
            details={"error_type": type(exc).__name__},
        ) from exc
    if not isinstance(config, dict):
        raise DocumentTextError(
            "source_not_authorized",
            "configured source exclusions are invalid",
        )
    excludes = config.get("excludes", [])
    if excludes is None:
        return ()
    if not isinstance(excludes, list):
        raise DocumentTextError(
            "source_not_authorized",
            "configured source exclusions are invalid",
        )
    patterns: list[str] = []
    for entry in excludes:
        if not isinstance(entry, dict):
            raise DocumentTextError(
                "source_not_authorized",
                "configured source exclusions are invalid",
            )
        pattern = entry.get("pattern")
        if not isinstance(pattern, str) or not pattern.strip():
            raise DocumentTextError(
                "source_not_authorized",
                "configured source exclusions are invalid",
            )
        patterns.append(pattern.strip())
    return tuple(patterns)


def _path_matches_configured_exclude(path: Path, pattern: str) -> bool:
    current = path
    while True:
        try:
            if current.match(pattern):
                return True
        except ValueError as exc:
            raise DocumentTextError(
                "source_not_authorized",
                "configured source exclusions are invalid",
                details={"error_type": type(exc).__name__},
            ) from exc
        if current == SOURCE_ROOT:
            return False
        current = current.parent


def _enforce_source_path_policy(path: Path) -> None:
    try:
        relative = path.relative_to(SOURCE_ROOT)
    except ValueError as exc:
        raise DocumentTextError(
            "source_not_authorized",
            "source is outside the approved user-home root",
        ) from exc
    parts = tuple(part.casefold() for part in relative.parts)
    if any(part in ALWAYS_EXCLUDED_COMPONENTS for part in parts):
        raise DocumentTextError(
            "source_not_authorized",
            "source is inside a protected filesystem area",
        )
    if any(_path_contains_sequence(parts, sequence) for sequence in ALWAYS_EXCLUDED_PATH_SEQUENCES):
        raise DocumentTextError(
            "source_not_authorized",
            "source is inside a protected filesystem area",
        )
    if any(
        _path_matches_configured_exclude(path, pattern)
        for pattern in _configured_exclude_patterns()
    ):
        raise DocumentTextError(
            "source_not_authorized",
            "source is excluded by the configured filesystem policy",
        )
    if path.suffix.casefold() in SENSITIVE_SUFFIXES:
        raise DocumentTextError(
            "source_not_authorized",
            "source type is excluded by the sensitive-file policy",
        )


def _opened_source_path(descriptor: int) -> Path:
    try:
        resolved = Path(f"/proc/self/fd/{descriptor}").resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise DocumentTextError(
            "source_not_authorized",
            "opened source root cannot be verified",
            details={"error_type": type(exc).__name__},
        ) from exc
    _enforce_source_path_policy(resolved)
    return resolved


def _open_source(raw_path: str, policy: dict[str, Any]) -> tuple[int, str, os.stat_result, str]:
    candidate = _source_candidate(raw_path)
    _enforce_source_path_policy(candidate)
    input_type = _source_kind(candidate)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(candidate, flags)
    except FileNotFoundError as exc:
        raise DocumentTextError("input_invalid", "source file does not exist") from exc
    except OSError as exc:
        raise DocumentTextError(
            "input_invalid",
            "source file cannot be opened safely",
            details={"error_type": type(exc).__name__, "errno": exc.errno},
        ) from exc
    try:
        _opened_source_path(descriptor)
        source_stat = os.fstat(descriptor)
        if not stat.S_ISREG(source_stat.st_mode):
            raise DocumentTextError("input_invalid", "source must be a regular file")
        maximum = int(policy["limits"]["max_source_bytes"])
        if source_stat.st_size <= 0:
            raise DocumentTextError("input_invalid", "source file is empty")
        if source_stat.st_size > maximum:
            raise DocumentTextError(
                "input_too_large",
                "source file exceeds the bounded v1 size limit",
                details={"source_bytes": source_stat.st_size, "max_source_bytes": maximum},
            )
        return descriptor, input_type, source_stat, candidate.suffix.casefold()
    except BaseException:
        os.close(descriptor)
        raise


def _snapshot_source(
    raw_path: str,
    policy: dict[str, Any],
    directory: Path,
) -> tuple[Path, str, os.stat_result, str]:
    descriptor, input_type, before, suffix = _open_source(raw_path, policy)
    snapshot = directory / f"source{suffix}"
    digest = hashlib.sha256()
    destination = -1
    copied = 0
    maximum = int(policy["limits"]["max_source_bytes"])
    try:
        destination = os.open(
            snapshot,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            copied += len(chunk)
            if copied > maximum:
                raise DocumentTextError(
                    "input_too_large",
                    "source file exceeded the bounded v1 size limit while snapshotting",
                    details={"max_source_bytes": maximum},
                )
            view = memoryview(chunk)
            while view:
                written = os.write(destination, view)
                if written <= 0:
                    raise DocumentTextError(
                        "input_invalid",
                        "private source snapshot write made no progress",
                    )
                view = view[written:]
        os.fsync(destination)
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
            or copied != before.st_size
        ):
            raise DocumentTextError(
                "input_invalid",
                "source content changed while the private snapshot was captured",
            )
    except DocumentTextError:
        raise
    except OSError as exc:
        raise DocumentTextError(
            "input_invalid",
            "private source snapshot could not be created safely",
            details={"error_type": type(exc).__name__, "errno": exc.errno},
        ) from exc
    finally:
        if destination >= 0:
            os.close(destination)
        os.close(descriptor)
    return snapshot, input_type, before, digest.hexdigest()


def _read_output(path: Path, maximum: int) -> tuple[str, int, bool]:
    size = path.stat().st_size
    with path.open("rb") as handle:
        payload = handle.read(maximum + 1)
    truncated = len(payload) > maximum or size > maximum
    emitted = payload[:maximum]
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    text = decoder.decode(emitted, final=False)
    encoded = text.encode("utf-8")
    if len(encoded) > maximum:
        text = encoded[:maximum].decode("utf-8", errors="ignore")
    return text, size, truncated


def _pdf_page_count(path: Path, policy: dict[str, Any]) -> int | None:
    executable = shutil.which(_tool_name(policy, "pdf_info"))
    if executable is None:
        return None
    completed = _run([executable, str(path)], policy=policy, operation="pdfinfo")
    if completed.returncode != 0:
        return None
    text = completed.stdout.decode("utf-8", errors="replace")
    match = re.search(r"^Pages:\s+(\d+)\s*$", text, flags=re.MULTILINE)
    if match is None:
        return None
    return int(match.group(1))


def _tiff_page_count(path: Path, policy: dict[str, Any]) -> int | None:
    maximum_pages = int(policy["limits"]["max_pages"])
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            header = handle.read(8)
            if len(header) != 8:
                return None
            if header[:2] == b"II":
                byte_order = "<"
            elif header[:2] == b"MM":
                byte_order = ">"
            else:
                return None
            if struct.unpack(f"{byte_order}H", header[2:4])[0] != 42:
                return None
            offset = struct.unpack(f"{byte_order}I", header[4:8])[0]
            if offset == 0:
                return None
            seen_offsets: set[int] = set()
            pages = 0
            while offset != 0:
                if offset in seen_offsets or offset < 8 or offset + 2 > size:
                    return None
                seen_offsets.add(offset)
                handle.seek(offset)
                entry_count_raw = handle.read(2)
                if len(entry_count_raw) != 2:
                    return None
                entry_count = struct.unpack(f"{byte_order}H", entry_count_raw)[0]
                next_offset_position = offset + 2 + entry_count * 12
                if next_offset_position + 4 > size:
                    return None
                handle.seek(next_offset_position)
                next_offset_raw = handle.read(4)
                if len(next_offset_raw) != 4:
                    return None
                offset = struct.unpack(f"{byte_order}I", next_offset_raw)[0]
                pages += 1
                if pages > maximum_pages:
                    return pages
            return pages if pages > 0 else None
    except (OSError, OverflowError, struct.error):
        return None


def _probe_pdf_text_layer(path: Path, policy: dict[str, Any]) -> bool | None:
    executable = shutil.which(_tool_name(policy, "pdf_text"))
    if executable is None:
        return None
    max_pages = int(policy["limits"]["max_pages"])
    maximum = int(policy["limits"]["max_output_bytes"])
    with tempfile.TemporaryDirectory(prefix="heim-doc-text-probe-") as directory:
        output = Path(directory) / "probe.txt"
        completed = _run(
            [
                executable,
                "-f",
                "1",
                "-l",
                str(max_pages),
                "-layout",
                str(path),
                str(output),
            ],
            policy=policy,
            operation="pdftotext-probe",
            file_size_limit_bytes=maximum,
        )
        cap_reached = (
            completed.returncode != 0
            and output.exists()
            and output.stat().st_size >= maximum
        )
        if (completed.returncode != 0 and not cap_reached) or not output.exists():
            return None
        minimum = int(policy["routing"]["text_layer_probe_min_non_whitespace_chars"])
        current_non_whitespace = 0
        saw_page_boundary = False
        with output.open("r", encoding="utf-8", errors="replace") as handle:
            for chunk in iter(lambda: handle.read(65536), ""):
                for character in chunk:
                    if character == "\f":
                        saw_page_boundary = True
                        if current_non_whitespace < minimum:
                            return False
                        current_non_whitespace = 0
                    elif not character.isspace():
                        current_non_whitespace += 1
        if cap_reached:
            return None
        if current_non_whitespace:
            return current_non_whitespace >= minimum
        return True if saw_page_boundary else False


def _tesseract_languages(policy: dict[str, Any]) -> dict[str, Any]:
    name = _tool_name(policy, "image_ocr")
    executable = shutil.which(name)
    if executable is None:
        return {"status": "unavailable", "tool": name, "installed": []}
    try:
        completed = _run(
            [executable, "--list-langs"],
            policy=policy,
            operation="tesseract-language-readiness",
        )
    except DocumentTextError as exc:
        return {
            "status": "unavailable",
            "tool": name,
            "installed": [],
            "reason": "readiness_probe_failed",
            "error_code": exc.code,
        }
    if completed.returncode != 0:
        return {
            "status": "unavailable",
            "tool": name,
            "installed": [],
            "reason": "readiness_probe_failed",
        }
    lines = completed.stdout.decode("utf-8", errors="replace").splitlines()
    installed = sorted({line.strip() for line in lines[1:] if line.strip()})
    required = policy["languages"].get("required_installed", [])
    missing = sorted(set(required).difference(installed))
    return {
        "status": "ready" if not missing else "degraded",
        "tool": name,
        "installed": installed,
        "required": required,
        "missing": missing,
    }


def _docling_readiness(policy: dict[str, Any]) -> dict[str, Any]:
    name = _tool_name(policy, "structured_optional")
    executable = shutil.which(name)
    if executable is None:
        return {
            "status": "unavailable",
            "tool": name,
            "reason": "executable_missing",
            "automatic_use": False,
        }
    try:
        receipt = _load_json(DOCLING_READINESS_PATH)
    except (OSError, ValueError, json.JSONDecodeError):
        return {
            "status": "unattested",
            "tool": name,
            "reason": "explicit_offline_readiness_receipt_missing",
            "automatic_use": False,
        }
    valid = (
        receipt.get("schema_version") == 1
        and receipt.get("kind") == "heim_pc.document_text.docling_readiness"
        and receipt.get("status") == "ready"
        and receipt.get("network_required") is False
    )
    return {
        "status": "ready" if valid else "unattested",
        "tool": name,
        "reason": None if valid else "readiness_receipt_invalid",
        "automatic_use": False,
    }


def doctor(policy: dict[str, Any]) -> dict[str, Any]:
    tool_roles = ("pdf_text", "pdf_info", "pdf_ocr", "image_ocr")
    tools: dict[str, dict[str, Any]] = {}
    for role in tool_roles:
        name = _tool_name(policy, role)
        executable = shutil.which(name)
        tools[role] = {
            "tool": name,
            "available": executable is not None,
            "executable": executable,
        }
    languages = _tesseract_languages(policy)
    sandbox = _tmpfs_sandbox_readiness(policy)
    sandbox_ready = sandbox["status"] == "ready"
    routes = {
        "pdf_text_layer": (
            tools["pdf_text"]["available"] and tools["pdf_info"]["available"]
        ),
        "pdf_ocr": (
            tools["pdf_text"]["available"]
            and tools["pdf_info"]["available"]
            and tools["pdf_ocr"]["available"]
            and tools["image_ocr"]["available"]
            and languages["status"] == "ready"
            and sandbox_ready
        ),
        "image_ocr": tools["image_ocr"]["available"] and languages["status"] == "ready",
    }
    return {
        "schema_version": 1,
        "kind": "heim-pc.document-text-doctor",
        "operation": "doctor",
        "status": "ready" if all(routes.values()) else "degraded",
        "routes": routes,
        "tools": tools,
        "languages": languages,
        "temporary_storage_sandbox": sandbox,
        "docling": _docling_readiness(policy),
        "network_access_authorized": False,
        "cloud_or_metered_use_authorized": False,
        "does_not_establish": [
            "source_file_access",
            "future_tool_availability",
            "extraction_correctness",
            "docling_model_readiness_without_valid_receipt",
        ],
    }


def _inspect_snapshot(
    source: Path,
    input_type: str,
    source_stat: os.stat_result,
    source_sha256: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    pages: int | None = None
    text_layer: bool | None = None
    if input_type == "pdf":
        pages = _pdf_page_count(source, policy)
        maximum_pages = int(policy["limits"]["max_pages"])
        if pages is not None and pages > maximum_pages:
            raise DocumentTextError(
                "input_too_large",
                "PDF exceeds the bounded v1 page limit",
                details={"pages": pages, "max_pages": maximum_pages},
            )
        text_layer = _probe_pdf_text_layer(source, policy) if pages is not None else None
        method = "pdftotext" if text_layer is True else "ocrmypdf_then_pdftotext"
    elif input_type == "tiff":
        pages = _tiff_page_count(source, policy)
        maximum_pages = int(policy["limits"]["max_pages"])
        if pages is not None and pages > maximum_pages:
            raise DocumentTextError(
                "input_too_large",
                "TIFF exceeds the bounded v1 page limit",
                details={"pages": pages, "max_pages": maximum_pages},
            )
        method = "tesseract"
    else:
        method = "tesseract"
    readiness = doctor(policy)
    if input_type in {"pdf", "tiff"} and pages is None:
        route_ready = False
    elif method == "pdftotext":
        route_ready = bool(readiness["routes"]["pdf_text_layer"])
    elif method == "ocrmypdf_then_pdftotext":
        route_ready = bool(readiness["routes"]["pdf_ocr"])
    else:
        route_ready = bool(readiness["routes"]["image_ocr"])
    return {
        "schema_version": 1,
        "kind": "heim-pc.document-text-inspection",
        "operation": "inspect",
        "status": "ready" if route_ready else "route_unavailable",
        "source_sha256": source_sha256,
        "source_bytes": source_stat.st_size,
        "input_type": input_type,
        "pages": pages,
        "page_bound_established": input_type not in {"pdf", "tiff"} or pages is not None,
        "text_layer_detected": text_layer,
        "recommended_method": method,
        "route_ready": route_ready,
        "docling": readiness["docling"],
        "does_not_establish": [
            "extraction_correctness",
            "layout_fidelity",
            "document_authenticity",
        ],
    }


def inspect_source(raw_path: str, policy: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="heim-doc-text-source-") as directory:
        source, input_type, source_stat, source_sha256 = _snapshot_source(
            raw_path, policy, Path(directory)
        )
        return _inspect_snapshot(source, input_type, source_stat, source_sha256, policy)


def _extract_pdftotext(source: Path, policy: dict[str, Any]) -> tuple[str, int, bool]:
    executable = _require_tool(policy, "pdf_text")
    with tempfile.TemporaryDirectory(prefix="heim-doc-text-pdf-") as directory:
        output = Path(directory) / "text.txt"
        maximum = int(policy["limits"]["max_output_bytes"])
        file_size_limit = maximum
        completed = _run(
            [
                executable,
                "-f",
                "1",
                "-l",
                str(int(policy["limits"]["max_pages"])),
                "-layout",
                str(source),
                str(output),
            ],
            policy=policy,
            operation="pdftotext",
            file_size_limit_bytes=file_size_limit,
        )
        cap_reached = (
            completed.returncode != 0
            and output.exists()
            and output.stat().st_size >= file_size_limit
        )
        if (completed.returncode != 0 and not cap_reached) or not output.exists():
            raise DocumentTextError(
                "extraction_failed",
                "pdftotext failed",
                details={
                    "returncode": completed.returncode,
                    "stderr_evidence": _process_stderr_evidence(
                        completed, int(policy["limits"]["max_stderr_bytes"])
                    ),
                },
            )
        text, output_bytes, truncated = _read_output(output, maximum)
        return text, output_bytes, truncated or cap_reached


def _extract_ocr_pdf(source: Path, policy: dict[str, Any], language: str) -> tuple[str, int, bool]:
    ocrmypdf = _require_tool(policy, "pdf_ocr")
    _require_tool(policy, "image_ocr")
    _require_tool(policy, "pdf_text")
    with tempfile.TemporaryDirectory(prefix="heim-doc-text-ocrpdf-") as directory:
        root = Path(directory)
        budget = root / "budget"
        budget.mkdir(mode=0o700)
        sandbox_rendered = budget / "ocr.pdf"
        rendered = root / "ocr.pdf"
        intermediate_limit = int(policy["limits"]["max_source_bytes"])
        completed = _run(
            [
                ocrmypdf,
                "--skip-text",
                "--rotate-pages",
                "--deskew",
                "--jobs",
                "1",
                "--optimize",
                "0",
                "--output-type",
                "pdf",
                "-l",
                language,
                str(source),
                str(sandbox_rendered),
            ],
            policy=policy,
            operation="ocrmypdf",
            file_size_limit_bytes=intermediate_limit,
            temporary_directory=budget,
            temporary_storage_limit_bytes=intermediate_limit,
            sandbox_export_relative_path="ocr.pdf",
            sandbox_export_path=rendered,
        )
        if completed.returncode != 0 or not rendered.exists():
            raise DocumentTextError(
                "extraction_failed",
                "OCRmyPDF failed",
                details={
                    "returncode": completed.returncode,
                    "stderr_evidence": _process_stderr_evidence(
                        completed, int(policy["limits"]["max_stderr_bytes"])
                    ),
                },
            )
        return _extract_pdftotext(rendered, policy)


def _extract_tesseract(source: Path, policy: dict[str, Any], language: str) -> tuple[str, int, bool]:
    executable = _require_tool(policy, "image_ocr")
    with tempfile.TemporaryDirectory(prefix="heim-doc-text-image-") as directory:
        output_base = Path(directory) / "ocr"
        output = output_base.with_suffix(".txt")
        maximum = int(policy["limits"]["max_output_bytes"])
        file_size_limit = maximum
        completed = _run(
            [executable, str(source), str(output_base), "-l", language, "txt"],
            policy=policy,
            operation="tesseract",
            file_size_limit_bytes=file_size_limit,
        )
        cap_reached = (
            completed.returncode != 0
            and output.exists()
            and output.stat().st_size >= file_size_limit
        )
        if (completed.returncode != 0 and not cap_reached) or not output.exists():
            raise DocumentTextError(
                "extraction_failed",
                "Tesseract failed",
                details={
                    "returncode": completed.returncode,
                    "stderr_evidence": _process_stderr_evidence(
                        completed, int(policy["limits"]["max_stderr_bytes"])
                    ),
                },
            )
        text, output_bytes, truncated = _read_output(output, maximum)
        return text, output_bytes, truncated or cap_reached


def _validate_language(language: str, policy: dict[str, Any]) -> str:
    allowed = policy["languages"].get("allowed", [])
    if language not in allowed:
        raise DocumentTextError(
            "input_invalid",
            "requested OCR language is not allowlisted by the local policy",
            details={"language": language, "allowed": allowed},
        )
    return language


def validate_extract_result(result: dict[str, Any]) -> None:
    contract = load_contract()
    required = contract.get("required_fields", [])
    if not isinstance(required, list):
        raise ValueError("document text contract required_fields must be an array")
    missing = [field for field in required if field not in result]
    if missing:
        raise DocumentTextError(
            "extraction_failed",
            "document text result violates its result contract",
            details={"missing_fields": missing},
        )
    if result.get("schema_version") != 1 or result.get("kind") != contract.get("kind"):
        raise DocumentTextError("extraction_failed", "document text result identity mismatch")


def extract_source(raw_path: str, policy: dict[str, Any], *, language: str) -> dict[str, Any]:
    language = _validate_language(language, policy)
    with tempfile.TemporaryDirectory(prefix="heim-doc-text-source-") as directory:
        source, input_type, source_stat, source_sha256 = _snapshot_source(
            raw_path, policy, Path(directory)
        )
        inspection = _inspect_snapshot(
            source, input_type, source_stat, source_sha256, policy
        )
        if inspection["status"] != "ready":
            raise DocumentTextError(
                "route_unavailable",
                "recommended local extraction route is not currently ready",
                details={"method": inspection["recommended_method"]},
            )
        method = str(inspection["recommended_method"])
        if method == "pdftotext":
            text, text_bytes, truncated = _extract_pdftotext(source, policy)
            result_language: str | None = None
        elif method == "ocrmypdf_then_pdftotext":
            text, text_bytes, truncated = _extract_ocr_pdf(source, policy, language)
            result_language = language
        elif method == "tesseract":
            text, text_bytes, truncated = _extract_tesseract(source, policy, language)
            result_language = language
        else:
            raise DocumentTextError(
                "route_unavailable",
                "inspection selected an unsupported extraction route",
            )
        result = {
            "schema_version": 1,
            "kind": "heim-pc.document-text",
            "source_sha256": source_sha256,
            "input_type": input_type,
            "method": method,
            "language": result_language,
            "pages": inspection["pages"],
            "text": text,
            "text_bytes": text_bytes,
            "truncated": truncated,
            "warnings": ["output_truncated_to_policy_limit"] if truncated else [],
        }
        validate_extract_result(result)
        return result


def _error_payload(operation: str, error: DocumentTextError) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "heim-pc.document-text-error",
        "operation": operation,
        "status": "blocked",
        "error": {
            "code": error.code,
            "message": str(error),
            "details": error.details,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    subparsers.add_parser("doctor", help="Report local route readiness without downloading anything")
    inspect_parser = subparsers.add_parser("inspect", help="Inspect one local document and select a route")
    inspect_parser.add_argument("source")
    extract_parser = subparsers.add_parser("extract", help="Extract text through the selected local route")
    extract_parser.add_argument("source")
    extract_parser.add_argument("--language", default=None)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    if raw_argv and raw_argv[0] == INTERNAL_TMPFS_EXEC_OPERATION:
        return _exec_bounded_tmpfs(raw_argv[1:])

    args = build_parser().parse_args(raw_argv)
    try:
        policy = load_policy()
        if args.operation == "doctor":
            payload = doctor(policy)
        elif args.operation == "inspect":
            payload = inspect_source(args.source, policy)
        else:
            language = args.language or str(policy["languages"]["default"])
            payload = extract_source(args.source, policy, language=language)
    except DocumentTextError as exc:
        print(json.dumps(_error_payload(args.operation, exc), ensure_ascii=False, sort_keys=True))
        return 2
    except OSError as exc:
        payload = _error_payload(
            args.operation,
            DocumentTextError(
                "local_io_error",
                "local filesystem or process operation failed",
                details={"error_type": type(exc).__name__, "errno": exc.errno},
            ),
        )
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 3
    except (ValueError, json.JSONDecodeError) as exc:
        payload = _error_payload(
            args.operation,
            DocumentTextError(
                "contract_invalid",
                "document text contract or local runtime state is invalid",
                details={"error_type": type(exc).__name__},
            ),
        )
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 3
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
