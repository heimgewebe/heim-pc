"""Root-only, out-of-Store policy installer for the original Grabowski broker.

No policy content, credentials or authority grant is embedded in Nix
derivations. The input and output are both root-owned regular 0600 files.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

SOURCE = Path("/persist/secrets/grabowski/privileged-actions.json")
DESTINATION = Path("/etc/grabowski/privileged-actions.json")
MAX_BYTES = 512 * 1024


def _require_directory(path: Path, uid: int, *, exact_mode: int | None = None) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_mode & 0o022
        or (exact_mode is not None and stat.S_IMODE(metadata.st_mode) != exact_mode)
    ):
        raise PermissionError(f"private policy directory is not root-controlled: {path}")


def _require_ancestors(path: Path, uid: int, trusted_boundary: Path = Path("/")) -> None:
    ancestors = [path.parent, *path.parent.parents]
    if trusted_boundary not in ancestors:
        raise PermissionError("private policy path escapes trusted ownership boundary")
    for ancestor in reversed(ancestors[:ancestors.index(trusted_boundary) + 1]):
        _require_directory(ancestor, uid)


def _read_source(source: Path, uid: int, expected_root: Path, trusted_boundary: Path) -> bytes:
    if source != expected_root / "privileged-actions.json":
        raise PermissionError("private policy source must be the dedicated persistent path")
    _require_ancestors(source, uid, trusted_boundary)
    # Strictly private final policy directory (not merely non-writable).
    _require_directory(expected_root, uid, exact_mode=0o700)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(source, flags)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != uid
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or not (0 < before.st_size <= MAX_BYTES)
        ):
            raise PermissionError("broker policy source must be a unique root-owned regular 0600 file")
        data = bytearray()
        while len(data) <= MAX_BYTES:
            chunk = os.read(fd, min(65536, MAX_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        if (
            len(data) != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        ):
            raise PermissionError("broker policy source changed during read")
    finally:
        os.close(fd)
    return bytes(data)


def _validate_policy(data: bytes) -> None:
    document = json.loads(data.decode("utf-8", errors="strict"))
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "actions"}
        or document["schema_version"] != 2
        or not isinstance(document["actions"], dict)
    ):
        raise ValueError("unsupported broker policy schema or unexpected top-level fields")
    # The production authority may be broad, but it must come only from the
    # independently root-controlled source and the original broker validator.
    for name, record in document["actions"].items():
        if not isinstance(name, str) or not name or not isinstance(record, dict):
            raise ValueError("malformed privileged action record")


def install(
    source: Path = SOURCE,
    destination: Path = DESTINATION,
    *,
    authority_uid: int = 0,
    source_root: Path = SOURCE.parent,
    trusted_boundary: Path = Path("/"),
) -> str:
    """Atomic copy, with all path and inode checks before root-side effects."""
    data = _read_source(source, authority_uid, source_root, trusted_boundary)
    _validate_policy(data)
    if destination.name != "privileged-actions.json":
        raise PermissionError("invalid privileged broker policy destination")
    _require_ancestors(destination, authority_uid, trusted_boundary)
    _require_directory(destination.parent, authority_uid, exact_mode=0o755)
    try:
        existing = destination.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and (
        not stat.S_ISREG(existing.st_mode)
        or existing.st_uid != authority_uid
        or stat.S_IMODE(existing.st_mode) != 0o600
        or existing.st_nlink != 1
    ):
        raise PermissionError("existing privileged broker policy is not safe to replace")

    # /etc/grabowski is root-writable but searchable (0755) because the
    # canonical unprivileged broker_status tool must lstat the root-owned
    # policy without reading it. The policy and temporary file remain 0600,
    # with no public Nix Store copy or shared temporary path.
    fd, temp_path = tempfile.mkstemp(prefix=".privileged-actions-", dir=destination.parent)
    try:
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("short privileged policy write")
            offset += written
        os.fsync(fd)
        os.close(fd)
        fd = -1
        # Recheck both endpoints while temp remains in a root-only directory.
        _require_ancestors(source, authority_uid, trusted_boundary)
        _require_directory(destination.parent, authority_uid, exact_mode=0o755)
        os.replace(temp_path, destination)
        directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.lexists(temp_path):
            os.unlink(temp_path)
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    if os.geteuid() != 0:
        raise PermissionError("private policy installer requires root")
    install()
    print("root-controlled Grabowski policy installed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, PermissionError, ValueError, json.JSONDecodeError) as exc:
        print(type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        raise SystemExit(1)