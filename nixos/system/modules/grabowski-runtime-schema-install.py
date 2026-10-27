"""Atomically install the NixOS-pinned contract validator as a root-owned trust anchor.

The bytes originate from the independently approved, immutable operator
derivation selected by the root-owned NixOS release configuration. Never copy
them from the live operator process, a mutable Git worktree or an environment
variable; those inputs cannot establish recovery trust.
"""
from __future__ import annotations

import grp
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

DESTINATION = Path("/etc/grabowski/runtime-contract-schema.py")
STORE_ROOT = Path("/nix/store")
MAX_BYTES = 512 * 1024
_PACKAGE = re.compile(r"[a-z0-9]{32}-grabowski-operator-[a-zA-Z0-9._-]+")


def _trusted_nix_store_group_write(
    current: Path, info: os.stat_result, nix_store_root: Path | None
) -> bool:
    """Admit only NixOS's root:nixbld 01775 sticky store entry directory.

    Sticky-bit semantics prevent unprivileged build users from replacing the
    root-owned pinned package directory. All package ancestors below the store
    and the /etc destination must still be strictly non-writable.
    """
    if (
        nix_store_root is None
        or current != nix_store_root
        or stat.S_IMODE(info.st_mode) != 0o1775
    ):
        return False
    try:
        return info.st_gid == grp.getgrnam("nixbld").gr_gid
    except KeyError:
        return False


def _check_directories(
    path: Path, *, uid: int, boundary: Path, nix_store_root: Path | None = None
) -> None:
    """Reject mutable ancestors except the single NixOS sticky store root."""
    if boundary != path and boundary not in path.parents:
        raise PermissionError("validator path escapes the trusted ownership boundary")
    current = path.parent
    while True:
        info = current.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != uid
            or info.st_mode & 0o002
            or (
                info.st_mode & 0o020
                and not _trusted_nix_store_group_write(current, info, nix_store_root)
            )
        ):
            raise PermissionError(f"validator directory is not root-controlled: {current}")
        if current == boundary:
            return
        if current == current.parent:
            raise PermissionError("trusted boundary is not an ancestor")
        current = current.parent


def _read_pinned_source(
    source: Path, *, uid: int, store_root: Path, boundary: Path
) -> bytes:
    if not source.is_absolute():
        raise PermissionError("validator source must be an absolute Nix store path")
    try:
        relative = source.relative_to(store_root)
    except ValueError as exc:
        raise PermissionError("validator source is outside the Nix store") from exc
    parts = relative.parts
    if not (
        len(parts) == 5
        and _PACKAGE.fullmatch(parts[0])
        and parts[1:] == (
            "lib", "python3.12", "site-packages", "grabowski_runtime_contract.py"
        )
    ):
        raise PermissionError("validator source is not the pinned operator module")
    _check_directories(
        source, uid=uid, boundary=boundary, nix_store_root=store_root
    )
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(source, flags)
    try:
        before = os.fstat(fd)
        # Nix store optimisation may hardlink a root-owned immutable source
        # through /nix/store/.links. Only the installed /etc anchor requires
        # exactly one link; a vanished source inode remains forbidden.
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != uid
            or before.st_nlink < 1
            or before.st_mode & 0o022
            or not 0 < before.st_size <= MAX_BYTES
        ):
            raise PermissionError("validator source must be a root-owned nonwritable regular file")
        chunks: list[bytes] = []
        size = 0
        while size <= MAX_BYTES:
            chunk = os.read(fd, min(65536, MAX_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        after = os.fstat(fd)
        if (
            size != before.st_size
            or (before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns)
        ):
            raise PermissionError("validator source changed while being read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def install(
    source: Path,
    destination: Path = DESTINATION,
    *,
    authority_uid: int = 0,
    store_root: Path = STORE_ROOT,
    trusted_boundary: Path = Path("/"),
) -> str:
    """A safe replacement is atomic; an unsafe existing inode is never followed."""
    data = _read_pinned_source(
        source, uid=authority_uid, store_root=store_root, boundary=trusted_boundary
    )
    if destination.name != DESTINATION.name:
        raise PermissionError("unexpected runtime schema destination")
    _check_directories(destination, uid=authority_uid, boundary=trusted_boundary)
    parent = destination.parent
    parent_info = parent.lstat()
    if stat.S_IMODE(parent_info.st_mode) != 0o755:
        raise PermissionError("runtime schema destination directory must be mode 0755")
    try:
        old = destination.lstat()
    except FileNotFoundError:
        old = None
    if old is not None and (
        not stat.S_ISREG(old.st_mode)
        or old.st_uid != authority_uid
        or old.st_nlink != 1
        or old.st_mode & 0o022
    ):
        raise PermissionError("existing runtime schema anchor is unsafe to replace")
    fd, temporary = tempfile.mkstemp(prefix=".runtime-contract-schema-", dir=parent)
    try:
        os.fchmod(fd, 0o644)  # The non-root operator must be able to read it.
        offset = 0
        while offset < len(data):
            count = os.write(fd, data[offset:])
            if count <= 0:
                raise OSError("short runtime schema write")
            offset += count
        os.fsync(fd)
        os.close(fd)
        fd = -1
        _check_directories(destination, uid=authority_uid, boundary=trusted_boundary)
        if stat.S_IMODE(parent.lstat().st_mode) != 0o755:
            raise PermissionError("runtime schema destination changed")
        if old is not None:
            try:
                now = destination.lstat()
            except FileNotFoundError as exc:
                raise PermissionError("runtime schema destination changed during install") from exc
            if (
                not stat.S_ISREG(now.st_mode)
                or now.st_uid != authority_uid
                or now.st_nlink != 1
                or now.st_mode & 0o022
                or (
                    old.st_dev, old.st_ino, old.st_mode, old.st_uid,
                    old.st_gid, old.st_nlink, old.st_size,
                    old.st_mtime_ns, old.st_ctime_ns,
                ) != (
                    now.st_dev, now.st_ino, now.st_mode, now.st_uid,
                    now.st_gid, now.st_nlink, now.st_size,
                    now.st_mtime_ns, now.st_ctime_ns,
                )
            ):
                raise PermissionError("runtime schema destination changed during install")
        else:
            try:
                destination.lstat()
            except FileNotFoundError:
                pass
            else:
                raise PermissionError("runtime schema destination appeared concurrently")
        os.replace(temporary, destination)
        directory_fd = os.open(
            parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.lexists(temporary):
            os.unlink(temporary)
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    if os.geteuid() != 0:
        raise PermissionError("runtime schema installer must run as root")
    if len(sys.argv) != 2:
        raise ValueError("expected exactly one root-pinned immutable operator schema")
    digest = install(Path(sys.argv[1]))
    print(f"root-pinned runtime contract schema installed; sha256={digest}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, PermissionError, ValueError) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)