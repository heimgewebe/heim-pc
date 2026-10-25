"""Fail-closed NixOS adapter for the *existing* Grabowski Rootbroker peer proof.

The original upstream broker checks SO_PEERCRED, systemd MainPID, system.slice,
root-owned cgroup.procs and an exact process command line. This module only
adapts immutable unit-fragment and interpreter paths for NixOS. It never
authorizes an arbitrary same-UID process and does not perform privileged work.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
from collections.abc import Mapping

UNIT_NAME = "grabowski-operator.service"
EXPECTED_FRAGMENT = Path("/etc/systemd/system/grabowski-operator.service")
NIX_STORE = Path("/nix/store")
OPERATOR_ENTRYPOINT_ENV = "GRABOWSKI_NIXOS_OPERATOR_ENTRYPOINT"
STORE_UNIT_RE = re.compile(
    r"^[0-9a-z]{32}-unit-grabowski-operator[.]service$"
)
OPERATOR_PACKAGE_RE = re.compile(
    r"^[0-9a-z]{32}-grabowski-operator-a6d4a8b0$"
)


def _safe_dir(path: Path, trusted_uid: int, *, allow_link: bool = False) -> bool:
    """Every traversable component must be root-controlled and not mutable."""
    try:
        linked = path.lstat()
        resolved = path.stat()
    except (OSError, ValueError):
        return False
    if linked.st_uid != trusted_uid:
        return False
    if stat.S_ISLNK(linked.st_mode):
        if not allow_link:
            return False
    elif not stat.S_ISDIR(linked.st_mode) or linked.st_mode & 0o022:
        return False
    return (
        stat.S_ISDIR(resolved.st_mode)
        and resolved.st_uid == trusted_uid
        and not resolved.st_mode & 0o022
    )


def _safe_file(path: Path, trusted_uid: int, *, executable: bool = False) -> bool:
    try:
        meta = path.lstat()
    except (OSError, ValueError):
        return False
    return (
        stat.S_ISREG(meta.st_mode)
        and meta.st_uid == trusted_uid
        and not meta.st_mode & 0o022
        and (not executable or bool(meta.st_mode & 0o111))
    )


def _store_unit(path: Path, store_root: Path) -> bool:
    # Physical NixOS VM proof: systemd FragmentPath resolves to a *file inside*
    # /nix/store/<hash>-unit-grabowski-operator.service/. Do not accept another
    # systemd unit, a differently named store object or a user-controlled path.
    return (
        path.is_absolute()
        and path.parent.parent == store_root
        and path.name == UNIT_NAME
        and STORE_UNIT_RE.fullmatch(path.parent.name) is not None
    )


def _safe_nix_store_directory(store_root: Path, trusted_uid: int) -> bool:
    # NixOS gives /nix/store mode 01775: owned by root, group-writable with a
    # sticky bit. Sticky ownership prevents group members from replacing a
    # root-owned store object; each accepted unit/file remains root-owned,
    # non-symlink and non-writable below. Never accept world-write or
    # group-write without sticky, including in the VM.
    if not _safe_dir(store_root.parent, trusted_uid):
        return False
    try:
        metadata = store_root.lstat()
    except (OSError, ValueError):
        return False
    mode = metadata.st_mode
    return (
        stat.S_ISDIR(mode)
        and metadata.st_uid == trusted_uid
        and not mode & stat.S_IWOTH
        and (
            not mode & stat.S_IWGRP
            or bool(mode & stat.S_ISVTX)
        )
    )


def fragment_allowed(
    fragment: Path,
    *,
    etc_fragment: Path = EXPECTED_FRAGMENT,
    store_root: Path = NIX_STORE,
) -> bool:
    """Reject every other unit name and path before accessing the filesystem."""
    return (
        isinstance(fragment, Path)
        and (
            fragment == etc_fragment
            or _store_unit(fragment, store_root)
        )
    )


def fragment_trusted(
    fragment: Path,
    *,
    etc_fragment: Path = EXPECTED_FRAGMENT,
    store_root: Path = NIX_STORE,
    trusted_uid: int = 0,
) -> bool:
    """Accept only the root-controlled generated NixOS unit, never user links.

    /etc/systemd/system is typically a symlink through /etc/static into a Nix
    store-generated unit file. We validate that root owns the visible links,
    parent chain and final immutable unit. Pop!'s regular-fragment requirement
    remains unchanged in the upstream source and is not reused on NixOS.
    """
    if not fragment_allowed(fragment, etc_fragment=etc_fragment, store_root=store_root):
        return False
    if not _safe_nix_store_directory(store_root, trusted_uid):
        return False
    if fragment == etc_fragment:
        # A mutable, arbitrary /etc unit file cannot stand in for NixOS's
        # immutable generated fragment. The root-controlled symlink is required.
        try:
            link = fragment.lstat()
        except (OSError, ValueError):
            return False
        if not stat.S_ISLNK(link.st_mode) or link.st_uid != trusted_uid:
            return False
        # /etc/systemd/system may itself be a root-controlled symlink.
        if not all(
            _safe_dir(parent, trusted_uid, allow_link=True)
            for parent in (
                etc_fragment.parent.parent.parent,
                etc_fragment.parent.parent,
                etc_fragment.parent,
            )
        ):
            return False
    try:
        resolved = fragment.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return False
    if not _store_unit(resolved, store_root):
        return False
    if not _safe_dir(resolved.parent, trusted_uid):
        return False
    return _safe_file(resolved, trusted_uid)


def expected_operator_argv(
    *,
    environ: Mapping[str, str] | None = None,
    store_root: Path = NIX_STORE,
    trusted_uid: int = 0,
) -> tuple[str, ...]:
    """Rootbroker unit supplies the immutable operator entrypoint, not the peer.

    Systemd owns this environment for the root per-request service. The
    SO_PEERCRED/MainPID/cgroup process proof in the original broker is still
    mandatory and must compare /proc/<peer>/cmdline to this exact argv.
    """
    raw = (os.environ if environ is None else environ).get(OPERATOR_ENTRYPOINT_ENV)
    if not isinstance(raw, str) or "\x00" in raw:
        raise PermissionError("NixOS operator entrypoint is not configured")
    path = Path(raw)
    if (
        not path.is_absolute()
        or path.parent.name != "bin"
        or path.name != "grabowski-operator"
        or path.parent.parent.parent != store_root
        or OPERATOR_PACKAGE_RE.fullmatch(path.parent.parent.name) is None
        or not _safe_nix_store_directory(store_root, trusted_uid)
        or not all(_safe_dir(parent, trusted_uid) for parent in (path.parent.parent, path.parent))
        or not _safe_file(path, trusted_uid, executable=True)
    ):
        raise PermissionError("NixOS operator entrypoint is not immutable/root-controlled")
    return (
        raw,
        "-m",
        "grabowski_operator",
        "--transport",
        "streamable-http",
        "--host",
        "127.0.0.1",
        "--port",
        "18181",
    )