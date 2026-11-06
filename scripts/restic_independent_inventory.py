#!/usr/bin/env python3
"""Compare Restic's read-only snapshot view with a restored tree on ANOTHER host.

Requires neither root nor the original machine. Runs entirely offline. Exit 1
on any missing path, unreadable file, or differing tree (including symlinks).
The two manifest hashes are safe to include in a signed off-host attestation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

PATHS = (
    "/home/alex", "/persist", "/etc", "/var/lib/tailscale",
    "/var/lib/NetworkManager", "/var/lib/nixos", "/var/lib/grabowski",
)
CHUNK = 1024 * 1024


def inventory(root: Path, paths: tuple[str, ...] = PATHS) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("inventory root must be an existing real directory")
    manifest = hashlib.sha256()
    file_count = 0
    total_bytes = 0

    def add(*parts: bytes) -> None:
        for field in parts:
            manifest.update(field)
            manifest.update(b"\0")

    def visit(path: Path) -> None:
        nonlocal file_count, total_bytes
        name = os.fsencode(path.relative_to(root))
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            add(b"L", name, os.fsencode(os.readlink(path)))
        elif stat.S_ISDIR(info.st_mode):
            add(b"D", name)
            with os.scandir(path) as stream:
                children = sorted((Path(entry.path) for entry in stream),
                                  key=lambda x: os.fsencode(x.name))
            for child in children:
                visit(child)
        elif stat.S_ISREG(info.st_mode):
            digest = hashlib.sha256()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                opened = os.fstat(fd)
                if (opened.st_dev != info.st_dev or opened.st_ino != info.st_ino
                        or opened.st_size != info.st_size):
                    raise RuntimeError("file changed during inventory")
                size = 0
                while True:
                    chunk = os.read(fd, CHUNK)
                    if not chunk:
                        break
                    size += len(chunk)
                    digest.update(chunk)
                if size != info.st_size:
                    raise RuntimeError("file size changed during inventory")
            finally:
                os.close(fd)
            add(b"F", name, str(size).encode("ascii"), digest.digest())
            file_count += 1
            total_bytes += size
        elif stat.S_ISFIFO(info.st_mode):
            add(b"P", name)
        else:
            raise RuntimeError("unsupported file type in recovery inventory")

    for absolute in paths:
        if not absolute.startswith("/") or ".." in Path(absolute).parts:
            raise ValueError("inventory paths must be absolute and canonical")
        rel = Path(absolute.lstrip("/"))
        for parent in (root, *(root.joinpath(*rel.parts[:i]) for i in range(1, len(rel.parts) + 1))):
            if parent.is_symlink():
                raise RuntimeError("inventory anchor symlink is not allowed")
        target = root / rel
        if not target.is_dir():
            raise RuntimeError("required restore directory missing")
        visit(target)
    if not file_count or not total_bytes:
        raise RuntimeError("empty full restore inventory is not acceptable")
    return {
        "sha256": manifest.hexdigest(),
        "file_count": file_count,
        "total_bytes": total_bytes,
        "covered_paths": list(paths),
    }


def compare(snapshot_root: Path, restore_root: Path) -> dict:
    snapshot = snapshot_root.resolve(strict=True)
    restored_tree = restore_root.resolve(strict=True)
    if (snapshot == restored_tree or snapshot in restored_tree.parents
            or restored_tree in snapshot.parents):
        raise RuntimeError("restore comparison requires disjoint source and destination trees")
    source = inventory(snapshot_root)
    restored = inventory(restore_root)
    result = {
        "source_sha256": source["sha256"],
        "restored_sha256": restored["sha256"],
        "covered_paths": source["covered_paths"],
        "file_count": source["file_count"],
        "total_bytes": source["total_bytes"],
    }
    if source != restored:
        raise RuntimeError("source and restored file/symlink inventories differ")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot-root", type=Path, required=True,
                        help="Restic FUSE ids/FULL_SNAPSHOT_ID under independent repository copy")
    parser.add_argument("--restore-root", type=Path, required=True,
                        help="restic restore --target directory on independent hardware")
    args = parser.parse_args(argv)
    result = compare(args.snapshot_root, args.restore_root)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Independent restore inventory FAILED: {exc}", file=sys.stderr)
        sys.exit(1)