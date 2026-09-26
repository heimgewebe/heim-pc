#!/usr/bin/env python3
"""Compatibility entrypoint for the canonical generic Heimgewebe ASR authority."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_OPERATOR_ENTRY = REPO_ROOT / "manifest" / "operator-entry.v1.json"


def canonical_entry() -> Path:
    return Path.home() / "repos" / "asr" / "scripts" / "asr_engine.py"


def installed_operator_entry() -> Path:
    return Path.home() / ".config" / "heimgewebe" / "operator-entry.v1.json"


def projection_drift_warning() -> str | None:
    installed = installed_operator_entry()
    try:
        canonical_bytes = CANONICAL_OPERATOR_ENTRY.read_bytes()
    except OSError:
        return (
            "WARNING: cannot verify the canonical heim-pc operator-entry projection; "
            "refresh the canonical checkout before relying on host capability resolution."
        )
    recovery = (
        "Review `python3 ~/repos/heim-pc/scripts/install_operator_entry.py --home ~/` "
        "then apply with `--apply --replace-existing`, and verify with "
        "`python3 ~/repos/heim-pc/scripts/check_operator_entry.py --home ~/ --require-installed` "
        "before relying on host capability resolution."
    )
    try:
        installed_metadata = installed.lstat()
    except FileNotFoundError:
        return (
            f"WARNING: installed heim-pc operator-entry projection is missing at {installed}. "
            + recovery
        )
    except OSError:
        return (
            f"WARNING: installed heim-pc operator-entry projection is unreadable at {installed}. "
            + recovery
        )
    if stat.S_ISLNK(installed_metadata.st_mode):
        return (
            f"WARNING: installed heim-pc operator-entry projection is a symlink at {installed}. "
            + recovery
        )
    if not stat.S_ISREG(installed_metadata.st_mode):
        return (
            f"WARNING: installed heim-pc operator-entry projection is not a regular file at {installed}. "
            + recovery
        )
    try:
        installed_bytes = installed.read_bytes()
    except OSError:
        return (
            f"WARNING: installed heim-pc operator-entry projection is unreadable at {installed}. "
            + recovery
        )
    if installed_bytes == canonical_bytes:
        return None
    installed_sha256 = hashlib.sha256(installed_bytes).hexdigest()
    canonical_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
    return (
        "WARNING: installed heim-pc operator-entry projection is stale "
        f"(sha256 {installed_sha256} != canonical {canonical_sha256}). "
        + recovery
    )


def main() -> int:
    target = canonical_entry()
    if not target.is_file():
        print(
            f"ERROR: canonical generic ASR entry is missing: {target}",
            file=sys.stderr,
        )
        return 127
    warning = projection_drift_warning()
    if warning is not None:
        print(warning, file=sys.stderr)
    os.execv(sys.executable, [sys.executable, str(target), *sys.argv[1:]])
    raise AssertionError("os.execv unexpectedly returned")


if __name__ == "__main__":
    raise SystemExit(main())
