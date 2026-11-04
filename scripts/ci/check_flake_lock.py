#!/usr/bin/env python3
"""Check the generated system lock; update only from authoritative root lock.

Nix refuses symlink lockfiles. After reviewing a root `nix flake update`, run
`python3 scripts/ci/check_flake_lock.py --sync` and review both files together.
Never update inputs from nixos/system independently.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


def check(root: Path, *, sync: bool = False) -> None:
    authority = root / "flake.lock"
    projection = root / "nixos/system/flake.lock"
    if authority.is_symlink() or projection.is_symlink():
        raise ValueError("flake locks must be regular files, not symlinks")
    expected = authority.read_bytes()
    if sync:
        projection.write_bytes(expected)
    if projection.read_bytes() != expected:
        raise ValueError("flake lock authority drift: regenerate system projection from root with --sync")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sync", action="store_true", help="regenerate system projection from root")
    args = parser.parse_args()
    try:
        check(Path(__file__).resolve().parents[2], sync=args.sync)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
