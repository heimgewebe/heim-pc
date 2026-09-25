#!/usr/bin/env python3
"""Decide whether the heavy Nix CI job is required for one exact Git event."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Iterable

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
NIX_EXACT_PATHS = frozenset(
    {
        ".github/workflows/heim-pc-nix.yml",
        "flake.nix",
        "flake.lock",
        "scripts/ci/check_pinned_nix_find_contract.py",
        "scripts/ci/nix_changed.py",
        "scripts/managed_build.py",
        "scripts/storage_inventory.py",
    }
)
NIXOS_SCRIPT_RE = re.compile(r"^scripts/nixos_[^/]*\.py$")


def path_requires_nix(path: str) -> bool:
    return (
        path in NIX_EXACT_PATHS
        or path.startswith("nixos/")
        or NIXOS_SCRIPT_RE.fullmatch(path) is not None
    )


def changed_paths_require_nix(paths: Iterable[str]) -> bool:
    return any(path_requires_nix(path) for path in paths)


def _commit_exists(revision: str) -> bool:
    if SHA40_RE.fullmatch(revision) is None:
        return False
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{revision}^{{commit}}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def _changed_paths(event_name: str, base: str, head: str) -> list[str] | None:
    if event_name not in {"push", "pull_request"}:
        return None
    if not _commit_exists(head):
        return None
    if base == "0" * 40 or not _commit_exists(base):
        return None

    revision_range = f"{base}...{head}" if event_name == "pull_request" else f"{base}..{head}"
    result = subprocess.run(
        ["git", "diff", "--name-only", "-z", "--no-renames", revision_range, "--"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        return None
    return [
        item.decode("utf-8", errors="surrogateescape")
        for item in result.stdout.split(b"\0")
        if item
    ]


def detect(event_name: str, base: str, head: str) -> tuple[bool, str]:
    paths = _changed_paths(event_name, base.lower(), head.lower())
    if paths is None:
        return True, "git comparison unavailable; fail-open to heavy Nix CI"
    if changed_paths_require_nix(paths):
        return True, f"Nix-relevant change found among {len(paths)} changed paths"
    return False, f"no Nix-relevant change among {len(paths)} changed paths"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    required, reason = detect(args.event_name, args.base, args.head)
    print(reason, file=sys.stderr)
    print(f"nix_changed={'true' if required else 'false'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
