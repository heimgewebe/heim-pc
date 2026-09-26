#!/usr/bin/env python3
"""Compatibility entrypoint for the canonical generic Heimgewebe ASR authority."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def canonical_entry() -> Path:
    return Path.home() / "repos" / "asr" / "scripts" / "asr_engine.py"


def main() -> int:
    target = canonical_entry()
    if not target.is_file():
        print(
            f"ERROR: canonical generic ASR entry is missing: {target}",
            file=sys.stderr,
        )
        return 127
    os.execv(sys.executable, [sys.executable, str(target), *sys.argv[1:]])
    raise AssertionError("os.execv unexpectedly returned")


if __name__ == "__main__":
    raise SystemExit(main())
