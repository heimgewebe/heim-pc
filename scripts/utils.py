#!/usr/bin/env python3
"""
Utility functions for heim-pc scripts.
"""
import os
import sys
import json
from pathlib import Path
import yaml
from typing import Any, Optional, Union

def get_repo_root() -> str:
    """Returns the absolute path to the repository root."""
    # Assuming this script is always in scripts/
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(script_dir)

def resolve_path(path: str, repo_root: Optional[Union[str, Path]] = None) -> str:
    """
    Resolves a path relative to the repository root. Accepts absolute paths within the repo root.
    Prevents path traversal.
    """
    root = Path(repo_root) if repo_root is not None else Path(get_repo_root())
    root = root.resolve()

    candidate = Path(path)

    # If path is relative, interpret it relative to root
    if not candidate.is_absolute():
        candidate = root / candidate

    # resolve() handles '..' and symlinks
    try:
        resolved = candidate.resolve()
    except (OSError, RuntimeError):
        # Fallback for paths that cannot be resolved (e.g. permission issues or infinite loops)
        # We still want to check containment if possible
        resolved = candidate

    # Ensure resolved is within root
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Path escapes repository root: {path}") from exc

    return str(resolved)

def load_json(path: str) -> Any:
    """Loads a JSON file with error handling."""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def load_yaml(path: str) -> Any:
    """Loads a YAML file with error handling."""
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def log_error(msg: str) -> None:
    """Logs an error message in GitHub Actions format."""
    print(f"::error::{msg}", file=sys.stderr)

def log_warning(msg: str) -> None:
    """Logs a warning message in GitHub Actions format."""
    print(f"::warning::{msg}")

def log_info(msg: str) -> None:
    """Logs an info message."""
    print(msg)
