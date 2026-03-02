#!/usr/bin/env python3
"""
Utility functions for heim-pc scripts.
"""
import os
import sys
import json
import yaml
from typing import Any

def get_repo_root() -> str:
    """Returns the absolute path to the repository root."""
    # Assuming this script is always in scripts/
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(script_dir)

def resolve_path(path: str) -> str:
    """
    Resolves a path relative to the repository root. Accepts absolute paths within the repo root.
    Prevents path traversal.
    """
    repo_root = os.path.abspath(get_repo_root())

    # If already absolute, don't join with repo_root
    if os.path.isabs(path):
        resolved_path = os.path.abspath(path)
    else:
        resolved_path = os.path.abspath(os.path.join(repo_root, path))

    # Ensure the resolved path is within the repository root
    # Using commonpath is robust for detecting if resolved_path is inside repo_root
    try:
        # We need to ensure that commonpath doesn't just return repo_root for /app-extra
        # On some systems/versions, commonpath([/app, /app-extra]) is /app.
        # So we verify that the common path is exactly repo_root AND it is actually a parent.
        common = os.path.commonpath([repo_root, resolved_path])
        is_inside = (common == repo_root) and (
            resolved_path == repo_root or
            resolved_path.startswith(os.path.join(repo_root, ""))
        )
    except ValueError:
        # commonpath raises ValueError if paths are on different drives (Windows)
        raise ValueError(f"Path escapes repository root (different drive/base): {path}")

    if not is_inside:
        raise ValueError(f"Path escapes repository root: {path}")

    return resolved_path

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
