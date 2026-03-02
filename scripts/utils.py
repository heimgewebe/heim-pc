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

def resolve_path(relative_path: str) -> str:
    """Resolves a path relative to the repository root and prevents path traversal."""
    repo_root = os.path.abspath(get_repo_root())
    # Use abspath to resolve any '..' and join with repo_root
    resolved_path = os.path.abspath(os.path.join(repo_root, relative_path))

    # Ensure the resolved path is within the repository root
    try:
        is_common = os.path.commonpath([repo_root, resolved_path]) == repo_root
    except ValueError:
        # commonpath raises ValueError if paths are on different drives (Windows)
        raise ValueError(f"Path escapes repository root (different drive/base): {relative_path}")

    if not is_common:
        raise ValueError(f"Path escapes repository root: {relative_path}")

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
