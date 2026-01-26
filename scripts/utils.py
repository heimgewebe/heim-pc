#!/usr/bin/env python3
"""
Utility functions for webmaschine scripts.
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
    """Resolves a path relative to the repository root."""
    return os.path.join(get_repo_root(), relative_path)

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
