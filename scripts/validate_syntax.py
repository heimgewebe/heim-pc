#!/usr/bin/env python3
"""
Validates YAML and JSON syntax for the heim-pc repository.
"""
# Standard library imports
import glob
import json
import os
import sys
import traceback
from typing import List, Set

# Third-party imports
try:
    import yaml
except ModuleNotFoundError as e:
    if e.name == "yaml":
        print("::error::PyYAML is missing. Please install it via 'pip install -r requirements.txt'.", file=sys.stderr)
        sys.exit(1)
    raise

# Local imports
import utils

def collect_files(patterns: List[str], repo_root: str) -> List[str]:
    """Collects files matching patterns, deduplicates, and sorts them."""
    files: Set[str] = set()
    for p in patterns:
        # Construct absolute path pattern
        abs_pattern = os.path.join(repo_root, p)
        files.update(glob.iglob(abs_pattern, recursive=True))

    # Deduplicate and sort for deterministic output and stable CI logs
    return sorted(files)

def validate_yaml(patterns: List[str], repo_root: str) -> bool:
    """
    Validates YAML files matching the given patterns.

    Returns:
        bool: True if an error occurred, False otherwise.
    """
    files = collect_files(patterns, repo_root)

    has_error = False
    for f in files:
        if not os.path.isfile(f):
            continue
        try:
            utils.load_yaml(f)
        except yaml.YAMLError as e:
            utils.log_error(f"Error parsing YAML {f}: {e}")
            has_error = True
        except Exception as e:
            msg = f"Unexpected error processing {f}: {e}"
            if os.environ.get('DEBUG'):
                msg += f"\n{traceback.format_exc()}"
            utils.log_error(msg)
            has_error = True

    return has_error

def validate_json(patterns: List[str], repo_root: str) -> bool:
    """
    Validates JSON files matching the given patterns.

    Returns:
        bool: True if an error occurred, False otherwise.
    """
    files = collect_files(patterns, repo_root)

    has_error = False
    for f in files:
        if not os.path.isfile(f):
            continue
        try:
            utils.load_json(f)
        except json.JSONDecodeError as e:
            utils.log_error(f"Error parsing JSON {f}: {e}")
            has_error = True
        except Exception as e:
            msg = f"Unexpected error processing {f}: {e}"
            if os.environ.get('DEBUG'):
                msg += f"\n{traceback.format_exc()}"
            utils.log_error(msg)
            has_error = True

    return has_error

def main() -> None:
    repo_root = utils.get_repo_root()
    utils.log_info(f"Running syntax validation for repo: {repo_root}")

    yaml_patterns = ['.github/workflows/*.yml', '.wgx/profile.yml', 'config/*.yml', 'config/**/*.yml']
    # state/*.json are validated by validate_contracts.py; removing here avoids redundant parsing
    json_patterns = ['snapshots/*.summary.json']

    utils.log_info("Validating YAML files...")
    yaml_has_error = validate_yaml(yaml_patterns, repo_root)

    utils.log_info("Validating JSON files...")
    json_has_error = validate_json(json_patterns, repo_root)

    if yaml_has_error or json_has_error:
        sys.exit(1)

    utils.log_info("Syntax validation passed.")

if __name__ == "__main__":
    main()
