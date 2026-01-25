#!/usr/bin/env python3
"""
Validates YAML and JSON syntax for the webmaschine repository.
"""
import sys
# Standard library imports
import glob
import json
import yaml
import os
from typing import List

import utils

def validate_yaml(patterns: List[str], repo_root: str) -> bool:
    """Validates YAML files matching the given patterns."""
    files: List[str] = []
    for p in patterns:
        # Construct absolute path pattern
        abs_pattern = os.path.join(repo_root, p)
        files.extend(glob.glob(abs_pattern, recursive=True))

    # Deduplicate and sort for deterministic output and stable CI logs
    files = sorted(set(files))

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
            utils.log_error(f"Unexpected error processing {f}: {e}")
            has_error = True

    return has_error

def validate_json(patterns: List[str], repo_root: str) -> bool:
    """Validates JSON files matching the given patterns."""
    files: List[str] = []
    for p in patterns:
        abs_pattern = os.path.join(repo_root, p)
        files.extend(glob.glob(abs_pattern, recursive=True))

    # Deduplicate and sort for deterministic output and stable CI logs
    files = sorted(set(files))

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
            utils.log_error(f"Unexpected error processing {f}: {e}")
            has_error = True

    return has_error

def main() -> None:
    repo_root = utils.get_repo_root()
    utils.log_info(f"Running syntax validation for repo: {repo_root}")

    yaml_patterns = ['.github/workflows/*.yml', '.wgx/profile.yml', 'config/*.yml', 'config/**/*.yml']
    json_patterns = ['state/*.json', 'snapshots/*.summary.json']

    utils.log_info("Validating YAML files...")
    yaml_has_error = validate_yaml(yaml_patterns, repo_root)

    utils.log_info("Validating JSON files...")
    json_has_error = validate_json(json_patterns, repo_root)

    if yaml_has_error or json_has_error:
        sys.exit(1)

    utils.log_info("Syntax validation passed.")

if __name__ == "__main__":
    main()
