#!/usr/bin/env python3
"""
Validates YAML and JSON syntax for the webmaschine repository.
"""
import sys
import glob
import json
import yaml
import os

def validate_yaml(patterns):
    """Validates YAML files matching the given patterns."""
    files = []
    for p in patterns:
        files.extend(glob.glob(p, recursive=True))

    error = False
    for f in files:
        try:
            with open(f, 'r') as stream:
                yaml.safe_load(stream)
        except yaml.YAMLError as e:
            print(f"Error parsing YAML {f}: {e}")
            error = True
        except Exception as e:
            print(f"Unexpected error processing {f}: {e}")
            error = True

    return error

def validate_json(patterns):
    """Validates JSON files matching the given patterns."""
    files = []
    for p in patterns:
        files.extend(glob.glob(p, recursive=True))

    error = False
    for f in files:
        try:
            with open(f, 'r') as stream:
                json.load(stream)
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON {f}: {e}")
            error = True
        except Exception as e:
            print(f"Unexpected error processing {f}: {e}")
            error = True

    return error

def main():
    # Ensure we run from the repository root
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    os.chdir(repo_root)
    print(f"Running syntax validation from: {os.getcwd()}")

    yaml_patterns = ['.github/workflows/*.yml', '.wgx/profile.yml', 'config/*.yml', 'config/**/*.yml']
    json_patterns = ['state/*.json', 'snapshots/*.summary.json']

    print("Validating YAML files...")
    yaml_error = validate_yaml(yaml_patterns)

    print("Validating JSON files...")
    json_error = validate_json(json_patterns)

    if yaml_error or json_error:
        sys.exit(1)

    print("Syntax validation passed.")

if __name__ == "__main__":
    main()
