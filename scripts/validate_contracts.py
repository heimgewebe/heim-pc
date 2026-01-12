#!/usr/bin/env python3
"""
Validates configuration and state files against canonical schemas from the metarepo.
"""
import sys
import os
import json
import yaml
from jsonschema import validate, ValidationError

def validate_zones(config_path, schema_path):
    """Validates the zones configuration."""
    print(f'Validating {config_path} against canonical JSON schema {schema_path}...')

    if not os.path.exists(config_path):
        print(f"::error::Config file {config_path} not found.")
        return False

    if not os.path.exists(schema_path):
        print(f"::error::Schema {schema_path} not found.")
        return False

    try:
        with open(config_path, 'r') as df:
            data = yaml.safe_load(df)
        with open(schema_path, 'r') as sf:
            schema = json.load(sf)

        validate(instance=data, schema=schema)
        print(f'OK: {config_path}')
        return True
    except ValidationError as e:
        print(f'::error::Validation Error in {config_path}: {e.message}')
        return False
    except Exception as e:
        print(f'::error::Error processing {config_path}: {e}')
        return False

def validate_state_file(data_file, schema_file, base_dir, schema_base_dir):
    """Validates a single state file against its schema."""
    data_file_path = os.path.join(base_dir, data_file)
    schema_file_path = os.path.join(schema_base_dir, schema_file)

    if not os.path.exists(data_file_path):
        print(f'Skipping {data_file} (not found)')
        return True
    if not os.path.exists(schema_file_path):
        print(f'::error::Schema {schema_file} not found in metarepo at {schema_file_path}')
        return False

    print(f'Validating {data_file} against canonical schema {schema_file}...')
    try:
        with open(data_file_path, 'r') as df:
            data = json.load(df)
        with open(schema_file_path, 'r') as sf:
            schema = json.load(sf)
        validate(instance=data, schema=schema)
        print(f'OK: {data_file}')
        return True
    except ValidationError as e:
        print(f'::error::Validation Error in {data_file}: {e.message}')
        return False
    except Exception as e:
        print(f'::error::Error processing {data_file}: {e}')
        return False

def main():
    # Ensure we resolve paths relative to the script location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)

    # In CI, metarepo is checked out to '_metarepo' as a sibling of 'webmaschine'.
    # So if we are in '.../workspace/webmaschine', metarepo is at '.../workspace/_metarepo'.
    # We allow overriding via env var for flexibility.
    metarepo_path_env = os.environ.get('METAREPO_PATH')
    if metarepo_path_env:
        metarepo_root = metarepo_path_env
    else:
        # Default assumption for CI structure: sibling directory of the repo root
        metarepo_root = os.path.abspath(os.path.join(repo_root, '..', '_metarepo'))

    print(f"Repo root: {repo_root}")
    print(f"Metarepo root: {metarepo_root}")

    # Check if metarepo exists
    if not os.path.exists(metarepo_root):
        print(f"::error::Metarepo directory not found at {metarepo_root}. Cannot validate contracts.")
        sys.exit(1)

    contracts_base = os.path.join(metarepo_root, 'contracts/webmaschine')

    # 1. Validate Zones
    zones_success = validate_zones(
        os.path.join(repo_root, 'config/zones.yml'),
        os.path.join(contracts_base, 'config/zones.schema.json')
    )

    # 2. Validate State Files
    files_to_validate = [
        ('state/index.json', 'state/index.schema.json'),
        ('state/repos.json', 'state/repos.schema.json'),
        ('state/uncertainties.json', 'state/uncertainties.schema.json'),
        ('state/insights.json', 'state/insights.schema.json'),
        ('state/drift.json', 'state/drift.schema.json')
    ]

    state_success = True
    for data_f, schema_f in files_to_validate:
        if not validate_state_file(data_f, schema_f, repo_root, contracts_base):
            state_success = False

    if not zones_success or not state_success:
        sys.exit(1)

if __name__ == "__main__":
    main()
