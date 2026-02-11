#!/usr/bin/env python3
"""
Validates configuration and state files against canonical schemas from the metarepo.
"""
import sys
import os
from typing import List, Tuple

from jsonschema import validate, ValidationError
import utils

def validate_zones(config_path: str, schema_path: str) -> bool:
    """Validates the zones configuration."""
    utils.log_info(f'Validating {config_path} against canonical JSON schema {schema_path}...')

    if not os.path.exists(config_path):
        utils.log_error(f"Config file {config_path} not found.")
        return False

    if not os.path.exists(schema_path):
        utils.log_error(f"Schema {schema_path} not found.")
        return False

    try:
        data = utils.load_yaml(config_path)
        schema = utils.load_json(schema_path)

        validate(instance=data, schema=schema)
        utils.log_info(f'OK: {config_path}')
        return True
    except ValidationError as e:
        utils.log_error(f'Validation Error in {config_path}: {e.message}')
        return False
    except Exception as e:
        utils.log_error(f'Error processing {config_path}: {e}')
        return False

def validate_state_file(data_file: str, schema_file: str, base_dir: str, schema_base_dir: str) -> bool:
    """Validates a single state file against its schema."""
    data_file_path = os.path.join(base_dir, data_file)
    schema_file_path = os.path.join(schema_base_dir, schema_file)

    if not os.path.exists(data_file_path):
        utils.log_info(f'Skipping {data_file} (not found)')
        return True
    if not os.path.exists(schema_file_path):
        utils.log_error(f'Schema {schema_file} not found in metarepo at {schema_file_path}')
        return False

    utils.log_info(f'Validating {data_file} against canonical schema {schema_file}...')
    try:
        data = utils.load_json(data_file_path)
        schema = utils.load_json(schema_file_path)

        validate(instance=data, schema=schema)
        utils.log_info(f'OK: {data_file}')
        return True
    except ValidationError as e:
        utils.log_error(f'Validation Error in {data_file}: {e.message}')
        return False
    except Exception as e:
        utils.log_error(f'Error processing {data_file}: {e}')
        return False

def main() -> None:
    repo_root = utils.get_repo_root()

    # In CI, metarepo is checked out to '_metarepo' as a sibling of 'heim-pc'.
    # So if we are in '.../workspace/heim-pc', metarepo is at '.../workspace/_metarepo'.
    # We allow overriding via env var for flexibility.
    metarepo_path_env = os.environ.get('METAREPO_PATH')
    if metarepo_path_env:
        metarepo_root = metarepo_path_env
    else:
        # Default assumption for CI structure: sibling directory of the repo root
        metarepo_root = os.path.abspath(os.path.join(repo_root, '..', '_metarepo'))

    utils.log_info(f"Repo root: {repo_root}")
    utils.log_info(f"Metarepo root: {metarepo_root}")

    # Check if metarepo exists
    if not os.path.exists(metarepo_root):
        utils.log_error(f"Metarepo directory not found at {metarepo_root}. Cannot validate contracts.")
        # We exit with 1 because validation cannot occur
        sys.exit(1)

    contracts_base = os.path.join(metarepo_root, 'contracts/heim-pc')

    # 1. Validate Zones
    zones_success = validate_zones(
        os.path.join(repo_root, 'config/zones.yml'),
        os.path.join(contracts_base, 'config/zones.schema.json')
    )

    # 2. Validate State Files
    files_to_validate: List[Tuple[str, str]] = [
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
