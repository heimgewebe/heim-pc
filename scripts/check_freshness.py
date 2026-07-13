#!/usr/bin/env python3
"""Inspect one legacy fixture without claiming current host or repository truth."""

import json
import sys
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from typing import Optional

import utils


def check_freshness(file_path: str) -> bool:
    try:
        data = utils.load_json(file_path)

        last_updated_str: Optional[str] = data.get('metadata', {}).get('last_updated')

        if last_updated_str is None:
            utils.log_warning('metadata.last_updated is null (Placeholder data detected)')
        else:
            utils.log_info(f'Last updated: {last_updated_str}')
            # Replace Z with +00:00 for ISO 8601 compliance (defensive coding)
            if last_updated_str.endswith('Z'):
                last_updated_str = last_updated_str[:-1] + '+00:00'

            try:
                last_updated_dt = datetime.fromisoformat(last_updated_str)
            except ValueError as e:
                utils.log_error(f'Invalid ISO 8601 timestamp in metadata.last_updated: {last_updated_str} ({e})')
                return False

            if last_updated_dt.tzinfo is None:
                last_updated_dt = last_updated_dt.replace(tzinfo=timezone.utc)

            if datetime.now(timezone.utc) - last_updated_dt > timedelta(days=7):
                utils.log_warning('Stale data detected. The last update was more than 7 days ago.')

        return True

    except FileNotFoundError:
        utils.log_error(f'{file_path} not found.')
        return False
    except json.JSONDecodeError:
        utils.log_error(f'Could not decode {file_path}.')
        return False
    except Exception as e:
        utils.log_error(f'An unexpected error occurred: {e}')
        return False


def main() -> None:
    file_path = utils.resolve_path('state/index.json')
    # Legacy warnings remain visible on stderr; stdout stays one JSON object.
    with redirect_stdout(sys.stderr):
        structurally_readable = check_freshness(file_path)
    receipt = {
        'schemaVersion': 1,
        'kind': 'legacy_fixture_freshness_diagnostic',
        'canonical': False,
        'target': file_path,
        'structurallyReadable': structurally_readable,
        'doesNotEstablish': [
            'current_host_state',
            'current_repository_inventory',
            'runtime_health',
            'operator_entry_validity',
        ],
    }
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    if not structurally_readable:
        sys.exit(1)


if __name__ == "__main__":
    main()
