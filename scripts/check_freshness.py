#!/usr/bin/env python3
"""
Checks metadata freshness and placeholder status.
"""
import sys
import json
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
                # Handle cases where fromisoformat might fail on specific python versions if not exact
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
    # Use resolve_path instead of chdir
    file_path = utils.resolve_path('state/index.json')
    if not check_freshness(file_path):
        sys.exit(1)

if __name__ == "__main__":
    main()
