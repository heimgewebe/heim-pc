#!/usr/bin/env python3
"""
Checks metadata freshness and placeholder status.
"""
import json
import sys
import os
from datetime import datetime, timedelta, timezone

def check_freshness(file_path):
    try:
        if not os.path.exists(file_path):
            print(f'::error::{file_path} not found.')
            return False

        with open(file_path, 'r') as f:
            data = json.load(f)

        last_updated_str = data.get('metadata', {}).get('last_updated')

        if last_updated_str is None:
            print('::warning::metadata.last_updated is null (Placeholder data detected)')
        else:
            print(f'Last updated: {last_updated_str}')
            # Replace Z with +00:00 for ISO 8601 compliance (defensive coding)
            if last_updated_str.endswith('Z'):
                last_updated_str = last_updated_str[:-1] + '+00:00'

            try:
                last_updated_dt = datetime.fromisoformat(last_updated_str)
            except ValueError as e:
                # Handle cases where fromisoformat might fail on specific python versions if not exact
                print(f'::error::Invalid ISO 8601 timestamp in metadata.last_updated: {last_updated_str} ({e})')
                return False

            if last_updated_dt.tzinfo is None:
                last_updated_dt = last_updated_dt.replace(tzinfo=timezone.utc)

            if datetime.now(timezone.utc) - last_updated_dt > timedelta(days=7):
                print('::warning::Stale data detected. The last update was more than 7 days ago.')

        return True

    except ValueError as e:
         print(f'::error::Invalid ISO 8601 timestamp in metadata.last_updated: {e}')
         return False
    except json.JSONDecodeError:
        print(f'::error::Could not decode {file_path}.')
        return False
    except Exception as e:
        print(f'::error::An unexpected error occurred: {e}')
        return False

def main():
    # Ensure we run from the repository root to find state/index.json
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    os.chdir(repo_root)

    file_path = 'state/index.json'
    if not check_freshness(file_path):
        sys.exit(1)

if __name__ == "__main__":
    main()
