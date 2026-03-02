import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import json
from datetime import datetime, timezone, timedelta

# Ensure scripts directory is in python path
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
scripts_path = os.path.join(repo_root, 'scripts')
if scripts_path not in sys.path:
    sys.path.insert(0, scripts_path)

# Scoped mock for yaml to avoid global side effects during session if possible.
yaml_patcher = patch.dict(sys.modules, {'yaml': MagicMock()})
yaml_patcher.start()

try:
    from check_freshness import check_freshness
except ImportError:
    yaml_patcher.stop()
    raise

# Define a fixed time for deterministic tests
FIXED_NOW = datetime(2026, 3, 2, 12, 0, 0, tzinfo=timezone.utc)

class TestCheckFreshness(unittest.TestCase):

    @classmethod
    def tearDownClass(cls):
        # Stop the YAML patcher after all tests in this class have run
        yaml_patcher.stop()

    @patch('utils.load_json')
    @patch('utils.log_error')
    def test_check_freshness_json_decode_error(self, mock_log_error, mock_load_json):
        # Setup: Mock load_json to raise JSONDecodeError
        mock_load_json.side_effect = json.JSONDecodeError("Expecting value", "{}", 0)

        # Execute
        result = check_freshness('dummy.json')

        # Verify
        self.assertFalse(result)
        mock_log_error.assert_called_once_with('Could not decode dummy.json.')

    @patch('utils.load_json')
    @patch('utils.log_error')
    def test_check_freshness_file_not_found_error(self, mock_log_error, mock_load_json):
        # Setup: Mock load_json to raise FileNotFoundError
        mock_load_json.side_effect = FileNotFoundError()

        # Execute
        result = check_freshness('missing.json')

        # Verify
        self.assertFalse(result)
        mock_log_error.assert_called_once_with('missing.json not found.')

    @patch('utils.load_json')
    @patch('utils.log_error')
    def test_check_freshness_unexpected_error(self, mock_log_error, mock_load_json):
        # Setup: Mock load_json to raise an unexpected Exception
        mock_load_json.side_effect = Exception("Boom!")

        # Execute
        result = check_freshness('error.json')

        # Verify
        self.assertFalse(result)
        mock_log_error.assert_called_once_with('An unexpected error occurred: Boom!')

    @patch('utils.log_info')
    @patch('check_freshness.datetime')
    @patch('utils.load_json')
    def test_check_freshness_success(self, mock_load_json, mock_datetime, mock_log_info):
        # Setup: Mock datetime to return fixed values
        mock_datetime.now.return_value = FIXED_NOW
        mock_datetime.fromisoformat.side_effect = datetime.fromisoformat

        # Setup: Mock load_json to return valid data (fresh)
        mock_load_json.return_value = {
            'metadata': {
                'last_updated': FIXED_NOW.isoformat()
            }
        }

        # Execute
        result = check_freshness('valid.json')

        # Verify
        self.assertTrue(result)
        mock_log_info.assert_called_once()

    @patch('utils.log_info')
    @patch('check_freshness.datetime')
    @patch('utils.load_json')
    @patch('utils.log_warning')
    def test_check_freshness_stale_data(self, mock_log_warning, mock_load_json, mock_datetime, mock_log_info):
        # Setup: Mock datetime
        mock_datetime.now.return_value = FIXED_NOW
        mock_datetime.fromisoformat.side_effect = datetime.fromisoformat

        # Setup: Mock load_json to return stale data (8 days ago)
        stale_time = FIXED_NOW - timedelta(days=8)
        mock_load_json.return_value = {
            'metadata': {
                'last_updated': stale_time.isoformat()
            }
        }

        # Execute
        result = check_freshness('stale.json')

        # Verify
        self.assertTrue(result)
        mock_log_warning.assert_called_once_with('Stale data detected. The last update was more than 7 days ago.')
        mock_log_info.assert_called_once()

    @patch('utils.load_json')
    @patch('utils.log_warning')
    def test_check_freshness_placeholder(self, mock_log_warning, mock_load_json):
        # Setup: Mock load_json to return data with null last_updated
        mock_load_json.return_value = {
            'metadata': {
                'last_updated': None
            }
        }

        # Execute
        result = check_freshness('placeholder.json')

        # Verify
        self.assertTrue(result)
        mock_log_warning.assert_called_once_with('metadata.last_updated is null (Placeholder data detected)')

    @patch('utils.log_info')
    @patch('utils.load_json')
    @patch('utils.log_error')
    def test_check_freshness_invalid_timestamp(self, mock_log_error, mock_load_json, mock_log_info):
        # Setup: Mock load_json to return data with invalid timestamp
        mock_load_json.return_value = {
            'metadata': {
                'last_updated': 'invalid-date'
            }
        }

        # Execute
        result = check_freshness('invalid.json')

        # Verify
        self.assertFalse(result)
        # Check that log_error was called with the expected message prefix
        called_args = mock_log_error.call_args[0][0]
        self.assertTrue(called_args.startswith('Invalid ISO 8601 timestamp in metadata.last_updated: invalid-date'))
        mock_log_info.assert_called_once()

if __name__ == '__main__':
    unittest.main()
