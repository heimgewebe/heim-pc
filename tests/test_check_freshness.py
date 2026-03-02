import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import json
from datetime import datetime, timezone

# Mock yaml because it's missing in the environment and scripts/utils.py imports it
sys.modules['yaml'] = MagicMock()

# Ensure scripts directory is in python path
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(repo_root, 'scripts'))

from check_freshness import check_freshness

class TestCheckFreshness(unittest.TestCase):

    @patch('utils.load_json')
    @patch('utils.log_error')
    def test_check_freshness_json_decode_error(self, mock_log_error, mock_load_json):
        # Setup: Mock load_json to raise JSONDecodeError
        # json.JSONDecodeError requires msg, doc, pos
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

    @patch('utils.load_json')
    def test_check_freshness_success(self, mock_load_json):
        # Setup: Mock load_json to return valid data (fresh)
        mock_load_json.return_value = {
            'metadata': {
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
        }

        # Execute
        result = check_freshness('valid.json')

        # Verify
        self.assertTrue(result)

    @patch('utils.load_json')
    @patch('utils.log_warning')
    def test_check_freshness_stale_data(self, mock_log_warning, mock_load_json):
        # Setup: Mock load_json to return stale data (more than 7 days ago)
        mock_load_json.return_value = {
            'metadata': {
                'last_updated': '2020-01-01T00:00:00Z'
            }
        }

        # Execute
        result = check_freshness('stale.json')

        # Verify
        self.assertTrue(result)
        mock_log_warning.assert_called_once_with('Stale data detected. The last update was more than 7 days ago.')

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

    @patch('utils.load_json')
    @patch('utils.log_error')
    def test_check_freshness_invalid_timestamp(self, mock_log_error, mock_load_json):
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

if __name__ == '__main__':
    unittest.main()
