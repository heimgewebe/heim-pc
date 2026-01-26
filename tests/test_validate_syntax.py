
import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Ensure scripts directory is in python path
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(repo_root, 'scripts'))

import validate_syntax
import utils

class TestValidateSyntax(unittest.TestCase):

    @patch('glob.glob')
    @patch('utils.load_yaml')
    @patch('os.path.isfile')
    def test_validate_yaml_deduplication_and_order(self, mock_isfile, mock_load_yaml, mock_glob):
        # Setup mocks
        # Simulate overlapping patterns returning duplicates and mixed order
        # pattern 1 returns [b, a]
        # pattern 2 returns [a, c]
        # Total raw: [b, a, a, c] -> Expected: [a, b, c]
        mock_glob.side_effect = [
            ['/path/to/b.yml', '/path/to/a.yml'],
            ['/path/to/a.yml', '/path/to/c.yml']
        ]
        mock_isfile.return_value = True

        patterns = ['pattern1', 'pattern2']
        repo_root = '/path/to'

        # Execute
        has_error = validate_syntax.validate_yaml(patterns, repo_root)

        # Verify deduplication: load_yaml called 3 times, not 4
        self.assertEqual(mock_load_yaml.call_count, 3)

        # Verify order: calls must be sorted (a, b, c)
        calls = [args[0] for args, _ in mock_load_yaml.call_args_list]
        self.assertEqual(calls, ['/path/to/a.yml', '/path/to/b.yml', '/path/to/c.yml'])

        self.assertFalse(has_error)

    @patch('glob.glob')
    @patch('utils.load_json')
    @patch('os.path.isfile')
    def test_validate_json_deduplication_and_order(self, mock_isfile, mock_load_json, mock_glob):
        # Similar test for JSON
        mock_glob.side_effect = [
            ['/path/to/y.json', '/path/to/x.json'],
            ['/path/to/x.json']
        ]
        mock_isfile.return_value = True

        patterns = ['pattern1', 'pattern2']
        repo_root = '/path/to'

        has_error = validate_syntax.validate_json(patterns, repo_root)

        # Expected: x, y
        self.assertEqual(mock_load_json.call_count, 2)
        calls = [args[0] for args, _ in mock_load_json.call_args_list]
        self.assertEqual(calls, ['/path/to/x.json', '/path/to/y.json'])

        self.assertFalse(has_error)

if __name__ == '__main__':
    unittest.main()
