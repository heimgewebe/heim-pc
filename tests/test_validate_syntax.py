
import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import tempfile
import shutil

# Ensure scripts directory is in python path
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(repo_root, 'scripts'))

import validate_syntax
import utils

class TestValidateSyntaxIntegration(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory
        self.test_dir = tempfile.mkdtemp()
        # Create dummy files
        # file_a matches *.yml
        with open(os.path.join(self.test_dir, 'file_a.yml'), 'w') as f:
            f.write("foo: bar")
        # file_b matches *.yml
        with open(os.path.join(self.test_dir, 'file_b.yml'), 'w') as f:
            f.write("foo: bar")

        # Create subdir
        subdir = os.path.join(self.test_dir, 'subdir')
        os.makedirs(subdir)
        # file_c matches **/*.yml
        with open(os.path.join(subdir, 'file_c.yml'), 'w') as f:
            f.write("foo: bar")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    @patch('utils.load_yaml')
    def test_validate_yaml_integration(self, mock_load_yaml):
        # We use patterns that overlap
        # Pattern 1: *.yml (matches file_a, file_b)
        # Pattern 2: **/*.yml (matches file_a, file_b, subdir/file_c)
        # We need relative patterns, so we pass the test_dir as repo_root

        patterns = ['*.yml', '**/*.yml']

        # Execute
        # We expect no errors
        has_error = validate_syntax.validate_yaml(patterns, self.test_dir)

        self.assertFalse(has_error)

        # Verification of Deduplication
        # Expected files: file_a.yml, file_b.yml, subdir/file_c.yml
        # Total unique files: 3
        # If deduplication fails, we would get file_a and file_b twice (total 5)
        self.assertEqual(mock_load_yaml.call_count, 3)

        # Verification of Deterministic Order
        # Files should be processed in alphabetical order
        calls = [args[0] for args, _ in mock_load_yaml.call_args_list]
        expected_files = sorted([
            os.path.join(self.test_dir, 'file_a.yml'),
            os.path.join(self.test_dir, 'file_b.yml'),
            os.path.join(self.test_dir, 'subdir/file_c.yml')
        ])

        self.assertEqual(calls, expected_files)

    @patch('utils.load_json')
    def test_validate_json_integration(self, mock_load_json):
        # Setup JSON files
        with open(os.path.join(self.test_dir, 'x.json'), 'w') as f:
            f.write("{}")
        with open(os.path.join(self.test_dir, 'y.json'), 'w') as f:
            f.write("{}")

        patterns = ['*.json', '**/*.json']

        has_error = validate_syntax.validate_json(patterns, self.test_dir)

        self.assertFalse(has_error)
        self.assertEqual(mock_load_json.call_count, 2)

        calls = [args[0] for args, _ in mock_load_json.call_args_list]
        expected_files = sorted([
            os.path.join(self.test_dir, 'x.json'),
            os.path.join(self.test_dir, 'y.json')
        ])
        self.assertEqual(calls, expected_files)

if __name__ == '__main__':
    unittest.main()
