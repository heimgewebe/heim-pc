
import unittest
import os
import sys
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

# Mock yaml since it's not installed in this environment
sys.modules["yaml"] = MagicMock()

# Ensure scripts directory is in python path
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(repo_root, 'scripts'))

import utils

class TestResolvePath(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory for repo root and resolve it
        self.test_repo_root = Path(tempfile.mkdtemp()).resolve()
        self.repo_root_patcher = patch('utils.get_repo_root', return_value=str(self.test_repo_root))
        self.mock_get_repo_root = self.repo_root_patcher.start()

    def tearDown(self):
        self.repo_root_patcher.stop()
        shutil.rmtree(self.test_repo_root)

    def test_resolve_valid_relative_path(self):
        # Test: normal relative path within repo
        rel_path = 'state/index.json'
        expected = str(self.test_repo_root / rel_path)
        self.assertEqual(utils.resolve_path(rel_path), expected)

    def test_resolve_path_with_internal_traversal(self):
        # Test: internal traversal (stays within root)
        rel_path = 'state/../state/index.json'
        expected = str(self.test_repo_root / 'state/index.json')
        self.assertEqual(utils.resolve_path(rel_path), expected)

    def test_resolve_dot_path(self):
        # Test: same directory as repo root
        self.assertEqual(utils.resolve_path('.'), str(self.test_repo_root))

    def test_error_on_escaping_traversal(self):
        # Test: traversal escaping repo root
        rel_path = '../../etc/passwd'
        with self.assertRaisesRegex(ValueError, "Path escapes repository root"):
            utils.resolve_path(rel_path)

    def test_error_on_absolute_path_injection(self):
        # Test: absolute path injection (outside root)
        # Using a fixed absolute path like /etc/passwd
        with self.assertRaisesRegex(ValueError, "Path escapes repository root"):
            utils.resolve_path('/etc/passwd')

    def test_absolute_path_within_root_is_allowed(self):
        # Test: absolute path that is inside the repository root
        abs_path_inside = str(self.test_repo_root / 'config/zones.yml')
        # This should be resolved correctly to itself
        self.assertEqual(utils.resolve_path(abs_path_inside), abs_path_inside)

if __name__ == '__main__':
    unittest.main()
