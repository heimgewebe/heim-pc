
import unittest
import os
import sys
import tempfile
import shutil
from pathlib import Path
from unittest.mock import MagicMock

# Mock yaml since it's not installed in this environment
sys.modules["yaml"] = MagicMock()

# Ensure scripts directory is in python path
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(repo_root, 'scripts'))

import utils

class TestResolvePath(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory for repo root and resolve it
        self.test_repo_root = Path(tempfile.mkdtemp()).resolve()

    def tearDown(self):
        shutil.rmtree(self.test_repo_root)

    def test_resolve_valid_relative_path(self):
        # Test: normal relative path within repo
        rel_path = 'state/index.json'
        expected = str(self.test_repo_root / rel_path)
        self.assertEqual(utils.resolve_path(rel_path, repo_root=self.test_repo_root), expected)

    def test_resolve_path_with_internal_traversal(self):
        # Test: internal traversal (stays within root)
        rel_path = 'state/../state/index.json'
        expected = str(self.test_repo_root / 'state/index.json')
        self.assertEqual(utils.resolve_path(rel_path, repo_root=self.test_repo_root), expected)

    def test_resolve_dot_path(self):
        # Test: same directory as repo root
        self.assertEqual(utils.resolve_path('.', repo_root=self.test_repo_root), str(self.test_repo_root))

    def test_error_on_escaping_traversal(self):
        # Test: traversal escaping repo root
        rel_path = '../../etc/passwd'
        with self.assertRaisesRegex(ValueError, "Path escapes repository root"):
            utils.resolve_path(rel_path, repo_root=self.test_repo_root)

    def test_error_on_absolute_path_injection(self):
        # Test: absolute path injection (outside root)
        # Using a fixed absolute path like /etc/passwd
        with self.assertRaisesRegex(ValueError, "Path escapes repository root"):
            utils.resolve_path('/etc/passwd', repo_root=self.test_repo_root)

    def test_absolute_path_within_root_is_allowed(self):
        # Test: absolute path that is inside the repository root
        abs_path_inside = str(self.test_repo_root / 'config/zones.yml')
        # This should be resolved correctly to itself
        self.assertEqual(utils.resolve_path(abs_path_inside, repo_root=self.test_repo_root), abs_path_inside)

if __name__ == '__main__':
    unittest.main()
