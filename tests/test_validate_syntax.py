
import unittest
import sys
import os
import tempfile
import shutil

# Ensure scripts directory is in python path
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(repo_root, 'scripts'))

from validate_syntax import collect_files

class TestCollectFiles(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory
        self.test_dir = tempfile.mkdtemp()

        # Create dummy files
        self.file_a = os.path.join(self.test_dir, 'a.yml')
        self.file_b = os.path.join(self.test_dir, 'b.yml')
        self.subdir = os.path.join(self.test_dir, 'subdir')
        os.makedirs(self.subdir)
        self.file_c = os.path.join(self.subdir, 'c.yml')

        # Write dummy content
        for f in [self.file_a, self.file_b, self.file_c]:
            with open(f, 'w') as fh:
                fh.write("foo: bar")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_deduplication_and_order(self):
        # Overlapping patterns:
        # *.yml matches a.yml, b.yml
        # **/*.yml matches a.yml, b.yml, subdir/c.yml
        patterns = ['*.yml', '**/*.yml']

        # Execute
        result = collect_files(patterns, self.test_dir)

        # Expected: List of absolute paths, sorted alphabetically, unique
        expected = sorted([self.file_a, self.file_b, self.file_c])

        # Check 1: Exact match (Order + Uniqueness + Completeness)
        self.assertEqual(result, expected)

        # Check 2: Explicit uniqueness check (Overlap Case)
        # Without deduplication, length would be 5 (2 from first pattern + 3 from second)
        self.assertEqual(len(result), 3, "Result should contain exactly 3 unique files")

        # Check 3: Check specific file presence (Overlap Case)
        # file_a should be present exactly once
        self.assertEqual(result.count(self.file_a), 1, "file_a should appear exactly once")

if __name__ == '__main__':
    unittest.main()
