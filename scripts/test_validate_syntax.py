#!/usr/bin/env python3
"""
Test for validate_syntax.py to ensure overlapping patterns don't produce duplicates
and file order is deterministic.
"""
import sys
import os
import tempfile
import glob

# Import the actual function we're testing
sys.path.insert(0, os.path.dirname(__file__))
from validate_syntax import collect_files

def test_deduplication_and_ordering():
    """Test that overlapping glob patterns produce unique, sorted results."""
    # Create a temporary directory structure
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test YAML files
        config_dir = os.path.join(tmpdir, 'config')
        sub_dir = os.path.join(config_dir, 'subdir')
        os.makedirs(sub_dir)
        
        # Create files
        file1 = os.path.join(config_dir, 'a.yml')
        file2 = os.path.join(config_dir, 'b.yml')
        file3 = os.path.join(sub_dir, 'c.yml')
        
        for f in [file1, file2, file3]:
            with open(f, 'w') as fh:
                fh.write('test: value\n')
        
        # Simulate overlapping patterns like in main():
        # 'config/*.yml' matches file1, file2
        # 'config/**/*.yml' matches file1, file2, file3
        patterns = ['config/*.yml', 'config/**/*.yml']
        
        # First, manually collect files to demonstrate the duplication problem
        files_raw = []
        for p in patterns:
            abs_pattern = os.path.join(tmpdir, p)
            files_raw.extend(glob.glob(abs_pattern, recursive=True))
        
        # Verify the raw collection has duplicates
        count_before = len(files_raw)
        assert count_before == 5, \
            f"Expected 5 files from overlapping patterns (file1 and file2 appear twice, file3 once), but got {count_before}"
        
        # Verify file1 and file2 appeared twice (from both patterns)
        assert files_raw.count(file1) == 2, \
            f"file1 should appear twice in raw list, got {files_raw.count(file1)}"
        assert files_raw.count(file2) == 2, \
            f"file2 should appear twice in raw list, got {files_raw.count(file2)}"
        # Verify file3 appeared exactly once (only from recursive pattern)
        assert files_raw.count(file3) == 1, \
            f"file3 should appear once in raw list, got {files_raw.count(file3)}"
        
        # Now test the actual implementation
        files_deduplicated = collect_files(patterns, tmpdir)
        
        # Verify deduplication worked
        assert len(files_deduplicated) == 3, \
            f"Expected exactly 3 unique files after deduplication, got {len(files_deduplicated)}"
        
        # Verify deterministic ordering (alphabetical) with concrete expected values
        assert files_deduplicated == [file1, file2, file3], \
            f"Files should be in deterministic alphabetical order: {[file1, file2, file3]}, got {files_deduplicated}"
        
        print("✓ Deduplication test passed: overlapping patterns correctly deduplicated")
        print(f"  Before: {count_before} processings")
        print(f"  After: {len(files_deduplicated)} unique files")
        print("✓ Ordering test passed: files are in deterministic alphabetical order")
        
        return True

if __name__ == "__main__":
    try:
        test_deduplication_and_ordering()
        print("\n✓ All tests passed")
        sys.exit(0)
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        sys.exit(1)
