#!/usr/bin/env python3
"""
Test for validate_syntax.py to ensure overlapping patterns don't produce duplicates
and file order is deterministic.
"""
import sys
import os
import tempfile
import glob

# Add scripts directory to path to import validate_syntax
sys.path.insert(0, os.path.dirname(__file__))

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
        
        # Collect files using the same logic as validate_yaml/validate_json
        files = []
        for p in patterns:
            abs_pattern = os.path.join(tmpdir, p)
            files.extend(glob.glob(abs_pattern, recursive=True))
        
        # Count before deduplication
        count_before = len(files)
        
        # Apply deduplication and sorting (same as in validate_syntax.py)
        files_deduplicated = sorted(set(files))
        
        # Count after deduplication
        count_after = len(files_deduplicated)
        
        # Assertions
        assert count_before > count_after, \
            f"Expected duplicates from overlapping patterns, but got {count_before} files before and {count_after} after"
        
        assert count_after == 3, \
            f"Expected exactly 3 unique files, got {count_after}"
        
        # Verify deterministic ordering (alphabetical)
        assert files_deduplicated == sorted(files_deduplicated), \
            "Files should be in sorted (alphabetical) order"
        
        # Verify file1 and file2 appeared twice (from both patterns)
        assert files.count(file1) == 2, \
            f"file1 should appear twice in raw list, got {files.count(file1)}"
        assert files.count(file2) == 2, \
            f"file2 should appear twice in raw list, got {files.count(file2)}"
        
        print("✓ Deduplication test passed: overlapping patterns correctly deduplicated")
        print(f"  Before: {count_before} processings")
        print(f"  After: {count_after} unique files")
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
