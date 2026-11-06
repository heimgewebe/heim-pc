"""Offline functional proof fixture for independently reconstructed Restic trees."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / "scripts/restic_independent_inventory.py"
SPEC = importlib.util.spec_from_file_location("restic_independent_inventory_test", MODULE)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class TreeInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stage = tempfile.TemporaryDirectory()
        self.addCleanup(self.stage.cleanup)
        root = Path(self.stage.name)
        self.snapshot = root / "snapshot"
        self.restored = root / "restored"
        for tree in (self.snapshot, self.restored):
            for path in checker.PATHS:
                (tree / path.lstrip("/")).mkdir(parents=True, exist_ok=True)
            files = tree / "home/alex"
            (files / "notes with space.txt").write_bytes(b"important notes\n")
            (files / "nested").mkdir()
            (files / "nested/durable.txt").write_bytes(bytes(range(256)))
            (tree / "persist/notes").symlink_to("../home/alex/notes with space.txt")

    def test_equal_full_snapshot_and_restore_have_identical_content_hashes(self) -> None:
        result = checker.compare(self.snapshot, self.restored)
        self.assertEqual(result["source_sha256"], result["restored_sha256"])
        self.assertEqual(len(result["source_sha256"]), 64)
        self.assertEqual(result["file_count"], 2)
        self.assertEqual(result["total_bytes"], len(b"important notes\n") + 256)
        self.assertEqual(set(result["covered_paths"]), set(checker.PATHS))

    def test_changed_file_bytes_are_rejected_even_if_size_matches(self) -> None:
        (self.restored / "home/alex/notes with space.txt").write_bytes(b"tampered! notes\n")
        with self.assertRaisesRegex(RuntimeError, "inventories differ"):
            checker.compare(self.snapshot, self.restored)

    def test_missing_file_rejected(self) -> None:
        (self.restored / "home/alex/nested/durable.txt").unlink()
        with self.assertRaisesRegex(RuntimeError, "inventories differ"):
            checker.compare(self.snapshot, self.restored)

    def test_changed_symlink_rejected(self) -> None:
        target = self.restored / "persist/notes"
        target.unlink()
        target.symlink_to("/etc/passwd")
        with self.assertRaisesRegex(RuntimeError, "inventories differ"):
            checker.compare(self.snapshot, self.restored)

    def test_empty_or_missing_required_path_rejected(self) -> None:
        (self.restored / "var/lib/grabowski").rmdir()
        with self.assertRaisesRegex(RuntimeError, "required restore directory missing"):
            checker.compare(self.snapshot, self.restored)

    def test_same_tree_and_nested_trees_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "disjoint source"):
            checker.compare(self.snapshot, self.snapshot)
        with self.assertRaisesRegex(RuntimeError, "disjoint source"):
            checker.compare(self.snapshot, self.snapshot / "home/alex")

    def test_malicious_required_anchor_symlink_rejected(self) -> None:
        (self.restored / "persist/notes").unlink()
        (self.restored / "persist").rmdir()
        (self.restored / "persist").symlink_to(self.snapshot / "persist")
        with self.assertRaisesRegex(RuntimeError, "anchor symlink"):
            checker.compare(self.snapshot, self.restored)

    def test_inventories_deterministic(self) -> None:
        previous = checker.inventory(self.snapshot)
        self.assertEqual(previous, checker.inventory(self.snapshot))


if __name__ == "__main__":
    unittest.main()
