"""Exercise the deployed hygiene wrapper without touching a real checkout."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "modules/grabowski-worktree-hygiene.py"
SPEC = importlib.util.spec_from_file_location("hygiene_wrapper", SCRIPT)
wrapper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wrapper)


class WorktreeHygieneWrapperTests(unittest.TestCase):
    def test_bounded_budget_and_exact_pool_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Path(directory) / "runner.py"
            capture = Path(directory) / "capture.json"
            runner.write_text(
                "import json\n"
                "def _apply_periodic_worktree_hygiene(**kwargs):\n"
                f"    with open({str(capture)!r}, 'w') as out:\n"
                "        json.dump(kwargs, out)\n"
                "    return {'status': 'passed', 'completed': True, 'actions': 8,"
                " 'receipts': [{'status': 'passed', 'output': {'cleaned': [{}]}}]}\n"
            )
            out = io.StringIO()
            with (
                patch.object(sys, "argv", [str(SCRIPT), str(runner)]),
                patch.object(wrapper.Path, "is_dir", return_value=True),
                redirect_stdout(out),
            ):
                self.assertEqual(wrapper.main(), 0)
            forwarded = json.loads(capture.read_text())
            self.assertEqual(forwarded["max_actions"], 8)
            self.assertEqual(forwarded["owner_id"], "grabowski-primary")
            self.assertEqual(forwarded["repositories"], list(wrapper.REPOSITORIES))
            self.assertLessEqual(len(forwarded["repositories"]), 8)
            self.assertEqual(
                forwarded["allowed_checkout_roots"],
                [
                    "/home/alex/repos/.grabowski-worktrees",
                    "/home/alex/repos/.grabowski-review-snapshots",
                    "/home/alex/repos/.commonthing-worktrees",
                    "/home/alex/repos/.heim-pc-worktrees",
                ],
            )
            self.assertNotIn("/home/alex/repos", forwarded["allowed_checkout_roots"])
            summary = json.loads(out.getvalue())
            self.assertEqual(summary["repositories_checked"], 1)
            self.assertEqual(summary["cleaned"], 1)

    def test_missing_roots_are_not_broadly_substituted(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Path(directory) / "runner.py"
            runner.write_text("raise AssertionError('must not run')\n")
            with (
                patch.object(sys, "argv", [str(SCRIPT), str(runner)]),
                patch.object(wrapper.Path, "is_dir", return_value=False),
            ):
                with self.assertRaisesRegex(RuntimeError, "no configured"):
                    wrapper.main()


if __name__ == "__main__":
    unittest.main()
