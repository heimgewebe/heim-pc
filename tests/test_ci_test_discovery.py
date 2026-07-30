from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "heim-pc-validate.yml"
REQUIREMENTS = ROOT / "requirements.txt"


class CiTestDiscoveryContractTests(unittest.TestCase):
    def test_ci_runs_pytest_so_pytest_style_tests_are_not_skipped(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("run: python3 -m pytest -q", workflow)
        self.assertNotIn("python3 -m unittest discover tests", workflow)

    def test_ci_declares_pytest_dependency(self) -> None:
        requirements = {
            line.strip().lower()
            for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }

        self.assertTrue(
            any(item == "pytest" or item.startswith("pytest>=") for item in requirements),
            "requirements.txt must install pytest before the CI test step",
        )
