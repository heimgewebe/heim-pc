from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("managed_cargo_maintenance", ROOT / "scripts/managed_cargo_maintenance.py")
assert SPEC and SPEC.loader
maintenance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(maintenance)


class ManagedCargoMaintenanceTests(unittest.TestCase):
    def evidence(self) -> dict:
        return {
            "schema_version": 1,
            "kind": maintenance.gc.EVIDENCE_KIND,
            "complete": True,
            "truncated": False,
            "observation_error_count": 0,
            "observation_errors": [],
            "evidence_sha256": "a" * 64,
        }

    def plan(self, *, candidates: bool, over_max: bool = True, blockers: list | None = None) -> dict:
        return {
            "plan_sha256": "b" * 64,
            "policy_sha256": "c" * 64,
            "safe_to_apply": candidates and not blockers,
            "candidates": [{"cache_key": "d" * 64}] if candidates else [],
            "convergence_blockers": blockers or [],
            "over_max_total": over_max,
            "total_managed_allocated_bytes": 1000,
        }

    def test_incomplete_task_evidence_fails_closed(self) -> None:
        value = self.evidence()
        value["complete"] = False
        with self.assertRaisesRegex(maintenance.MaintenanceError, "incomplete"):
            maintenance._validate_task_evidence(value)

    def test_non_hex_evidence_hash_fails_closed(self) -> None:
        value = self.evidence()
        value["evidence_sha256"] = "z" * 64
        with self.assertRaisesRegex(maintenance.MaintenanceError, "hash"):
            maintenance._validate_task_evidence(value)

    def test_reconcile_applies_exact_plan_and_records_reclaim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = {"max_receipts": 10}
            disk = type("Disk", (), {"total": 10000, "free": 4000})()
            with (
                patch.object(maintenance.mb, "load_policy", return_value=policy),
                patch.object(maintenance.gc, "build_plan", return_value=self.plan(candidates=True)),
                patch.object(maintenance.gc, "apply_plan", return_value={"receipt_path": "/tmp/gc.json", "receipt": {"after_allocated_bytes": 700, "reclaimed_bytes": 300}}) as apply,
                patch.object(maintenance.shutil, "disk_usage", return_value=disk),
            ):
                result = maintenance.reconcile(policy_path=root / "policy.json", state_root=root / "state", evidence_provider=lambda _limit: self.evidence())
            self.assertEqual(result["receipt"]["status"], "applied")
            self.assertEqual(result["receipt"]["reclaimed_bytes"], 300)
            self.assertEqual(apply.call_args.kwargs["expected_plan_sha256"], "b" * 64)
            self.assertEqual(apply.call_args.kwargs["confirmation"], maintenance.gc.CONFIRMATION)
            self.assertTrue((root / "state/latest.json").is_file())

    def test_over_budget_without_eligible_candidates_is_successful_attention_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            disk = type("Disk", (), {"total": 10000, "free": 3000})()
            with (
                patch.object(maintenance.mb, "load_policy", return_value={"max_receipts": 10}),
                patch.object(maintenance.gc, "build_plan", return_value=self.plan(candidates=False)),
                patch.object(maintenance.gc, "apply_plan") as apply,
                patch.object(maintenance.shutil, "disk_usage", return_value=disk),
            ):
                result = maintenance.reconcile(policy_path=root / "policy.json", state_root=root / "state", evidence_provider=lambda _limit: self.evidence())
            self.assertEqual(result["receipt"]["status"], "over_budget_no_eligible_candidates")
            apply.assert_not_called()


if __name__ == "__main__":
    unittest.main()
