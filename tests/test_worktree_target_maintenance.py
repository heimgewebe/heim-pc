from __future__ import annotations

import importlib.util
import json
import fcntl
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "worktree_target_maintenance",
    ROOT / "scripts" / "worktree_target_maintenance.py",
)
assert SPEC and SPEC.loader
maintenance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(maintenance)


class WorktreeTargetMaintenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.test_repo_root = Path.home() / "repos"
        self.test_repo_root.mkdir(parents=True, exist_ok=True)
        self.base_context = tempfile.TemporaryDirectory(
            prefix="heim-pc-target-test-", dir=self.test_repo_root
        )
        self.base = Path(self.base_context.name)
        self.repository = self.base / "repo"
        (self.repository / ".git").mkdir(parents=True)
        self.worktree_root = self.base / "worktrees"
        self.worktree_root.mkdir()
        self.worktree = self.worktree_root / "writer"
        self.target = self.worktree / "target"
        self.target.mkdir(parents=True)
        artifact = self.target / "debug" / "artifact"
        artifact.parent.mkdir()
        artifact.write_bytes(b"x" * 4096)
        old = int(time.time()) - 10 * 86400
        os.utime(artifact, (old, old))
        os.utime(artifact.parent, (old, old))
        os.utime(self.target, (old, old))
        self.state_root = self.base / "state"
        self.policy_path = self.base / "policy.json"
        self.policy_value = {
            "schema_version": 1,
            "kind": "heim_pc.worktree_target_policy",
            "owner_uid": os.getuid(),
            "automatic_apply": True,
            "warning_bytes": 1,
            "hard_bytes": 2,
            "warning_min_age_seconds": 7 * 86400,
            "hard_min_age_seconds": 86400,
            "max_candidates_per_run": 8,
            "max_remove_bytes_per_run": 1024 * 1024 * 1024,
            "max_tree_entries": 1000,
            "repositories": [
                {
                    "repository": str(self.repository),
                    "worktree_roots": [str(self.worktree_root)],
                }
            ],
            "quarantine_root": str(self.base / "quarantine"),
        }
        self.policy_path.write_text(json.dumps(self.policy_value), encoding="utf-8")

    def tearDown(self) -> None:
        self.base_context.cleanup()

    def record(self, *, dirty: bool = False, state: str = "unclassified_clean", blocking: bool = False) -> dict[str, object]:
        return {
            "path": str(self.worktree),
            "head": "a" * 40,
            "branch": "work/test",
            "is_main": False,
            "exists": True,
            "prunable": False,
            "status": {"dirty": dirty},
            "lifecycle_decision": {"state": state},
            "coordination": {"blocking": blocking},
        }

    def inventory(self, record: dict[str, object] | None = None):
        chosen = self.record() if record is None else record
        return lambda _repository: {"worktrees": [chosen]}

    def observation(self, roots, *, owner_uid, state_root, complete=True, referenced=False):
        normalized = sorted(str(root) for root in roots)
        references = []
        if referenced:
            references.append(
                {
                    "pid": 42,
                    "uid": owner_uid,
                    "kind": "cwd",
                    "root": normalized[0],
                    "path": normalized[0],
                }
            )
        material = {
            "kind": maintenance.OBSERVATION_KIND,
            "schema_version": 1,
            "complete": complete,
            "target_uid": owner_uid,
            "roots": normalized,
            "process_count": 1,
            "open_file_descriptors_checked": 0,
            "path_references": references,
            "errors": [] if complete else ["permission"],
        }
        return {**material, "observation_sha256": maintenance.canonical_sha256(material)}

    def rehash_plan(self, plan: dict[str, object]) -> None:
        material = dict(plan)
        material.pop("plan_sha256", None)
        material.pop("plan_id", None)
        plan["plan_id"] = maintenance.canonical_sha256(material)
        with_id = dict(plan)
        with_id.pop("plan_sha256", None)
        plan["plan_sha256"] = maintenance.canonical_sha256(with_id)

    def test_selects_only_old_clean_unreferenced_target(self) -> None:
        policy = maintenance.load_policy(self.policy_path)
        plan = maintenance.collect_plan(
            policy,
            state_root=self.state_root,
            inventory_provider=self.inventory(),
            observer=self.observation,
        )
        self.assertEqual(plan["threshold"], "hard")
        self.assertEqual([item["target"] for item in plan["selected"]], [str(self.target)])
        self.assertTrue(plan["process_observation_complete"])

    def test_dirty_retained_and_blocked_worktrees_are_excluded(self) -> None:
        policy = maintenance.load_policy(self.policy_path)
        for record, reason in (
            (self.record(dirty=True), "dirty-or-unknown"),
            (self.record(state="retained"), "retained-archived-or-classified"),
            (self.record(blocking=True), "active-lease-task-or-process"),
        ):
            plan = maintenance.collect_plan(
                policy,
                state_root=self.state_root,
                inventory_provider=self.inventory(record),
                observer=self.observation,
            )
            self.assertFalse(plan["selected"])
            self.assertIn(reason, {item["reason"] for item in plan["exclusions"]})

    def test_process_reference_or_incomplete_observation_blocks_selection(self) -> None:
        policy = maintenance.load_policy(self.policy_path)
        referenced = maintenance.collect_plan(
            policy,
            state_root=self.state_root,
            inventory_provider=self.inventory(),
            observer=lambda roots, **kwargs: self.observation(roots, referenced=True, **kwargs),
        )
        self.assertFalse(referenced["selected"])
        self.assertIn("active-process-reference", {item["reason"] for item in referenced["exclusions"]})
        incomplete = maintenance.collect_plan(
            policy,
            state_root=self.state_root,
            inventory_provider=self.inventory(),
            observer=lambda roots, **kwargs: self.observation(roots, complete=False, **kwargs),
        )
        self.assertFalse(incomplete["selected"])
        self.assertFalse(incomplete["process_observation_complete"])

    def test_apply_removes_only_target_and_writes_receipt(self) -> None:
        policy = maintenance.load_policy(self.policy_path)
        plan = maintenance.collect_plan(
            policy,
            state_root=self.state_root,
            inventory_provider=self.inventory(),
            observer=self.observation,
        )
        plan_path = maintenance.write_plan(plan, self.state_root)
        receipt = maintenance.apply_plan(
            plan_path,
            expected_sha256=plan["plan_sha256"],
            confirmation=f"APPLY:{plan['plan_id']}",
            policy_path=self.policy_path,
            state_root=self.state_root,
            inventory_provider=self.inventory(),
            observer=self.observation,
        )
        self.assertTrue(receipt["success"])
        self.assertFalse(self.target.exists())
        self.assertTrue(self.worktree.exists())
        self.assertFalse(receipt["source_files_removed"])
        self.assertFalse(receipt["worktrees_removed"])

    def test_apply_rejects_cross_device_quarantine_before_move(self) -> None:
        policy = maintenance.load_policy(self.policy_path)
        plan = maintenance.collect_plan(
            policy,
            state_root=self.state_root,
            inventory_provider=self.inventory(),
            observer=self.observation,
        )
        plan_path = maintenance.write_plan(plan, self.state_root)
        original_stat = maintenance.Path.stat

        def stat_with_foreign_target_device(path, *args, **kwargs):
            result = original_stat(path, *args, **kwargs)
            if path == self.target and kwargs.get("follow_symlinks", True):
                class ForeignDeviceStat:
                    st_dev = result.st_dev + 1
                return ForeignDeviceStat()
            return result

        with patch.object(maintenance.Path, "stat", new=stat_with_foreign_target_device):
            with self.assertRaisesRegex(maintenance.MaintenanceError, "different filesystem"):
                maintenance.apply_plan(
                    plan_path,
                    expected_sha256=plan["plan_sha256"],
                    confirmation=f"APPLY:{plan['plan_id']}",
                    policy_path=self.policy_path,
                    state_root=self.state_root,
                    inventory_provider=self.inventory(),
                    observer=self.observation,
                )
        self.assertTrue(self.target.exists())

    def test_apply_fails_fast_when_another_apply_holds_lock(self) -> None:
        policy = maintenance.load_policy(self.policy_path)
        plan = maintenance.collect_plan(
            policy,
            state_root=self.state_root,
            inventory_provider=self.inventory(),
            observer=self.observation,
        )
        plan_path = maintenance.write_plan(plan, self.state_root)
        lock_path = self.state_root / "apply.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("w") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(
                maintenance.MaintenanceError, "another maintenance instance"
            ):
                maintenance.apply_plan(
                    plan_path,
                    expected_sha256=plan["plan_sha256"],
                    confirmation=f"APPLY:{plan['plan_id']}",
                    policy_path=self.policy_path,
                    state_root=self.state_root,
                    inventory_provider=self.inventory(),
                    observer=self.observation,
                )
        self.assertTrue(self.target.exists())

    def test_post_move_process_reference_restores_target(self) -> None:
        policy = maintenance.load_policy(self.policy_path)
        plan = maintenance.collect_plan(
            policy,
            state_root=self.state_root,
            inventory_provider=self.inventory(),
            observer=self.observation,
        )
        plan_path = maintenance.write_plan(plan, self.state_root)
        calls = 0
        def observer_with_late_reference(roots, **kwargs):
            nonlocal calls
            calls += 1
            return self.observation(roots, referenced=calls == 2, **kwargs)
        with self.assertRaisesRegex(maintenance.MaintenanceError, "post-move"):
            maintenance.apply_plan(
                plan_path,
                expected_sha256=plan["plan_sha256"],
                confirmation=f"APPLY:{plan['plan_id']}",
                policy_path=self.policy_path,
                state_root=self.state_root,
                inventory_provider=self.inventory(),
                observer=observer_with_late_reference,
            )
        self.assertTrue(self.target.exists())

    def test_apply_rejects_candidate_target_outside_worktree(self) -> None:
        policy = maintenance.load_policy(self.policy_path)
        plan = maintenance.collect_plan(
            policy,
            state_root=self.state_root,
            inventory_provider=self.inventory(),
            observer=self.observation,
        )
        foreign = self.base / "foreign"
        foreign.mkdir()
        (foreign / "keep").write_text("important", encoding="utf-8")
        snapshot = maintenance.tree_snapshot(
            foreign, owner_uid=os.getuid(), max_entries=1000
        )
        item = plan["selected"][0]
        item["target"] = str(foreign)
        item["snapshot"] = snapshot
        item["candidate_id"] = maintenance.canonical_sha256({
            "repository": item["repository"],
            "worktree": item["worktree"],
            "target": item["target"],
            "head": item["head"],
            "branch": item["branch"],
            "tree_sha256": snapshot["tree_sha256"],
        })[:24]
        plan["selected_bytes"] = snapshot["size_bytes"]
        material = dict(plan)
        material.pop("plan_sha256", None)
        material.pop("plan_id", None)
        plan["plan_id"] = maintenance.canonical_sha256(material)
        with_id = dict(plan)
        with_id.pop("plan_sha256", None)
        plan["plan_sha256"] = maintenance.canonical_sha256(with_id)
        plan_path = maintenance.write_plan(plan, self.state_root)
        with self.assertRaisesRegex(maintenance.MaintenanceError, "worktree target"):
            maintenance.apply_plan(
                plan_path,
                expected_sha256=plan["plan_sha256"],
                confirmation=f"APPLY:{plan['plan_id']}",
                policy_path=self.policy_path,
                state_root=self.state_root,
                inventory_provider=self.inventory(),
                observer=self.observation,
            )
        self.assertTrue((foreign / "keep").exists())

    def test_apply_rejects_forged_budget_state(self) -> None:
        policy = maintenance.load_policy(self.policy_path)
        plan = maintenance.collect_plan(
            policy,
            state_root=self.state_root,
            inventory_provider=self.inventory(),
            observer=self.observation,
        )
        plan["total_target_bytes"] += 4096
        plan["projected_target_bytes"] += 4096
        self.rehash_plan(plan)
        plan_path = maintenance.write_plan(plan, self.state_root)
        with self.assertRaisesRegex(maintenance.MaintenanceError, "budget state changed"):
            maintenance.apply_plan(
                plan_path,
                expected_sha256=plan["plan_sha256"],
                confirmation=f"APPLY:{plan['plan_id']}",
                policy_path=self.policy_path,
                state_root=self.state_root,
                inventory_provider=self.inventory(),
                observer=self.observation,
            )
        self.assertTrue(self.target.exists())

    def test_apply_rejects_forged_snapshot_size(self) -> None:
        policy = maintenance.load_policy(self.policy_path)
        plan = maintenance.collect_plan(
            policy,
            state_root=self.state_root,
            inventory_provider=self.inventory(),
            observer=self.observation,
        )
        actual_size = plan["selected"][0]["snapshot"]["size_bytes"]
        plan["selected"][0]["snapshot"]["size_bytes"] = 1
        plan["selected_bytes"] = 1
        plan["projected_target_bytes"] += actual_size - 1
        self.rehash_plan(plan)
        plan_path = maintenance.write_plan(plan, self.state_root)
        with self.assertRaisesRegex(maintenance.MaintenanceError, "target changed after plan"):
            maintenance.apply_plan(
                plan_path,
                expected_sha256=plan["plan_sha256"],
                confirmation=f"APPLY:{plan['plan_id']}",
                policy_path=self.policy_path,
                state_root=self.state_root,
                inventory_provider=self.inventory(),
                observer=self.observation,
            )
        self.assertTrue(self.target.exists())

    def test_apply_rejects_forged_candidate_age(self) -> None:
        policy = maintenance.load_policy(self.policy_path)
        plan = maintenance.collect_plan(
            policy,
            state_root=self.state_root,
            inventory_provider=self.inventory(),
            observer=self.observation,
        )
        plan["selected"][0]["age_seconds"] += 999999
        self.rehash_plan(plan)
        plan_path = maintenance.write_plan(plan, self.state_root)
        with self.assertRaisesRegex(maintenance.MaintenanceError, "target age"):
            maintenance.apply_plan(
                plan_path,
                expected_sha256=plan["plan_sha256"],
                confirmation=f"APPLY:{plan['plan_id']}",
                policy_path=self.policy_path,
                state_root=self.state_root,
                inventory_provider=self.inventory(),
                observer=self.observation,
            )
        self.assertTrue(self.target.exists())

    def test_remove_failure_records_recovery_required(self) -> None:
        policy = maintenance.load_policy(self.policy_path)
        plan = maintenance.collect_plan(
            policy,
            state_root=self.state_root,
            inventory_provider=self.inventory(),
            observer=self.observation,
        )
        plan_path = maintenance.write_plan(plan, self.state_root)
        with patch.object(maintenance.shutil, "rmtree", side_effect=OSError("blocked")):
            with self.assertRaisesRegex(OSError, "blocked"):
                maintenance.apply_plan(
                    plan_path,
                    expected_sha256=plan["plan_sha256"],
                    confirmation=f"APPLY:{plan['plan_id']}",
                    policy_path=self.policy_path,
                    state_root=self.state_root,
                    inventory_provider=self.inventory(),
                    observer=self.observation,
                )
        receipt = json.loads(
            (self.state_root / "receipts" / f"{plan['plan_id']}.json").read_text()
        )
        self.assertEqual(receipt["state"], "recovery-required")
        self.assertFalse(self.target.exists())
        self.assertTrue(Path(receipt["pending"]["destination"]).exists())

    def test_post_move_mutation_during_observation_restores_target(self) -> None:
        policy = maintenance.load_policy(self.policy_path)
        plan = maintenance.collect_plan(
            policy,
            state_root=self.state_root,
            inventory_provider=self.inventory(),
            observer=self.observation,
        )
        plan_path = maintenance.write_plan(plan, self.state_root)
        calls = 0

        def mutating_observer(roots, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                destination = Path(roots[0])
                (destination / "mutation").write_text("changed", encoding="utf-8")
            return self.observation(roots, **kwargs)

        with self.assertRaisesRegex(maintenance.MaintenanceError, "post-move verification"):
            maintenance.apply_plan(
                plan_path,
                expected_sha256=plan["plan_sha256"],
                confirmation=f"APPLY:{plan['plan_id']}",
                policy_path=self.policy_path,
                state_root=self.state_root,
                inventory_provider=self.inventory(),
                observer=mutating_observer,
            )
        self.assertTrue(self.target.exists())
        self.assertTrue((self.target / "mutation").exists())

    def test_observer_exception_after_move_restores_target(self) -> None:
        policy = maintenance.load_policy(self.policy_path)
        plan = maintenance.collect_plan(
            policy,
            state_root=self.state_root,
            inventory_provider=self.inventory(),
            observer=self.observation,
        )
        plan_path = maintenance.write_plan(plan, self.state_root)
        calls = 0
        def failing_observer(roots, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise maintenance.MaintenanceError("observer unavailable")
            return self.observation(roots, **kwargs)
        with self.assertRaisesRegex(maintenance.MaintenanceError, "observer unavailable"):
            maintenance.apply_plan(
                plan_path,
                expected_sha256=plan["plan_sha256"],
                confirmation=f"APPLY:{plan['plan_id']}",
                policy_path=self.policy_path,
                state_root=self.state_root,
                inventory_provider=self.inventory(),
                observer=failing_observer,
            )
        self.assertTrue(self.target.exists())
        receipt = json.loads(
            (self.state_root / "receipts" / f"{plan['plan_id']}.json").read_text()
        )
        self.assertEqual(receipt["state"], "rolled-back")

    def test_apply_rejects_tree_drift(self) -> None:
        policy = maintenance.load_policy(self.policy_path)
        plan = maintenance.collect_plan(
            policy,
            state_root=self.state_root,
            inventory_provider=self.inventory(),
            observer=self.observation,
        )
        plan_path = maintenance.write_plan(plan, self.state_root)
        (self.target / "late").write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(
            maintenance.MaintenanceError,
            "target budget state changed after plan|target changed after plan",
        ):
            maintenance.apply_plan(
                plan_path,
                expected_sha256=plan["plan_sha256"],
                confirmation=f"APPLY:{plan['plan_id']}",
                policy_path=self.policy_path,
                state_root=self.state_root,
                inventory_provider=self.inventory(),
                observer=self.observation,
            )
        self.assertTrue(self.target.exists())


if __name__ == "__main__":
    unittest.main()
