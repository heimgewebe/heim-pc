from __future__ import annotations

import fcntl
import json
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from scripts import managed_build
from scripts import managed_cargo_gc


class ManagedCargoGcTests(unittest.TestCase):
    def setUp(self) -> None:
        policy_path = Path(__file__).resolve().parents[1] / "config" / "managed-build.v1.json"
        self.policy = managed_build.load_policy(policy_path)
        process_patcher = mock.patch.object(
            managed_cargo_gc, "_live_process_references", return_value=({}, [])
        )
        process_patcher.start()
        self.addCleanup(process_patcher.stop)

    def fixture(self, root: Path) -> tuple[dict, Path, Path]:
        policy = json.loads(json.dumps(self.policy))
        policy["cache_root"] = "${HOME}/cache"
        policy["state_root"] = "${HOME}/state"
        policy["cargo_cache_retention"] = {
            "minimum_unused_seconds": 100,
            "target_total_bytes": 0,
            "max_total_bytes": 1,
            "max_cleanup_per_run_bytes": 1024 * 1024,
            "max_cleanup_candidates_per_run": 8,
        }
        cache_root = root / "cache" / "cargo"
        state_root = root / "state"
        cache_root.mkdir(parents=True)
        (state_root / "receipts").mkdir(parents=True)
        return policy, cache_root, state_root

    def make_cache(self, cache_root: Path, key: str, size: int = 8192) -> Path:
        path = cache_root / key
        path.mkdir()
        (path / "artifact.bin").write_bytes(b"x" * size)
        return path

    def make_receipt(
        self,
        state_root: Path,
        cache_root: Path,
        key: str,
        *,
        repo_id: str = "f" * 64,
        finished_at: str = "1970-01-01T00:01:40Z",
    ) -> None:
        payload = {
            "schema_version": 1,
            "kind": "heim_pc.managed_build_receipt",
            "tool": "cargo",
            "cache_key": key,
            "cache_path": str(cache_root / key),
            "repository_identity_sha256": repo_id,
            "finished_at": finished_at,
        }
        (state_root / "receipts" / f"{key[:8]}.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )

    def make_evidence(
        self,
        root: Path,
        cache_root: Path,
        entries: list[dict],
        *,
        complete: bool = True,
        errors: list[str] | None = None,
    ) -> Path:
        payload = {
            "schema_version": 1,
            "kind": managed_cargo_gc.EVIDENCE_KIND,
            "complete": complete,
            "observation_errors": errors or [],
            "entries": entries,
        }
        payload["evidence_sha256"] = managed_cargo_gc._sha256_json(payload)
        path = root / "evidence.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def evidence_entry(
        self,
        cache_root: Path,
        key: str,
        *,
        protected: bool = False,
        last_used: int = 100,
        repo_id: str | None = "f" * 64,
        reasons: list[str] | None = None,
    ) -> dict:
        return {
            "cache_key": key,
            "cache_path": str(cache_root / key),
            "protected": protected,
            "last_used_at_unix": last_used,
            "repository_identity_sha256": repo_id,
            "reasons": reasons or [],
            "task_refs": [],
        }

    def test_inventory_fails_closed_without_task_evidence_or_usage_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, _ = self.fixture(home)
            key = "a" * 64
            self.make_cache(cache_root, key)
            (cache_root / "legacy-manual-target").mkdir()

            result = managed_cargo_gc.inventory(
                policy, home=home, evidence_path=None, now_unix=1000
            )

            self.assertEqual([item["cache_key"] for item in result["managed"]], [key])
            self.assertTrue(result["managed"][0]["protected"])
            self.assertIn(
                "external_protection_evidence_incomplete",
                result["managed"][0]["protection_reasons"],
            )
            self.assertIn(
                "usage_provenance_unknown", result["managed"][0]["protection_reasons"]
            )
            self.assertEqual(result["unclassified"][0]["name"], "legacy-manual-target")

    def test_symlink_identity_is_unclassified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, _ = self.fixture(home)
            target = home / "outside"
            target.mkdir()
            key = "a" * 64
            (cache_root / key).symlink_to(target, target_is_directory=True)

            result = managed_cargo_gc.inventory(
                policy, home=home, evidence_path=None, now_unix=1000
            )

            self.assertEqual(result["managed"], [])
            self.assertEqual(result["unclassified"][0]["reason"], "identity_path_not_real_directory")

    def test_complete_external_protection_keeps_shared_cache_out_of_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            key = "b" * 64
            self.make_cache(cache_root, key)
            self.make_receipt(state_root, cache_root, key)
            entry = self.evidence_entry(
                cache_root,
                key,
                protected=True,
                reasons=["running", "shared_cache_has_live_consumer"],
            )
            entry["task_refs"] = [
                {"task_id": "task-1", "state": "running"},
                {"task_id": "task-2", "state": "completed"},
            ]
            evidence = self.make_evidence(home, cache_root, [entry])

            plan = managed_cargo_gc.build_plan(
                policy, home=home, evidence_path=evidence, now_unix=1000
            )

            self.assertEqual(plan["candidates"], [])
            self.assertEqual(plan["protected"][0]["cache_key"], key)
            self.assertIn("running", plan["protected"][0]["selection_reasons"])

    def test_incomplete_external_evidence_blocks_cleanup_globally(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            key = "c" * 64
            self.make_cache(cache_root, key)
            self.make_receipt(state_root, cache_root, key)
            evidence = self.make_evidence(
                home,
                cache_root,
                [self.evidence_entry(cache_root, key)],
                complete=False,
            )

            plan = managed_cargo_gc.build_plan(
                policy, home=home, evidence_path=evidence, now_unix=1000
            )

            self.assertFalse(plan["safe_to_apply"])
            self.assertEqual(plan["candidates"], [])
            self.assertIn(
                "external_protection_evidence_incomplete",
                plan["protected"][0]["selection_reasons"],
            )

    def test_byte_prioritization_selects_larger_identity_first(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            policy["cargo_cache_retention"]["max_cleanup_per_run_bytes"] = 20 * 1024
            small = "d" * 64
            large = "e" * 64
            self.make_cache(cache_root, small, 4096)
            self.make_cache(cache_root, large, 12288)
            self.make_receipt(state_root, cache_root, small)
            self.make_receipt(state_root, cache_root, large)
            evidence = self.make_evidence(
                home,
                cache_root,
                [
                    self.evidence_entry(cache_root, small),
                    self.evidence_entry(cache_root, large),
                ],
            )

            plan = managed_cargo_gc.build_plan(
                policy, home=home, evidence_path=evidence, now_unix=1000
            )

            self.assertTrue(plan["candidates"])
            self.assertEqual(plan["candidates"][0]["cache_key"], large)
            self.assertGreaterEqual(
                plan["candidates"][0]["allocated_bytes"],
                plan["candidates"][-1]["allocated_bytes"],
            )

    def test_oversized_identity_is_reported_as_policy_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            policy["cargo_cache_retention"]["max_cleanup_per_run_bytes"] = 1
            key = "0" * 64
            self.make_cache(cache_root, key)
            self.make_receipt(state_root, cache_root, key)
            evidence = self.make_evidence(
                home, cache_root, [self.evidence_entry(cache_root, key)]
            )

            plan = managed_cargo_gc.build_plan(
                policy, home=home, evidence_path=evidence, now_unix=1000
            )

            self.assertEqual(plan["candidates"], [])
            self.assertFalse(plan["safe_to_apply"])
            self.assertEqual(plan["oversized_eligible"][0]["cache_key"], key)
            self.assertEqual(
                plan["convergence_blockers"][0]["kind"],
                "oversized_identity_requires_policy_override",
            )
            self.assertGreater(
                plan["convergence_blockers"][0][
                    "minimum_required_max_cleanup_per_run_bytes"
                ],
                1,
            )

    def test_candidate_count_limit_bounds_selection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            policy["cargo_cache_retention"]["max_cleanup_per_run_bytes"] = 10 * 1024 * 1024
            policy["cargo_cache_retention"]["max_cleanup_candidates_per_run"] = 2
            keys = [character * 64 for character in ("1", "2", "3")]
            for key in keys:
                self.make_cache(cache_root, key, 4096)
                self.make_receipt(state_root, cache_root, key)
            evidence = self.make_evidence(
                home,
                cache_root,
                [self.evidence_entry(cache_root, key) for key in keys],
            )

            plan = managed_cargo_gc.build_plan(
                policy, home=home, evidence_path=evidence, now_unix=1000
            )

            self.assertEqual(len(plan["candidates"]), 2)
            self.assertTrue(
                any(
                    blocker["kind"] == "candidate_count_limit_reached"
                    for blocker in plan["convergence_blockers"]
                )
            )

    def test_touch_changes_strict_but_not_stable_tree_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / ("4" * 64)
            root.mkdir()
            artifact = root / "artifact.bin"
            artifact.write_bytes(b"payload")
            before = managed_cargo_gc._tree_observation(root)
            current = artifact.stat().st_mtime_ns
            os.utime(artifact, ns=(current + 1_000_000, current + 1_000_000))
            after = managed_cargo_gc._tree_observation(root)
            self.assertNotEqual(
                before["strict_tree_fingerprint_sha256"],
                after["strict_tree_fingerprint_sha256"],
            )
            self.assertEqual(
                before["stable_tree_fingerprint_sha256"],
                after["stable_tree_fingerprint_sha256"],
            )

    def test_nested_symlink_is_not_followed_during_apply(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            key = "5" * 64
            cache = self.make_cache(cache_root, key)
            outside = home / "outside"
            outside.mkdir()
            sentinel = outside / "keep.txt"
            sentinel.write_text("keep", encoding="utf-8")
            (cache / "outside-link").symlink_to(outside, target_is_directory=True)
            self.make_receipt(state_root, cache_root, key)
            evidence = self.make_evidence(
                home, cache_root, [self.evidence_entry(cache_root, key)]
            )
            plan = managed_cargo_gc.build_plan(
                policy, home=home, evidence_path=evidence, now_unix=1000
            )
            plan_path = home / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")

            managed_cargo_gc.apply_plan(
                policy,
                home=home,
                plan_path=plan_path,
                evidence_path=evidence,
                expected_plan_sha256=plan["plan_sha256"],
                confirmation=managed_cargo_gc.CONFIRMATION,
            )

            self.assertFalse(cache.exists())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    def test_shared_lifecycle_lock_blocks_apply(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            key = "6" * 64
            cache = self.make_cache(cache_root, key)
            self.make_receipt(state_root, cache_root, key)
            evidence = self.make_evidence(
                home, cache_root, [self.evidence_entry(cache_root, key)]
            )
            plan = managed_cargo_gc.build_plan(
                policy, home=home, evidence_path=evidence, now_unix=1000
            )
            plan_path = home / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            lock_path = managed_cargo_gc._cache_lock_path(state_root, key)
            lock_path.parent.mkdir(parents=True)
            with lock_path.open("w+", encoding="utf-8", errors="strict") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
                with self.assertRaisesRegex(
                    managed_cargo_gc.CargoGcError, "lifecycle lock is held"
                ):
                    managed_cargo_gc.apply_plan(
                        policy,
                        home=home,
                        plan_path=plan_path,
                        evidence_path=evidence,
                        expected_plan_sha256=plan["plan_sha256"],
                        confirmation=managed_cargo_gc.CONFIRMATION,
                    )
            self.assertTrue(cache.exists())

    def test_unexpired_pin_protects_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            key = "1" * 64
            repo_id = "2" * 64
            self.make_cache(cache_root, key)
            self.make_receipt(state_root, cache_root, key, repo_id=repo_id)
            pin_dir = state_root / "pins"
            pin_dir.mkdir()
            (pin_dir / f"{repo_id}-cargo.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "repository_identity_sha256": repo_id,
                        "tool": "cargo",
                        "reason": "recovery",
                        "expires_at_unix": 5000,
                    }
                ),
                encoding="utf-8",
            )
            evidence = self.make_evidence(
                home,
                cache_root,
                [self.evidence_entry(cache_root, key, repo_id=repo_id)],
            )

            plan = managed_cargo_gc.build_plan(
                policy, home=home, evidence_path=evidence, now_unix=1000
            )

            self.assertEqual(plan["candidates"], [])
            self.assertIn("unexpired_pin", plan["protected"][0]["selection_reasons"])

    def test_minimum_unused_age_protects_recent_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            key = "3" * 64
            self.make_cache(cache_root, key)
            self.make_receipt(state_root, cache_root, key)
            evidence = self.make_evidence(
                home,
                cache_root,
                [self.evidence_entry(cache_root, key, last_used=950)],
            )

            plan = managed_cargo_gc.build_plan(
                policy, home=home, evidence_path=evidence, now_unix=1000
            )

            self.assertEqual(plan["candidates"], [])
            self.assertIn(
                "minimum_unused_age_not_reached",
                plan["protected"][0]["selection_reasons"],
            )

    def test_apply_rejects_tree_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            key = "4" * 64
            cache = self.make_cache(cache_root, key)
            self.make_receipt(state_root, cache_root, key)
            evidence = self.make_evidence(
                home,
                cache_root,
                [self.evidence_entry(cache_root, key)],
            )
            plan = managed_cargo_gc.build_plan(
                policy, home=home, evidence_path=evidence, now_unix=1000
            )
            self.assertTrue(plan["safe_to_apply"])
            plan_path = home / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            (cache / "changed").write_text("drift", encoding="utf-8")

            with self.assertRaisesRegex(managed_cargo_gc.CargoGcError, "tree changed"):
                managed_cargo_gc.apply_plan(
                    policy,
                    home=home,
                    plan_path=plan_path,
                    evidence_path=evidence,
                    expected_plan_sha256=plan["plan_sha256"],
                    confirmation=managed_cargo_gc.CONFIRMATION,
                )
            self.assertTrue(cache.exists())

    def test_apply_removes_only_exact_identity_and_writes_readback_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            key = "5" * 64
            cache = self.make_cache(cache_root, key)
            legacy = cache_root / "keep-me"
            legacy.mkdir()
            self.make_receipt(state_root, cache_root, key)
            evidence = self.make_evidence(
                home,
                cache_root,
                [self.evidence_entry(cache_root, key)],
            )
            plan = managed_cargo_gc.build_plan(
                policy, home=home, evidence_path=evidence, now_unix=1000
            )
            plan_path = home / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")

            result = managed_cargo_gc.apply_plan(
                policy,
                home=home,
                plan_path=plan_path,
                evidence_path=evidence,
                expected_plan_sha256=plan["plan_sha256"],
                confirmation=managed_cargo_gc.CONFIRMATION,
            )

            self.assertFalse(cache.exists())
            self.assertTrue(legacy.exists())
            receipt_path = Path(result["receipt_path"])
            self.assertTrue(receipt_path.is_file())
            self.assertEqual(result["receipt"]["remaining_unclassified_count"], 1)
            self.assertGreater(result["receipt"]["reclaimed_bytes"], 0)

    def test_unknown_repository_provenance_is_protected_when_any_cargo_pin_is_active(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            key = "6" * 64
            self.make_cache(cache_root, key)
            pin_dir = state_root / "pins"
            pin_dir.mkdir()
            unrelated_repo_id = "7" * 64
            (pin_dir / f"{unrelated_repo_id}-cargo.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "repository_identity_sha256": unrelated_repo_id,
                        "tool": "cargo",
                        "reason": "unknown cache could belong to pinned repo",
                        "expires_at_unix": 5000,
                    }
                ),
                encoding="utf-8",
            )
            evidence = self.make_evidence(
                home,
                cache_root,
                [self.evidence_entry(cache_root, key, repo_id=None)],
            )

            plan = managed_cargo_gc.build_plan(
                policy, home=home, evidence_path=evidence, now_unix=1000
            )

            self.assertEqual(plan["candidates"], [])
            self.assertIn(
                "repository_provenance_unknown_with_active_pins",
                plan["protected"][0]["selection_reasons"],
            )

    def test_live_process_reference_protects_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            key = "8" * 64
            self.make_cache(cache_root, key)
            self.make_receipt(state_root, cache_root, key)
            evidence = self.make_evidence(
                home, cache_root, [self.evidence_entry(cache_root, key)]
            )
            with mock.patch.object(
                managed_cargo_gc,
                "_live_process_references",
                return_value=({key: [12345]}, []),
            ):
                plan = managed_cargo_gc.build_plan(
                    policy, home=home, evidence_path=evidence, now_unix=1000
                )
            self.assertEqual(plan["candidates"], [])
            self.assertIn(
                "live_process_reference", plan["protected"][0]["selection_reasons"]
            )
            self.assertEqual(plan["protected"][0]["live_process_pids"], [12345])

    def test_incomplete_process_observation_blocks_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            key = "9" * 64
            self.make_cache(cache_root, key)
            self.make_receipt(state_root, cache_root, key)
            evidence = self.make_evidence(
                home, cache_root, [self.evidence_entry(cache_root, key)]
            )
            with mock.patch.object(
                managed_cargo_gc,
                "_live_process_references",
                return_value=({}, ["cannot inspect same-user process"]),
            ):
                plan = managed_cargo_gc.build_plan(
                    policy, home=home, evidence_path=evidence, now_unix=1000
                )
            self.assertFalse(plan["safe_to_apply"])
            self.assertIn(
                "process_observation_incomplete",
                plan["protected"][0]["selection_reasons"],
            )

    def test_malformed_cargo_pin_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            key = "a" * 64
            self.make_cache(cache_root, key)
            pin_dir = state_root / "pins"
            pin_dir.mkdir()
            (pin_dir / f"{'b' * 64}-cargo.json").write_text(
                json.dumps({"schema_version": 1, "tool": "cargo"}),
                encoding="utf-8",
            )
            evidence = self.make_evidence(
                home, cache_root, [self.evidence_entry(cache_root, key)]
            )
            with self.assertRaisesRegex(managed_cargo_gc.CargoGcError, "pin is malformed"):
                managed_cargo_gc.build_plan(
                    policy, home=home, evidence_path=evidence, now_unix=1000
                )

    def test_tampered_external_evidence_hash_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            key = "c" * 64
            self.make_cache(cache_root, key)
            self.make_receipt(state_root, cache_root, key)
            evidence = self.make_evidence(
                home, cache_root, [self.evidence_entry(cache_root, key)]
            )
            payload = json.loads(evidence.read_text(encoding="utf-8"))
            payload["entries"][0]["last_used_at_unix"] = 999
            evidence.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(managed_cargo_gc.CargoGcError, "evidence hash is invalid"):
                managed_cargo_gc.build_plan(
                    policy, home=home, evidence_path=evidence, now_unix=1000
                )

    def test_apply_aborts_if_process_reference_appears_after_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            key = "d" * 64
            cache = self.make_cache(cache_root, key)
            self.make_receipt(state_root, cache_root, key)
            evidence = self.make_evidence(
                home, cache_root, [self.evidence_entry(cache_root, key)]
            )
            plan = managed_cargo_gc.build_plan(
                policy, home=home, evidence_path=evidence, now_unix=1000
            )
            self.assertTrue(plan["safe_to_apply"])
            plan_path = home / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            with mock.patch.object(
                managed_cargo_gc,
                "_live_process_references",
                side_effect=[({}, []), ({key: [4242]}, [])],
            ):
                with self.assertRaisesRegex(
                    managed_cargo_gc.CargoGcError, "acquired live process reference"
                ):
                    managed_cargo_gc.apply_plan(
                        policy,
                        home=home,
                        plan_path=plan_path,
                        evidence_path=evidence,
                        expected_plan_sha256=plan["plan_sha256"],
                        confirmation=managed_cargo_gc.CONFIRMATION,
                    )
            self.assertTrue(cache.exists())

    def test_all_candidate_locks_are_acquired_before_first_delete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            policy["cargo_cache_retention"]["max_cleanup_per_run_bytes"] = 10 * 1024 * 1024
            first = "7" * 64
            second = "8" * 64
            first_cache = self.make_cache(cache_root, first, 4096)
            second_cache = self.make_cache(cache_root, second, 4096)
            for key in (first, second):
                self.make_receipt(state_root, cache_root, key)
            evidence = self.make_evidence(
                home,
                cache_root,
                [self.evidence_entry(cache_root, first), self.evidence_entry(cache_root, second)],
            )
            plan = managed_cargo_gc.build_plan(
                policy, home=home, evidence_path=evidence, now_unix=1000
            )
            self.assertEqual(len(plan["candidates"]), 2)
            plan_path = home / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            second_lock = managed_cargo_gc._cache_lock_path(state_root, second)
            second_lock.parent.mkdir(parents=True)
            with second_lock.open("w+", encoding="utf-8", errors="strict") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
                with self.assertRaisesRegex(
                    managed_cargo_gc.CargoGcError, "lifecycle lock is held"
                ):
                    managed_cargo_gc.apply_plan(
                        policy,
                        home=home,
                        plan_path=plan_path,
                        evidence_path=evidence,
                        expected_plan_sha256=plan["plan_sha256"],
                        confirmation=managed_cargo_gc.CONFIRMATION,
                    )
            self.assertTrue(first_cache.exists())
            self.assertTrue(second_cache.exists())
            self.assertEqual(list((state_root / "gc-receipts").glob("*.json")), [])

    def test_partial_delete_failure_writes_receipt_before_raising(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, state_root = self.fixture(home)
            policy["cargo_cache_retention"]["max_cleanup_per_run_bytes"] = 10 * 1024 * 1024
            first = "9" * 64
            second = "a" * 64
            first_cache = self.make_cache(cache_root, first, 4096)
            second_cache = self.make_cache(cache_root, second, 4096)
            for key in (first, second):
                self.make_receipt(state_root, cache_root, key)
            evidence = self.make_evidence(
                home,
                cache_root,
                [self.evidence_entry(cache_root, first), self.evidence_entry(cache_root, second)],
            )
            plan = managed_cargo_gc.build_plan(
                policy, home=home, evidence_path=evidence, now_unix=1000
            )
            self.assertEqual([item["cache_key"] for item in plan["candidates"]], [first, second])
            plan_path = home / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            real_rmtree = managed_cargo_gc.shutil.rmtree
            calls = 0

            def failing_second(path: Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated delete failure")
                real_rmtree(path)

            with (
                mock.patch.object(managed_cargo_gc.shutil, "rmtree", side_effect=failing_second),
                self.assertRaisesRegex(
                    managed_cargo_gc.CargoGcError, "partial or unverified effect"
                ),
            ):
                managed_cargo_gc.apply_plan(
                    policy,
                    home=home,
                    plan_path=plan_path,
                    evidence_path=evidence,
                    expected_plan_sha256=plan["plan_sha256"],
                    confirmation=managed_cargo_gc.CONFIRMATION,
                )

            self.assertFalse(first_cache.exists())
            self.assertTrue(second_cache.exists())
            receipts = list((state_root / "gc-receipts").glob("*.json"))
            self.assertEqual(len(receipts), 1)
            receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
            self.assertEqual(receipt["status"], "partial_failure")
            self.assertEqual([item["cache_key"] for item in receipt["removed"]], [first])
            self.assertIn("simulated delete failure", receipt["failure"])
            self.assertEqual(receipt["failed_candidate_cache_key"], second)
            self.assertGreater(receipt["applied_at_unix_ns"], 0)

    def test_snapshot_preserves_historical_usage_after_task_evidence_disappears(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, _state_root = self.fixture(home)
            key = "e" * 64
            self.make_cache(cache_root, key)
            evidence = self.make_evidence(
                home,
                cache_root,
                [self.evidence_entry(cache_root, key, last_used=100, repo_id=None)],
            )

            snapshot = managed_cargo_gc.snapshot_external_usage(
                policy, home=home, evidence_path=evidence, now_unix=200
            )

            self.assertEqual([item["cache_key"] for item in snapshot["written"]], [key])
            empty_evidence = self.make_evidence(home, cache_root, [])
            plan = managed_cargo_gc.build_plan(
                policy, home=home, evidence_path=empty_evidence, now_unix=1000
            )
            self.assertEqual([item["cache_key"] for item in plan["candidates"]], [key])
            self.assertEqual(plan["candidates"][0]["last_used_at_unix"], 100)
            self.assertEqual(plan["candidates"][0]["local_receipt_count"], 1)

    def test_snapshot_rejects_incomplete_external_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            policy, cache_root, _state_root = self.fixture(home)
            key = "f" * 64
            self.make_cache(cache_root, key)
            evidence = self.make_evidence(
                home,
                cache_root,
                [self.evidence_entry(cache_root, key)],
                complete=False,
            )
            with self.assertRaisesRegex(
                managed_cargo_gc.CargoGcError, "incomplete and cannot be snapshotted"
            ):
                managed_cargo_gc.snapshot_external_usage(
                    policy, home=home, evidence_path=evidence, now_unix=200
                )


if __name__ == "__main__":
    unittest.main()
