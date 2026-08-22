from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from scripts import home_hygiene
from scripts import install_home_hygiene


class HomeHygieneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.policy_path = self.root / "policy.json"
        source_policy = json.loads(
            (Path(__file__).resolve().parents[1] / "config/home-hygiene.v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.policy_path.write_text(json.dumps(source_policy), encoding="utf-8")
        self.policy = home_hygiene.load_policy(self.policy_path, home=self.home)

    def test_policy_rejects_automatic_home_root_mutation(self) -> None:
        data = json.loads(self.policy_path.read_text(encoding="utf-8"))
        data["safety"]["automatic_home_root_mutation"] = True
        self.policy_path.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(home_hygiene.HygieneError, "must remain false"):
            home_hygiene.load_policy(self.policy_path, home=self.home)

    def test_inventory_classifies_allowed_candidate_and_unexpected(self) -> None:
        (self.home / "Dokumente").mkdir()
        candidate = self.home / "diff.txt"
        candidate.write_text("patch", encoding="utf-8")
        (self.home / "mystery").mkdir()

        result = home_hygiene.inventory(self.policy, home=self.home, now_unix=100)

        by_name = {item["name"]: item for item in result["entries"]}
        self.assertEqual(by_name["Dokumente"]["classification"], "allowed")
        self.assertEqual(by_name["diff.txt"]["classification"], "loose_candidate")
        self.assertEqual(by_name["mystery"]["classification"], "unexpected")
        self.assertEqual(result["summary"]["loose_candidate_count"], 1)
        self.assertFalse(result["summary"]["automatic_home_root_mutation"])

    def test_inventory_receipts_core_disappearance_during_initial_scan(self) -> None:
        directory = self.home / ".local/state/heim-pc/coredumps"
        directory.mkdir(parents=True)
        disappearing = directory / "core.inventory.1.1"
        disappearing.write_bytes(b"x")
        original_observation = home_hygiene._file_observation

        def observe(path: Path, *, hash_limit: int):
            if path == disappearing:
                raise FileNotFoundError(path)
            return original_observation(path, hash_limit=hash_limit)

        with mock.patch.object(
            home_hygiene, "_file_observation", side_effect=observe
        ):
            result = home_hygiene.inventory(
                self.policy, home=self.home, now_unix=100
            )

        self.assertEqual(result["coredumps"]["count"], 0)
        warnings = result["coredumps"]["observation_warnings"]
        self.assertEqual(len(warnings), 1)
        self.assertIn("disappeared during inventory observation", warnings[0])

    def test_quarantine_plan_and_apply_are_plan_hash_bound(self) -> None:
        candidate = self.home / "diff.txt"
        candidate.write_text("patch", encoding="utf-8")
        os.utime(candidate, (10, 10))
        plan_path = self.root / "quarantine-plan.json"
        with mock.patch.object(home_hygiene, "_process_references", return_value=({}, [])):
            plan = home_hygiene.build_quarantine_plan(
                self.policy, home=self.home, now_unix=100
            )
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            result = home_hygiene.apply_quarantine(
                self.policy,
                home=self.home,
                plan_path=plan_path,
                expected_plan_sha256=plan["plan_sha256"],
                confirmation=home_hygiene.QUARANTINE_CONFIRMATION,
            )

        self.assertFalse(candidate.exists())
        moved = result["receipt"]["moved"]
        self.assertEqual(len(moved), 1)
        self.assertTrue(Path(moved[0]["target"]).is_file())
        self.assertEqual(result["receipt"]["status"], "success")

    def test_quarantine_rejects_candidate_drift(self) -> None:
        candidate = self.home / "diff.txt"
        candidate.write_text("first", encoding="utf-8")
        plan_path = self.root / "quarantine-plan.json"
        with mock.patch.object(home_hygiene, "_process_references", return_value=({}, [])):
            plan = home_hygiene.build_quarantine_plan(
                self.policy, home=self.home, now_unix=100
            )
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            candidate.write_text("second", encoding="utf-8")
            with self.assertRaisesRegex(home_hygiene.HygieneError, "changed after planning"):
                home_hygiene.apply_quarantine(
                    self.policy,
                    home=self.home,
                    plan_path=plan_path,
                    expected_plan_sha256=plan["plan_sha256"],
                    confirmation=home_hygiene.QUARANTINE_CONFIRMATION,
                )

    def test_alias_migration_moves_tree_without_compatibility_link(self) -> None:
        source = self.home / "audits"
        source.mkdir()
        (source / "record.json").write_text("{}", encoding="utf-8")
        plan_path = self.root / "alias-plan.json"
        with mock.patch.object(home_hygiene, "_process_references", return_value=({}, [])):
            plan = home_hygiene.build_alias_plan(
                self.policy, home=self.home, now_unix=100
            )
            candidate = next(
                item for item in plan["candidates"] if item["source"] == str(source)
            )
            self.assertFalse(candidate["compatibility_symlink"])
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            result = home_hygiene.apply_alias_plan(
                self.policy,
                home=self.home,
                plan_path=plan_path,
                expected_plan_sha256=plan["plan_sha256"],
                confirmation=home_hygiene.ALIAS_CONFIRMATION,
            )

        target = self.home / "artifacts/audits"
        self.assertFalse(source.exists())
        self.assertEqual((target / "record.json").read_text(encoding="utf-8"), "{}")
        self.assertEqual(result["receipt"]["status"], "success")

    def test_alias_plan_skips_nonempty_target(self) -> None:
        source = self.home / "audits"
        source.mkdir()
        target = self.home / "artifacts/audits"
        target.mkdir(parents=True)
        (target / "existing").write_text("x", encoding="utf-8")
        with mock.patch.object(home_hygiene, "_process_references", return_value=({}, [])):
            plan = home_hygiene.build_alias_plan(
                self.policy, home=self.home, now_unix=100
            )
        skipped = {item["source"]: item["reason"] for item in plan["skipped"]}
        self.assertEqual(skipped[str(source)], "target_not_empty")

    def test_alias_plan_allows_internal_logs_symlink_with_compatibility_root(self) -> None:
        source = self.home / "logs"
        source.mkdir()
        target_file = source / "target.log"
        target_file.write_text("log", encoding="utf-8")
        (source / "latest.log").symlink_to(target_file)

        with mock.patch.object(home_hygiene, "_process_references", return_value=({}, [])):
            plan = home_hygiene.build_alias_plan(
                self.policy, home=self.home, now_unix=100
            )

        candidate = next(item for item in plan["candidates"] if item["source"] == str(source))
        self.assertEqual(candidate["mode"], "replace")
        self.assertTrue(candidate["allow_internal_symlinks"])
        self.assertTrue(candidate["allow_absolute_internal_symlinks"])
        plan_path = self.root / "logs-alias-plan.json"
        plan_path.write_text(json.dumps(plan), encoding="utf-8")
        with mock.patch.object(home_hygiene, "_process_references", return_value=({}, [])):
            result = home_hygiene.apply_alias_plan(
                self.policy,
                home=self.home,
                plan_path=plan_path,
                expected_plan_sha256=plan["plan_sha256"],
                confirmation=home_hygiene.ALIAS_CONFIRMATION,
            )
        migrated = self.home / "artifacts/logs"
        self.assertTrue(source.is_symlink())
        self.assertEqual((migrated / "latest.log").resolve(), migrated / "target.log")
        self.assertEqual(result["receipt"]["status"], "success")

    def test_alias_plan_rejects_logs_symlink_escaping_root(self) -> None:
        source = self.home / "logs"
        source.mkdir()
        outside = self.home / "outside.log"
        outside.write_text("outside", encoding="utf-8")
        (source / "latest.log").symlink_to(outside)
        safe = self.home / "audits"
        safe.mkdir()
        (safe / "record.json").write_text("{}", encoding="utf-8")

        with mock.patch.object(home_hygiene, "_process_references", return_value=({}, [])):
            plan = home_hygiene.build_alias_plan(
                self.policy, home=self.home, now_unix=100
            )

        candidates = {item["source"] for item in plan["candidates"]}
        skipped = {item["source"]: item for item in plan["skipped"]}
        self.assertIn(str(safe), candidates)
        self.assertEqual(skipped[str(source)]["reason"], "unsafe_source_tree")
        self.assertIn("escapes its root", skipped[str(source)]["detail"])

    def test_alias_merge_into_nonempty_target_is_collision_free(self) -> None:
        source = self.home / "diffs"
        source.mkdir()
        (source / "new.diff").write_text("new", encoding="utf-8")
        target = self.home / "artifacts/diffs"
        target.mkdir(parents=True)
        (target / "existing.diff").write_text("old", encoding="utf-8")
        plan_path = self.root / "alias-plan.json"

        with mock.patch.object(home_hygiene, "_process_references", return_value=({}, [])):
            plan = home_hygiene.build_alias_plan(self.policy, home=self.home, now_unix=100)
            candidate = next(item for item in plan["candidates"] if item["source"] == str(source))
            self.assertEqual(candidate["mode"], "merge")
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            result = home_hygiene.apply_alias_plan(
                self.policy,
                home=self.home,
                plan_path=plan_path,
                expected_plan_sha256=plan["plan_sha256"],
                confirmation=home_hygiene.ALIAS_CONFIRMATION,
            )

        self.assertFalse(source.exists())
        self.assertEqual((target / "existing.diff").read_text(), "old")
        self.assertEqual((target / "new.diff").read_text(), "new")
        self.assertEqual(result["receipt"]["status"], "success")
        self.assertEqual(len(result["receipt"]["migrated"][0]["moved_entries"]), 1)

    def test_alias_merge_race_does_not_replace_competing_destination(self) -> None:
        source = self.home / "diffs"
        source.mkdir()
        source_entry = source / "new.diff"
        source_entry.write_text("new", encoding="utf-8")
        target = self.home / "artifacts/diffs"
        target.mkdir(parents=True)
        (target / "existing.diff").write_text("old", encoding="utf-8")
        target_entry = target / "new.diff"
        plan_path = self.root / "alias-race-plan.json"

        with mock.patch.object(home_hygiene, "_process_references", return_value=({}, [])):
            plan = home_hygiene.build_alias_plan(self.policy, home=self.home, now_unix=100)
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            original_rename = home_hygiene._rename_noreplace

            def inject_competing_target(entry_source: Path, entry_target: Path) -> None:
                entry_target.write_text("competitor", encoding="utf-8")
                original_rename(entry_source, entry_target)

            with mock.patch.object(
                home_hygiene, "_rename_noreplace", side_effect=inject_competing_target
            ):
                with self.assertRaisesRegex(
                    home_hygiene.HygieneError, "alias migration had a partial effect"
                ):
                    home_hygiene.apply_alias_plan(
                        self.policy,
                        home=self.home,
                        plan_path=plan_path,
                        expected_plan_sha256=plan["plan_sha256"],
                        confirmation=home_hygiene.ALIAS_CONFIRMATION,
                    )

        self.assertEqual(target_entry.read_text(encoding="utf-8"), "competitor")
        self.assertEqual(source_entry.read_text(encoding="utf-8"), "new")
        receipts = list(
            (self.home / ".local/state/heim-pc/home-hygiene/alias-receipts").glob("*.json")
        )
        self.assertEqual(len(receipts), 1)
        receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
        self.assertIn("alias merge collision appeared", receipt["failure"])
        self.assertEqual(receipt["migrated"], [])

    def test_alias_merge_refuses_existing_destination_name(self) -> None:
        source = self.home / "diffs"
        source.mkdir()
        (source / "same.diff").write_text("new", encoding="utf-8")
        target = self.home / "artifacts/diffs"
        target.mkdir(parents=True)
        (target / "same.diff").write_text("old", encoding="utf-8")
        with mock.patch.object(home_hygiene, "_process_references", return_value=({}, [])):
            plan = home_hygiene.build_alias_plan(self.policy, home=self.home, now_unix=100)
        skipped = {item["source"]: item for item in plan["skipped"]}
        self.assertEqual(skipped[str(source)]["reason"], "target_collision")
        self.assertEqual(skipped[str(source)]["detail"], "same.diff")

    def test_alias_replace_partial_effect_is_receipted_after_root_move(self) -> None:
        source = self.home / "logs"
        source.mkdir()
        (source / "run.log").write_text("log", encoding="utf-8")
        plan_path = self.root / "logs-partial-plan.json"
        with mock.patch.object(home_hygiene, "_process_references", return_value=({}, [])):
            plan = home_hygiene.build_alias_plan(self.policy, home=self.home, now_unix=100)
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            with mock.patch.object(Path, "symlink_to", side_effect=OSError("injected")):
                with self.assertRaisesRegex(home_hygiene.HygieneError, "partial effect"):
                    home_hygiene.apply_alias_plan(
                        self.policy,
                        home=self.home,
                        plan_path=plan_path,
                        expected_plan_sha256=plan["plan_sha256"],
                        confirmation=home_hygiene.ALIAS_CONFIRMATION,
                    )
        target = self.home / "artifacts/logs"
        self.assertTrue(target.is_dir())
        self.assertFalse(source.exists())
        receipts = list(
            (self.home / ".local/state/heim-pc/home-hygiene/alias-receipts").glob("*.json")
        )
        self.assertEqual(len(receipts), 1)
        receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "partial_failure")
        self.assertTrue(receipt["migrated"][0]["partial"])
        self.assertTrue(receipt["migrated"][0]["replace_effect_started"])

    def test_installer_root_plan_is_bounded_and_hashes_content(self) -> None:
        plan = install_home_hygiene._root_plan(
            self.policy, home=self.home, user_name="alex"
        )

        sysctl = plan["sysctl"]
        limits = plan["limits"]
        self.assertEqual(sysctl["path"], "/etc/sysctl.d/60-heim-pc-coredump.conf")
        self.assertIn(str(self.home / ".local/state/heim-pc/coredumps"), sysctl["content"])
        self.assertIn("kernel.core_uses_pid=0", sysctl["content"])
        self.assertEqual(
            sysctl["sha256"],
            install_home_hygiene._sha256(sysctl["content"].encode("utf-8")),
        )
        self.assertEqual(
            limits["path"], "/etc/security/limits.d/60-heim-pc-coredump.conf"
        )
        self.assertIn("alex soft core 2097152", limits["content"])
        self.assertIn("alex hard core 2097152", limits["content"])

    def test_installer_rejects_symlink_in_runtime_directory_chain(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (self.home / ".local").symlink_to(outside, target_is_directory=True)

        with self.assertRaisesRegex(
            install_home_hygiene.InstallError, "directory chain is unsafe"
        ):
            install_home_hygiene._ensure_directory(
                self.home / ".local/state/heim-pc", home=self.home
            )

    def test_core_retention_removes_old_and_oversized_files(self) -> None:
        directory = self.home / ".local/state/heim-pc/coredumps"
        directory.mkdir(parents=True)
        old = directory / "core.old.1.1"
        old.write_bytes(b"x" * 200)
        recent = directory / "core.new.2.2"
        recent.write_bytes(b"y" * 50)
        os.utime(old, (1, 1))
        os.utime(recent, (995, 995))
        self.policy["coredumps"]["minimum_settled_seconds"] = 10
        self.policy["coredumps"]["retention_seconds"] = 100
        self.policy["coredumps"]["per_file_limit_bytes"] = 100
        self.policy["coredumps"]["max_total_bytes"] = 100
        with mock.patch.object(home_hygiene, "_process_references", return_value=({}, [])):
            result = home_hygiene.prune_coredumps(
                self.policy,
                home=self.home,
                confirmation=self.policy["coredumps"]["cleanup_confirmation"],
                now_unix=1000,
            )
        self.assertFalse(old.exists())
        self.assertTrue(recent.exists())
        self.assertEqual(result["receipt"]["reclaimed_bytes"], 200)

    def test_core_retention_defers_young_oversized_file(self) -> None:
        directory = self.home / ".local/state/heim-pc/coredumps"
        directory.mkdir(parents=True)
        young = directory / "core.young.3.3"
        young.write_bytes(b"z" * 200)
        os.utime(young, (995, 995))
        self.policy["coredumps"]["minimum_settled_seconds"] = 100
        self.policy["coredumps"]["retention_seconds"] = 1000
        self.policy["coredumps"]["per_file_limit_bytes"] = 100
        self.policy["coredumps"]["max_total_bytes"] = 100

        with mock.patch.object(home_hygiene, "_process_references", return_value=({}, [])):
            result = home_hygiene.prune_coredumps(
                self.policy,
                home=self.home,
                confirmation=self.policy["coredumps"]["cleanup_confirmation"],
                now_unix=1000,
            )

        self.assertTrue(young.exists())
        self.assertEqual(
            result["receipt"]["status"], "deferred_unsettled_over_budget"
        )
        self.assertEqual(result["receipt"]["removed"], [])
        self.assertEqual(
            result["receipt"]["deferred_unsettled"][0]["path"], str(young)
        )


    def test_mapped_file_targets_include_absolute_and_deleted_paths(self) -> None:
        targets = home_hygiene._mapped_file_targets(
            [
                "7f00-7f10 r--p 00000000 08:01 1 /tmp/file with spaces",
                "7f10-7f20 rw-p 00000000 08:01 2 /tmp/deleted.db (deleted)",
                "7f20-7f30 rw-p 00000000 00:00 0 [heap]",
            ]
        )

        self.assertEqual(
            targets, [Path("/tmp/file with spaces"), Path("/tmp/deleted.db")]
        )

    def test_quarantine_revalidates_immediately_before_each_move(self) -> None:
        first = self.home / "diff-a.txt"
        second = self.home / "diff-b.txt"
        first.write_text("first", encoding="utf-8")
        second.write_text("second", encoding="utf-8")
        os.utime(first, (10, 10))
        os.utime(second, (11, 11))
        plan_path = self.root / "quarantine-plan.json"
        original_validate = home_hygiene._validate_file_observation
        calls = 0

        def validate(path: Path, expected: dict[str, object], *, hash_limit: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 4:
                second.write_text("drift", encoding="utf-8")
            original_validate(path, expected, hash_limit=hash_limit)

        with mock.patch.object(home_hygiene, "_process_references", return_value=({}, [])):
            plan = home_hygiene.build_quarantine_plan(
                self.policy, home=self.home, now_unix=100
            )
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            with mock.patch.object(
                home_hygiene, "_validate_file_observation", side_effect=validate
            ):
                with self.assertRaisesRegex(
                    home_hygiene.HygieneError, "quarantine had a partial effect"
                ):
                    home_hygiene.apply_quarantine(
                        self.policy,
                        home=self.home,
                        plan_path=plan_path,
                        expected_plan_sha256=plan["plan_sha256"],
                        confirmation=home_hygiene.QUARANTINE_CONFIRMATION,
                    )

        self.assertFalse(first.exists())
        self.assertTrue(second.exists())
        receipts = list(
            (self.home / ".local/state/heim-pc/home-hygiene/quarantine-receipts").glob(
                "*.json"
            )
        )
        self.assertEqual(len(receipts), 1)
        receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "partial_failure")
        self.assertEqual(receipt["remaining_count"], 1)

    def test_alias_migration_revalidates_immediately_before_move(self) -> None:
        source = self.home / "audits"
        source.mkdir()
        (source / "record.json").write_text("{}", encoding="utf-8")
        plan_path = self.root / "alias-plan.json"
        original_observation = home_hygiene._tree_observation
        calls = 0

        def observe(path: Path) -> dict[str, object]:
            nonlocal calls
            calls += 1
            if calls == 2:
                (source / "late.json").write_text("{}", encoding="utf-8")
            return original_observation(path)

        with mock.patch.object(home_hygiene, "_process_references", return_value=({}, [])):
            plan = home_hygiene.build_alias_plan(
                self.policy, home=self.home, now_unix=100
            )
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            with mock.patch.object(
                home_hygiene, "_tree_observation", side_effect=observe
            ):
                with self.assertRaisesRegex(
                    home_hygiene.HygieneError, "alias migration had a partial effect"
                ):
                    home_hygiene.apply_alias_plan(
                        self.policy,
                        home=self.home,
                        plan_path=plan_path,
                        expected_plan_sha256=plan["plan_sha256"],
                        confirmation=home_hygiene.ALIAS_CONFIRMATION,
                    )

        self.assertTrue(source.exists())
        receipts = list(
            (self.home / ".local/state/heim-pc/home-hygiene/alias-receipts").glob(
                "*.json"
            )
        )
        self.assertEqual(len(receipts), 1)
        receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "partial_failure")
        self.assertIn("immediately before migration", receipt["failure"])

    def test_core_retention_receipts_disappearance_during_initial_scan(self) -> None:
        directory = self.home / ".local/state/heim-pc/coredumps"
        directory.mkdir(parents=True)
        disappearing = directory / "core.initial.5.5"
        disappearing.write_bytes(b"x")
        original_observation = home_hygiene._file_observation

        def observe(path: Path, *, hash_limit: int):
            if path == disappearing:
                raise FileNotFoundError(path)
            return original_observation(path, hash_limit=hash_limit)

        with mock.patch.object(
            home_hygiene, "_file_observation", side_effect=observe
        ):
            with mock.patch.object(
                home_hygiene, "_process_references", return_value=({}, [])
            ):
                result = home_hygiene.prune_coredumps(
                    self.policy,
                    home=self.home,
                    confirmation=self.policy["coredumps"]["cleanup_confirmation"],
                    now_unix=1000,
                )

        warnings = result["receipt"]["initial_observation_warnings"]
        self.assertEqual(len(warnings), 1)
        self.assertIn("disappeared during initial retention observation", warnings[0])

    def test_core_retention_receipts_disappearance_before_unlink(self) -> None:
        directory = self.home / ".local/state/heim-pc/coredumps"
        directory.mkdir(parents=True)
        disappearing = directory / "core.before-unlink.6.6"
        disappearing.write_bytes(b"x" * 200)
        os.utime(disappearing, (1, 1))
        self.policy["coredumps"]["minimum_settled_seconds"] = 10
        self.policy["coredumps"]["retention_seconds"] = 100
        original_validate = home_hygiene._validate_file_observation

        def validate(path: Path, expected: dict[str, object], *, hash_limit: int):
            if path == disappearing:
                path.unlink()
                raise FileNotFoundError(path)
            return original_validate(path, expected, hash_limit=hash_limit)

        with mock.patch.object(
            home_hygiene, "_process_references", return_value=({}, [])
        ):
            with mock.patch.object(
                home_hygiene, "_validate_file_observation", side_effect=validate
            ):
                result = home_hygiene.prune_coredumps(
                    self.policy,
                    home=self.home,
                    confirmation=self.policy["coredumps"]["cleanup_confirmation"],
                    now_unix=1000,
                )

        self.assertFalse(disappearing.exists())
        self.assertEqual(result["receipt"]["removed"], [])
        warnings = result["receipt"]["concurrent_removal_warnings"]
        self.assertEqual(len(warnings), 1)
        self.assertIn("disappeared immediately before retention removal", warnings[0])

    def test_core_retention_receipts_concurrent_disappearance(self) -> None:
        directory = self.home / ".local/state/heim-pc/coredumps"
        directory.mkdir(parents=True)
        recent = directory / "core.concurrent.4.4"
        recent.write_bytes(b"x" * 50)
        os.utime(recent, (995, 995))
        self.policy["coredumps"]["minimum_settled_seconds"] = 100
        self.policy["coredumps"]["retention_seconds"] = 1000
        self.policy["coredumps"]["max_total_bytes"] = 1000
        original_iterdir = Path.iterdir
        calls = 0

        def iterdir(path: Path):
            nonlocal calls
            if path == directory:
                calls += 1
                if calls == 2:
                    items = list(original_iterdir(path))

                    def disappearing():
                        for item in items:
                            yield item
                            if item == recent:
                                item.unlink()

                    return disappearing()
            return original_iterdir(path)

        with mock.patch.object(home_hygiene, "_process_references", return_value=({}, [])):
            with mock.patch.object(Path, "iterdir", new=iterdir):
                result = home_hygiene.prune_coredumps(
                    self.policy,
                    home=self.home,
                    confirmation=self.policy["coredumps"]["cleanup_confirmation"],
                    now_unix=1000,
                )

        warnings = result["receipt"]["post_observation_warnings"]
        self.assertEqual(len(warnings), 1)
        self.assertIn("disappeared during post-retention observation", warnings[0])


    def test_process_reference_blocks_quarantine_candidate(self) -> None:
        candidate = self.home / "diff.txt"
        candidate.write_text("patch", encoding="utf-8")
        references = {str(candidate): [123]}
        with mock.patch.object(
            home_hygiene, "_process_references", return_value=(references, [])
        ):
            plan = home_hygiene.build_quarantine_plan(
                self.policy, home=self.home, now_unix=int(time.time())
            )
        self.assertFalse(plan["applicable"])
        self.assertEqual(plan["skipped"][0]["reason"], "live_process_reference")


if __name__ == "__main__":
    unittest.main()
