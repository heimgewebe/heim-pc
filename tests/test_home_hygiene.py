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

    def test_alias_plan_skips_unsafe_tree_but_keeps_other_candidate(self) -> None:
        unsafe = self.home / "logs"
        unsafe.mkdir()
        (unsafe / "target.log").write_text("log", encoding="utf-8")
        (unsafe / "latest.log").symlink_to("target.log")
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
        self.assertEqual(skipped[str(unsafe)]["reason"], "unsafe_source_tree")
        self.assertIn("contains a symlink", skipped[str(unsafe)]["detail"])
        self.assertTrue(plan["applicable"])

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
