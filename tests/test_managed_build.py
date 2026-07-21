from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import managed_build


class ManagedBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy_path = (
            Path(__file__).resolve().parents[1]
            / "config"
            / "managed-build.v1.json"
        )
        self.policy = managed_build.load_policy(self.policy_path)

    def make_git_repo(self, root: Path) -> Path:
        repo = root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.email", "tests@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.name", "Managed Build Tests"],
            check=True,
        )
        (repo / "README.md").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "fixture"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "remote",
                "add",
                "origin",
                "https://secret-token@github.com/example/repository.git",
            ],
            check=True,
        )
        return repo

    def fixed_toolchain(self) -> dict[str, object]:
        return {"observations": {"fixture": "1"}, "sha256": "a" * 64}

    def test_repository_policy_loads(self) -> None:
        self.assertEqual(self.policy["schema_version"], 1)
        self.assertEqual(
            set(self.policy["tools"]),
            {"cargo", "node", "python", "playwright"},
        )
        self.assertFalse(self.policy["automatic_cleanup_authorized"])

    def test_policy_rejects_automatic_cleanup_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            data = json.loads(self.policy_path.read_text(encoding="utf-8"))
            data["automatic_cleanup_authorized"] = True
            path.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaisesRegex(managed_build.PolicyError, "must remain false"):
                managed_build.load_policy(path)

    def test_policy_rejects_duplicate_executable_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            data = json.loads(self.policy_path.read_text(encoding="utf-8"))
            data["tools"]["playwright"]["executables"].append("node")
            path.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaisesRegex(managed_build.PolicyError, "duplicate executable"):
                managed_build.load_policy(path)

    def test_repository_identity_is_shared_by_linked_worktrees(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = self.make_git_repo(root)
            linked = root / "linked"
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "worktree",
                    "add",
                    "-q",
                    "-b",
                    "linked-fixture",
                    str(linked),
                    "HEAD",
                ],
                check=True,
            )

            primary = managed_build.repository_facts(repo)
            secondary = managed_build.repository_facts(linked)

            self.assertEqual(
                primary["repository_identity_sha256"],
                secondary["repository_identity_sha256"],
            )
            self.assertEqual(primary["git_common_dir"], secondary["git_common_dir"])
            self.assertNotIn("secret-token", json.dumps(primary))

    def test_cargo_plan_is_external_and_identity_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            (repo / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
            environment_before = os.environ.copy()

            with patch.object(
                managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()
            ):
                first = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["cargo", "test"],
                    home=home,
                )
                second = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["cargo", "test"],
                    home=home,
                )

            cargo_target = Path(first["environment"]["CARGO_TARGET_DIR"])
            self.assertEqual(first["profile"], "test")
            self.assertEqual(first["cache_key"], second["cache_key"])
            self.assertNotEqual(first["generated_at"], "")
            self.assertTrue(cargo_target.is_relative_to(home))
            self.assertFalse(cargo_target.is_relative_to(repo))
            self.assertFalse(cargo_target.exists())
            self.assertEqual(os.environ, environment_before)

    def test_lockfile_or_profile_change_changes_cache_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            lockfile = repo / "Cargo.lock"
            lockfile.write_text("version = 3\n", encoding="utf-8")
            with patch.object(
                managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()
            ):
                dev = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["cargo", "check"],
                    home=home,
                )
                release = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["cargo", "check", "--release"],
                    home=home,
                )
                lockfile.write_text("version = 4\n", encoding="utf-8")
                changed = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["cargo", "check"],
                    home=home,
                )

            self.assertNotEqual(dev["cache_key"], release["cache_key"])
            self.assertNotEqual(dev["cache_key"], changed["cache_key"])

    def test_environment_resolver_reuses_identity_without_scanning_or_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            (repo / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
            environment_before = os.environ.copy()

            with (
                patch.object(managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()),
                patch.object(managed_build, "scan_worktree_payloads") as scan,
            ):
                resolved = managed_build.resolve_environment(
                    self.policy,
                    repo=repo,
                    command=["cargo"],
                    home=home,
                    explicit_tool="cargo",
                    explicit_profile="test",
                )
            with patch.object(
                managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()
            ):
                planned = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["cargo", "test"],
                    home=home,
                )

            scan.assert_not_called()
            self.assertEqual(resolved["kind"], "heim_pc.managed_build_environment")
            self.assertEqual(resolved["cache_key"], planned["cache_key"])
            self.assertEqual(resolved["environment"], planned["environment"])
            self.assertEqual(resolved["profile"], "test")
            self.assertFalse(Path(resolved["cache_path"]).exists())
            self.assertEqual(os.environ, environment_before)

    def test_environment_resolver_separates_lockfile_toolchain_and_profile_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            lockfile = repo / "Cargo.lock"
            lockfile.write_text("version = 3\n", encoding="utf-8")
            with patch.object(
                managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()
            ):
                first = managed_build.resolve_environment(
                    self.policy, repo=repo, command=["cargo"], home=home,
                    explicit_tool="cargo", explicit_profile="operator-task",
                )
                other_profile = managed_build.resolve_environment(
                    self.policy, repo=repo, command=["cargo"], home=home,
                    explicit_tool="cargo", explicit_profile="release",
                )
                lockfile.write_text("version = 4\n", encoding="utf-8")
                other_lock = managed_build.resolve_environment(
                    self.policy, repo=repo, command=["cargo"], home=home,
                    explicit_tool="cargo", explicit_profile="operator-task",
                )
            with patch.object(
                managed_build, "_toolchain_digest",
                return_value={"observations": {"fixture": "2"}, "sha256": "b" * 64},
            ):
                other_toolchain = managed_build.resolve_environment(
                    self.policy, repo=repo, command=["cargo"], home=home,
                    explicit_tool="cargo", explicit_profile="operator-task",
                )

            self.assertNotEqual(first["cache_key"], other_profile["cache_key"])
            self.assertNotEqual(first["cache_key"], other_lock["cache_key"])
            self.assertNotEqual(other_lock["cache_key"], other_toolchain["cache_key"])

    def test_node_python_and_playwright_are_explicitly_classified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            with patch.object(
                managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()
            ):
                node = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["npm", "test"],
                    home=home,
                )
                python = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["python3", "-m", "pytest"],
                    home=home,
                )
                playwright = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["npx", "playwright", "test"],
                    home=home,
                )

            self.assertEqual(node["tool"], "node")
            self.assertIn("NPM_CONFIG_CACHE", node["environment"])
            self.assertEqual(python["tool"], "python")
            self.assertIn("UV_CACHE_DIR", python["environment"])
            self.assertEqual(playwright["tool"], "playwright")
            self.assertIn("PLAYWRIGHT_BROWSERS_PATH", playwright["environment"])
            self.assertIn("PNPM_STORE_DIR", playwright["environment"])

    def test_real_storage_inventory_scan_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = self.make_git_repo(root)
            target = repo / "target"
            target.mkdir()
            (target / "payload.bin").write_bytes(b"payload")

            observation = managed_build.scan_worktree_payloads(repo, ["target"])

            self.assertGreaterEqual(observation["allocated_bytes"], 7)
            self.assertEqual(len(observation["entries"]), 1)
            self.assertEqual(observation["entries"][0]["relative_path"], "target")
            self.assertGreaterEqual(observation["entries"][0]["logical_bytes"], 7)

    def test_toolchain_probe_uses_resolved_cargo_and_sibling_rustc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            cargo = bin_dir / "cargo"
            rustc = bin_dir / "rustc"
            for executable in (cargo, rustc):
                executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                executable.chmod(0o755)
            calls: list[list[str]] = []

            def observe(argv: list[str], *, cwd: Path, timeout_seconds: int = 5) -> str:
                calls.append(argv)
                return "rc=0\nfixture"

            with patch.object(managed_build, "_run_readonly", side_effect=observe):
                digest = managed_build._toolchain_digest(
                    "cargo",
                    [str(cargo), "test"],
                    root,
                )

            self.assertEqual(calls[0], [str(cargo), "--version"])
            self.assertEqual(calls[1], [str(rustc.absolute()), "-Vv"])
            self.assertNotIn("unavailable", json.dumps(digest))

    def test_budget_boundaries_are_inclusive(self) -> None:
        budget = {"warning": 2, "hard": 5}
        self.assertEqual(managed_build._status(1, budget), "ok")
        self.assertEqual(managed_build._status(2, budget), "warning")
        self.assertEqual(managed_build._status(4, budget), "warning")
        self.assertEqual(managed_build._status(5, budget), "hard_limit")

    def test_hard_limit_blocks_without_pin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            hard = self.policy["managed_worktree_budget_bytes"]["hard"]
            with (
                patch.object(
                    managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()
                ),
                patch.object(
                    managed_build,
                    "scan_worktree_payloads",
                    return_value={"allocated_bytes": hard, "entries": []},
                ),
            ):
                plan = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["cargo", "test"],
                    home=home,
                )

            self.assertTrue(plan["guard"]["blocked"])
            self.assertEqual(plan["guard"]["status"], "blocked")

    def test_explicit_unexpired_pin_allows_hard_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            managed_build.create_pin(
                self.policy,
                repo=repo,
                tool="cargo",
                reason="large one-off verification",
                ttl_hours=1,
                home=home,
                now_epoch=100,
            )
            hard = self.policy["managed_worktree_budget_bytes"]["hard"]
            with (
                patch.object(
                    managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()
                ),
                patch.object(
                    managed_build,
                    "scan_worktree_payloads",
                    return_value={"allocated_bytes": hard, "entries": []},
                ),
            ):
                plan = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["cargo", "test"],
                    home=home,
                    now_epoch=200,
                )

            self.assertFalse(plan["guard"]["blocked"])
            self.assertEqual(plan["guard"]["status"], "hard_limit")
            self.assertEqual(plan["guard"]["pin"]["reason"], "large one-off verification")

    def test_expired_pin_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            result = managed_build.create_pin(
                self.policy,
                repo=repo,
                tool="cargo",
                reason="expired fixture",
                ttl_hours=1,
                home=home,
                now_epoch=100,
            )
            facts = managed_build.repository_facts(repo)

            self.assertIsNone(
                managed_build.read_pin(
                    Path(result["path"]).parents[1],
                    facts["repository_identity_sha256"],
                    "cargo",
                    now_epoch=4000,
                )
            )

    def test_execute_plan_refuses_blocked_plan_before_runner(self) -> None:
        runner = Mock()
        plan = {
            "guard": {"blocked": True},
        }
        with self.assertRaisesRegex(managed_build.ManagedBuildError, "blocked"):
            managed_build.execute_plan(
                self.policy,
                plan,
                ["cargo", "test"],
                home=Path("/tmp"),
                runner=runner,
            )
        runner.assert_not_called()

    def test_execute_plan_sets_child_environment_and_writes_bounded_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            policy = json.loads(json.dumps(self.policy))
            policy["max_receipts"] = 2
            with patch.object(
                managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()
            ):
                plan = managed_build.build_plan(
                    policy,
                    repo=repo,
                    command=[sys.executable, "--version"],
                    home=home,
                    explicit_tool="python",
                )
            captured: dict[str, object] = {}

            def runner(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                captured["argv"] = argv
                captured["environment"] = kwargs["env"]
                captured["cwd"] = kwargs["cwd"]
                return subprocess.CompletedProcess(argv, 0)

            returncode = managed_build.execute_plan(
                policy,
                plan,
                [sys.executable, "--version"],
                home=home,
                runner=runner,
            )

            receipts = list((home / ".local/state/heim-pc/managed-builds/receipts").glob("*.json"))
            self.assertEqual(returncode, 0)
            self.assertEqual(captured["cwd"], repo)
            child_environment = captured["environment"]
            self.assertEqual(
                child_environment["PIP_CACHE_DIR"],
                plan["environment"]["PIP_CACHE_DIR"],
            )
            self.assertEqual(len(receipts), 1)
            receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
            self.assertEqual(receipt["returncode"], 0)
            self.assertNotIn("argv", receipt["command"])
            self.assertFalse(receipt["automatic_cleanup_authorized"])

    def test_secure_directory_rejects_symlink_component(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            outside = Path(directory) / "outside"
            outside.mkdir()
            (home / ".cache").symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(managed_build.ManagedBuildError, "not a real directory"):
                managed_build._ensure_secure_directory(
                    home / ".cache/heim-pc/managed-builds",
                    home,
                )

    def test_policy_bound_executable_resolution_uses_home_tool_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            cargo = home / ".cargo/bin/cargo"
            cargo.parent.mkdir(parents=True)
            cargo.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            cargo.chmod(0o755)

            command = managed_build._normalized_command(
                ["cargo", "test"],
                policy=self.policy,
                home=home,
            )

            self.assertEqual(command[0], str(cargo.absolute()))
            self.assertEqual(command[1:], ["test"])

    def test_policy_bound_executable_resolution_rejects_explicit_path(self) -> None:
        with self.assertRaisesRegex(managed_build.ManagedBuildError, "without a path"):
            managed_build._normalized_command(
                ["/tmp/cargo", "test"],
                policy=self.policy,
                home=Path("/tmp"),
            )

    def test_policy_rejects_root_executable_search_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            data = json.loads(self.policy_path.read_text(encoding="utf-8"))
            data["executable_search_paths"] = ["/"]
            path.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaisesRegex(managed_build.PolicyError, "absolute or"):
                managed_build.load_policy(path)

    def test_invalid_explicit_tool_executable_pair_fails_closed(self) -> None:
        with self.assertRaisesRegex(managed_build.ManagedBuildError, "not allowed"):
            managed_build.classify_tool(
                self.policy,
                ["cargo", "test"],
                explicit_tool="python",
            )

    def test_trim_receipts_keeps_newest_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = []
            for index in range(4):
                path = root / f"{index}.json"
                path.write_text("{}\n", encoding="utf-8")
                os.utime(path, ns=(index + 1, index + 1))
                paths.append(path)

            managed_build._trim_receipts(root, 2)

            self.assertEqual(
                sorted(path.name for path in root.glob("*.json")),
                ["2.json", "3.json"],
            )


if __name__ == "__main__":
    unittest.main()
