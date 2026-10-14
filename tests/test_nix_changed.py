import unittest
from unittest import mock

from scripts.ci import nix_changed


class T(unittest.TestCase):
    def test_relevant_paths_require_heavy_nix_ci(self):
        for path in (
            ".github/workflows/heim-pc-nix.yml",
            "config/home-hygiene.v1.json",
            "config/memory-pressure-guard.v1.json",
            "config/storage-pressure.v1.json",
            "flake.nix",
            "flake.lock",
            "nixos/system/flake.nix",
            "nixos/production/trust-contract-v1.json",
            "scripts/ci/check_pinned_nix_find_contract.py",
            "scripts/ci/nix_changed.py",
            "scripts/grabowski_memory_guard.py",
            "scripts/home_hygiene.py",
            "scripts/managed_build.py",
            "scripts/memory_pressure_snapshot.py",
            "scripts/pytest_temp_gc.py",
            "scripts/storage_inventory.py",
            "scripts/storage_pressure_watch.py",
            "scripts/nixos_production_install.py",
        ):
            with self.subTest(path=path):
                self.assertTrue(nix_changed.path_requires_nix(path))

    def test_signed_cache_probe_change_requires_heavy_nix_ci(self):
        probe = "scripts/ci/check_nix_cache_signature_rejection.sh"
        with mock.patch.object(nix_changed, "_changed_paths", return_value=[probe]):
            required, reason = nix_changed.detect("pull_request", "a" * 40, "b" * 40)
        self.assertTrue(required, reason)
        self.assertTrue(nix_changed.path_requires_nix(probe))

    def test_signature_probe_is_executed_inside_nix_job(self):
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/heim-pc-nix.yml").read_text(encoding="utf-8")
        detect_section, delimiter, nix_section = workflow.partition("\n  nix:\n")
        self.assertTrue(delimiter, "heavy Nix job must exist")
        invocation = (
            "- name: Prove untrusted signatures are rejected by substitution\n"
            "        run: bash scripts/ci/check_nix_cache_signature_rejection.sh"
        )
        self.assertEqual(nix_section.count(invocation), 1)
        self.assertNotIn(invocation, detect_section)
        self.assertTrue((root / "scripts/ci/check_nix_cache_signature_rejection.sh").is_file())

    def test_unrelated_paths_skip_heavy_nix_ci(self):
        for path in (
            "README.md",
            "architecture/runaway-guard.md",
            "tests/test_memory_pressure_guard.py",
            "docs/notes.md",
        ):
            with self.subTest(path=path):
                self.assertFalse(nix_changed.path_requires_nix(path))

    def test_large_changeset_has_no_github_path_filter_file_limit(self):
        paths = [f"docs/generated-{index}.md" for index in range(5000)]
        paths.append("nixos/system/modules/networking.nix")
        self.assertTrue(nix_changed.changed_paths_require_nix(paths))

    def test_unknown_git_comparison_fails_open_to_heavy_nix_ci(self):
        with mock.patch.object(nix_changed, "_changed_paths", return_value=None):
            required, reason = nix_changed.detect("pull_request", "a" * 40, "b" * 40)
        self.assertTrue(required)
        self.assertIn("fail-open", reason)

    def test_known_unrelated_comparison_skips_heavy_nix_ci(self):
        with mock.patch.object(
            nix_changed,
            "_changed_paths",
            return_value=["README.md", "architecture/runaway-guard.md"],
        ):
            required, reason = nix_changed.detect("pull_request", "a" * 40, "b" * 40)
        self.assertFalse(required)
        self.assertIn("no Nix-relevant change", reason)


if __name__ == "__main__":
    unittest.main()