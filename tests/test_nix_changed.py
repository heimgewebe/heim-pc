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

    def test_signed_cache_controls_cannot_skip_nix_ci(self):
        for path in (
            ".github/workflows/heim-pc-nix-cache-publish.yml",
            "scripts/ci/check_nix_cache_signature_rejection.sh",
            "tests/test_ci_nix_cache.py",
            "tests/test_nix_changed.py",
        ):
            with self.subTest(path=path):
                self.assertTrue(nix_changed.path_requires_nix(path))
                self.assertTrue(nix_changed.changed_paths_require_nix([path]))

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
