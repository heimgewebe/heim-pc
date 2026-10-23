"""Offline regression gates for the real, pinned NixOS Grabowski broker package.

These tests do not claim that the full operator is packaged or running.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "nixos" / "system" / "modules"
REVISION = "dd6dc690285b6a8a0cdbb3c18d84a1681e604923"
TARBALL_HASH = "sha256-rEsGU4mWRbti570DialOPusjZvFK1gfk7UUiI9pbrf4="


class GrabowskiProductionPackagingTests(unittest.TestCase):
    def test_exact_existing_broker_source_is_pinned(self):
        source = (MODULES / "grabowski-broker-package.nix").read_text()
        self.assertIn(f'sourceRevision = "{REVISION}";', source)
        self.assertIn('https://codeload.github.com/heimgewebe/grabowski/tar.gz/', source)
        self.assertIn(f'hash = "{TARBALL_HASH}";', source)
        self.assertIn('sourceArchive = pkgs.fetchurl', source)
        self.assertNotIn('fetchTarball', source)
        self.assertNotIn('rev = "main"', source)

    def test_broker_is_the_original_implementation_not_a_demo(self):
        source = (MODULES / "grabowski-broker-package.nix").read_text()
        self.assertIn('extracted/tools/grabowski_privileged_broker.py', source)
        for name in (
            "grabowski_privileged_broker",
            "grabowski_blockade_authority",
            "grabowski_blockade_store",
            "grabowski_blockades",
            "grabowski_command_identity",
            "grabowski_secret_pty",
        ):
            self.assertIn(name, source)
        self.assertIn('runpy.run_path(', source)
        self.assertIn('run_name="nixos_package_import_smoke"', source)

    def test_nixos_runtime_paths_cannot_fall_back_to_pop_mutable_source(self):
        source = (MODULES / "grabowski-broker-package.nix").read_text()
        self.assertIn('--replace-fail \'LIB_DIR = Path("/usr/local/lib/grabowski")\'', source)
        self.assertIn('--replace-fail \'SYSTEMCTL = "/usr/bin/systemctl"\'', source)
        self.assertIn('"\u0024{pkgs.systemd}/bin/systemctl"', source)
        self.assertIn('"\u0024{pkgs.systemd}/bin/systemd-run"', source)
        self.assertIn('makeWrapper "\u0024{pkgs.python3}/bin/python3"', source)
        # No attempt to repurpose Pop!_OS privileged package operations.
        self.assertNotIn('--replace-fail \'"/usr/bin/dpkg"\'', source)
        self.assertNotIn('--replace-fail \'"/usr/bin/snap"\'', source)

    def test_headless_operator_and_broker_remain_off_without_a_real_release(self):
        candidate = (MODULES / "seagate-primary-candidate.nix").read_text()
        production = (MODULES / "grabowski-production.nix").read_text()
        pinned = (MODULES / "grabowski-broker-package.nix").read_text()
        flake = (ROOT / "nixos" / "system" / "flake.nix").read_text()
        self.assertIn("./grabowski-broker-package.nix", candidate)
        self.assertIn("admit = cfg.enable && packagesPresent;", production)
        self.assertIn("default = null;", production)
        self.assertIn("lib.mkIf admit", production)
        self.assertIn("lib.mkDefault brokerPackage;", pinned)
        self.assertIn("assert !inactive.heimPc.grabowskiProduction.enable;", flake)
        self.assertIn("assert inactive.heimPc.grabowskiProduction.operatorPackage == null;", flake)
        self.assertIn("assert !(builtins.tryEval noPackages.system.build.toplevel.drvPath).success;", flake)
        self.assertNotIn('users.users.alex.extraGroups = lib.mkIf admit', production)
        self.assertIn('SupplementaryGroups = [ "grabowski" ];', production)
        self.assertIn('assert !(builtins.elem "grabowski" proof.users.users.alex.extraGroups);', flake)
        self.assertIn('assert builtins.elem "grabowski" operator.SupplementaryGroups;', flake)
        self.assertIn('CapabilityBoundingSet =', production)
        self.assertIn('CAP_SYS_ADMIN', production)
        self.assertIn('SystemCallFilter = "~@mount @module @reboot @swap";', production)
        self.assertIn('SystemCallErrorNumber = "EPERM";', production)
        self.assertIn('RestrictNamespaces = true;', production)
        self.assertIn('assert broker.RestrictNamespaces;', flake)



if __name__ == "__main__":
    unittest.main()