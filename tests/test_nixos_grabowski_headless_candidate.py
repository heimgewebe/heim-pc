"""Source gates for the opt-in full Grabowski/Nixer Seagate NixOS candidate.

These tests cannot replace the existing original-operator KVM proof, a real
Seagate root-owned policy, or a physical reboot/recovery acceptance test.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
FLAKE = ROOT / "nixos/system/flake.nix"
BASE = ROOT / "nixos/system/modules/seagate-primary-candidate.nix"
PRODUCTION = ROOT / "nixos/system/modules/grabowski-production.nix"
RELEASE = "72cc7119fabe-srcsete8cd97d6073c-lock264e747ad05a-contract650f923c4cfb"


class PinnedGrabowskiNixosCandidateTests(unittest.TestCase):
    def setUp(self):
        self.flake = FLAKE.read_text()
        start = "nixosConfigurations.heim-pc-seagate-grabowski-headless-candidate ="
        end = "# Negative pre-deployment proof is exported as a module"
        self.assertEqual(self.flake.count(start), 1)
        self.candidate = self.flake.split(start, 1)[1].split(end, 1)[0]

    def test_operator_is_opt_in_successor_of_nixer_not_primary_default(self):
        self.assertIn(
            "self.nixosConfigurations.heim-pc-seagate-nixer-headless-candidate.extendModules",
            self.candidate,
        )
        self.assertIn("heimPc.grabowskiProduction = {", self.candidate)
        self.assertIn("users.users.alex.linger = pkgs.lib.mkForce true;", self.candidate)
        self.assertIn("enable = true;", self.candidate)
        self.assertIn(f'releaseId =\n                  "{RELEASE}";', self.candidate)
        self.assertIn("import ./modules/grabowski-operator-package.nix", self.candidate)
        self.assertIn("import ./modules/grabowski-broker-package.nix", self.candidate)
        self.assertIn("packageOnly = true;", self.candidate)
        self.assertNotIn("privileged-actions.json", self.candidate)
        self.assertNotIn("BootNext", self.candidate)
        self.assertNotIn("canTouchEfiVariables = true", self.candidate)
        base = BASE.read_text()
        self.assertNotIn("heimPc.grabowskiProduction.enable = true;", base)
        self.assertNotIn("users.users.alex.linger = true", base)

    def test_primary_candidate_preserves_controlled_owner_recovery(self):
        base = BASE.read_text()
        self.assertIn("security.sudo.wheelNeedsPassword = lib.mkForce true;", base)
        self.assertIn("config.security.sudo.wheelNeedsPassword;", base)
        self.assertIn("security.sudo.extraRules = [{", base)
        self.assertIn('users = [ "alex" ];', base)
        self.assertIn('command = "ALL"; options = [ "NOPASSWD" ];', base)
        self.assertNotIn('!lib.hasInfix "NOPASSWD" config.security.sudo.configFile', base)
        # Existing SSH and rootbroker recovery paths remain configured.
        self.assertIn("PermitRootLogin = \"no\";", base)
        self.assertIn("AllowUsers = [ \"alex\" ];", base)
        self.assertIn("./grabowski-broker-package.nix", base)

    def test_configuration_has_hard_nix_eval_source_and_authority_gate(self):
        self.assertIn("seagate-grabowski-headless-contract =", self.flake)
        proof = self.flake.split(
            "seagate-grabowski-headless-contract =", 1
        )[1].split("grabowski-production-unit-contract =", 1)[0]
        for required in (
            "assert !baseline.heimPc.grabowskiProduction.enable;",
            "assert cfg.heimPc.grabowskiProduction.enable;",
            "operatorPackage.outPath == originalOperator.outPath;",
            "brokerPackage.outPath == originalBroker.outPath;",
            "assert cfg.system.configurationRevision == sourceRevision;",
            "assert !cfg.boot.loader.efi.canTouchEfiVariables;",
            'assert !(builtins.elem "nomodeset" cfg.boot.kernelParams);',
            'assert cfg.systemd.services.nixer-headless.serviceConfig.User == "alex";',
            'assert cfg.systemd.services.nixer-headless.serviceConfig.Group == "users";',
            'assert op.serviceConfig.Group == "users";',
            'assert cfg.users.users.alex.linger;',
            'assert builtins.elem "user@1000.service" op.requires;',
            'assert !(builtins.elem "grabowski" cfg.users.users.alex.extraGroups);',
            'assert op.serviceConfig.SupplementaryGroups == [ "grabowski" ];',
            'assert policy.unitConfig.AssertPathIsMountPoint == "/persist";',
            'assert builtins.elem "grabowski-private-policy-install.service" socket.requires;',
            'assert broker.serviceConfig.User == "root";',
            'assert !(builtins.hasAttr "grabowski-demo" cfg.systemd.services);',
        ):
            with self.subTest(required=required):
                self.assertIn(required, proof)
        self.assertIn(
            'assert cfg.heimPc.grabowskiProduction.releaseId ==\n            "' + RELEASE + '";',
            proof,
        )

    def test_private_rootbroker_policy_and_peer_authority_remain_original(self):
        production = PRODUCTION.read_text()
        self.assertIn(
            'SOURCE = Path("/persist/secrets/grabowski/privileged-actions.json")',
            (ROOT / "nixos/system/modules/grabowski-private-policy-install.py").read_text(),
        )
        self.assertIn(
            "systemd.services.grabowski-private-policy-install = lib.mkIf admit",
            production,
        )
        self.assertIn("lib.mkIf admit", production)
        self.assertIn('SupplementaryGroups = [ "grabowski" ];', production)
        self.assertIn("CapabilityBoundingSet =", production)
        self.assertIn('SystemCallFilter = "~@mount @module @reboot @swap";', production)
        self.assertNotIn("environment.etc.\"grabowski/privileged-actions.json\"", production)


if __name__ == "__main__":
    unittest.main()