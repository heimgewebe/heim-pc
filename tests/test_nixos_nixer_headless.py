"""Seagate NixOS: Nixer may run without a user manager, but not with root rights."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
FLAKE = ROOT / "nixos/system/flake.nix"
MODULE = ROOT / "nixos/system/modules/nixer-headless.nix"
PRIMARY = ROOT / "nixos/system/modules/seagate-primary-candidate.nix"
TRUST = ROOT / "nixos/production/trust-contract-v1.json"


class NixerHeadlessSourceTests(unittest.TestCase):
    def test_service_is_system_scoped_and_does_not_grant_root_or_linger(self):
        text = MODULE.read_text()
        self.assertIn('lib.mkEnableOption', text)
        self.assertIn('systemd.services.nixer-headless = {', text)
        self.assertNotIn('systemd.user.services.nixer-headless', text)
        self.assertIn('wantedBy = [ "multi-user.target" ];', text)
        self.assertIn('User = "alex";', text)
        self.assertIn('Group = "users";', text)
        self.assertIn("NoNewPrivileges = true;", text)
        self.assertNotIn("NoNewPrivileges = false;", text)
        self.assertIn('RuntimeDirectory = "nixer-headless";', text)
        self.assertIn('RuntimeDirectoryMode = "0700";', text)
        self.assertNotIn('!config.users.users.alex.linger', text)
        self.assertIn('!config.services.nixer.enable', text)
        self.assertIn('!(builtins.elem "grabowski" config.users.users.alex.extraGroups)', text)
        self.assertNotIn('User = "root";', text)
        self.assertNotIn('SupplementaryGroups =', text)

    def test_read_only_nixer_fails_closed_without_exact_preinstalled_image(self):
        text = MODULE.read_text()
        trust = json.loads(TRUST.read_text())
        image_id = trust["managed_nix_verifier"]["image_id"]
        self.assertIn(image_id, text)
        self.assertIn("podman image inspect --format '{{.Id}}'", text)
        self.assertIn('if [ "$observed" !=', text)
        self.assertIn('expected=${lib.escapeShellArg (lib.removePrefix "sha256:" pinnedImageId)}', text)
        self.assertIn('if [ "$observed" != "$expected" ] && [ "$observed" != "sha256:$expected" ]; then', text)
        self.assertNotIn('if [ "$observed" != ${lib.escapeShellArg pinnedImageId} ]; then', text)
        self.assertIn('ExecStartPre = "${checkImage}/bin/heim-pc-nixer-check-image";', text)
        self.assertIn('NIXER_DOCKER_BIN = "${pkgs.podman}/bin/podman";', text)
        self.assertIn('NIXER_CONTAINER_XDG_RUNTIME_DIR = "/run/nixer-headless";', text)
        self.assertIn('NIXER_REPO_ROOT = "/home/alex/repos";', text)
        self.assertIn('--host 127.0.0.1 --port 18187', text)
        self.assertNotIn('podman pull ', text)
        self.assertNotIn('podman tag ', text)
        self.assertNotIn('nixos-rebuild', text)

    def test_kvm_preflight_bypass_exists_only_in_disposable_test_node(self):
        proof = (
            ROOT / "nixos/system/tests/nixer-headless-systemd.nix"
        ).read_text()
        self.assertIn("nixer-headless-systemd-vm-proof", FLAKE.read_text())
        self.assertIn("nodes = {", proof)
        self.assertIn("missing = { ... }: { imports = [ common ]; };", proof)
        self.assertIn("systemd.services.nixer-headless.serviceConfig.ExecStartPre =", proof)
        self.assertIn('lib.mkForce "${pkgs.coreutils}/bin/true";', proof)
        self.assertIn(
            'with subtest("missing pinned OCI image denies headless Nixer start")',
            proof,
        )
        self.assertIn(
            'with subtest("original Nixer starts as headless unprivileged system MainPID")',
            proof,
        )
        self.assertIn(
            'with subtest("original nine-tool Nixer MCP initializes on localhost")',
            proof,
        )
        self.assertIn('"nixer_status"', proof)
        self.assertIn('"nixos_options"', proof)
        self.assertEqual(proof.count("--property=NoNewPrivileges"), 2)
        self.assertNotIn("systemd.user.services.nixer =", proof)

    def test_separate_nixer_candidate_cannot_change_headless_base(self):
        flake = FLAKE.read_text()
        primary = PRIMARY.read_text()
        self.assertIn(
            'nixosConfigurations.heim-pc-seagate-nixer-headless-candidate =',
            flake,
        )
        self.assertIn('nixer.nixosModules.default', flake)
        self.assertIn('./modules/nixer-headless.nix', flake)
        self.assertIn('heimPc.nixerHeadless.enable = true;', flake)
        self.assertIn('seagate-nixer-headless-contract =', flake)
        self.assertIn('assert !cfg.services.nixer.enable;', flake)
        self.assertIn('assert !(builtins.hasAttr "nixer" cfg.systemd.user.services);', flake)
        self.assertIn('assert !cfg.heimPc.grabowskiProduction.enable;', flake)
        self.assertIn('assert !cfg.boot.loader.efi.canTouchEfiVariables;', flake)
        self.assertIn('users.users.alex.linger = false;', primary)
        baseline = flake.split(
            'nixosConfigurations.heim-pc-seagate-primary-candidate =', 1
        )[1].split('nixosConfigurations.heim-pc-vm =', 1)[0]
        self.assertNotIn('nixer-headless.nix', baseline)
        self.assertNotIn('heimPc.nixerHeadless.enable = true;', baseline)


if __name__ == "__main__":
    unittest.main()
