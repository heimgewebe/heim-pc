"""Offline regression gates for the real, pinned NixOS Grabowski broker package.

These static tests complement actual isolated Nix builds and MCP protocol checks.
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
        self.assertIn("admit = cfg.enable && packagesPresent && releaseBound;", production)
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


    def test_full_operator_is_hash_locked_and_release_identity_is_shared(self):
        op = (MODULES / "grabowski-operator-package.nix").read_text()
        broker = (MODULES / "grabowski-broker-package.nix").read_text()
        prod = (MODULES / "grabowski-production.nix").read_text()
        flake = (ROOT / "nixos/system/flake.nix").read_text()
        release_id = "dd6dc690285b-srcset5c51dbd24485-lock264e747ad05a-contract2681d2593edc"
        lock_sha256 = "264e747ad05a536e9ca7639c6cba5a45636b93df0fe3153b4ae040ec14d456e3"
        self.assertIn('releaseId = "' + release_id + '";', op)
        self.assertIn('releaseId = "' + release_id + '";', broker)
        self.assertIn('lockSha256 = "' + lock_sha256 + '";', op)
        self.assertIn('lockSha256 = "' + lock_sha256 + '";', broker)
        self.assertIn('sha256-y/6EMxK7jFHXSJzI4xWre15WY4VOyeP+C33SQPjNESg=', op)
        self.assertNotIn("pkgs.lib.fakeHash", op)
        self.assertIn("--require-hashes --only-binary=:all:", op)
        self.assertIn("--no-index --no-deps --no-compile --no-input", op)
        self.assertIn("PYTHONPATH", op)
        self.assertIn("grabowski_operator --transport streamable-http", op)
        self.assertIn('--argv0 "$out/bin/grabowski-operator"', op)
        # The deployment manifest maps runtime.py to grabowski_operator and
        # the previous grabowski_operator.py to grabowski_operator_core.
        self.assertIn('contract.get("source") == "src/grabowski_runtime.py"', op)
        self.assertIn('len(expected) == 203', op)
        self.assertIn('len(supporting) != 127', op)
        self.assertIn('entries = [{"module": contract["module"], "source": contract["source"]}, *supporting]', op)
        self.assertIn('dst = site / (name + ".py")', op)
        self.assertNotIn('install -m 0644 extracted/src/*.py', op)
        self.assertIn('cfg.operatorPackage.outPath == canonicalOperator.outPath', prod)
        self.assertIn('cfg.brokerPackage.outPath == canonicalBroker.outPath', prod)
        self.assertIn('cfg.releaseId == expectedReleaseId', prod)
        self.assertIn('cfg.operatorPackage.passthru.lockSha256 == expectedLockSha256', prod)
        self.assertIn('cfg.brokerPackage.passthru.lockSha256 == expectedLockSha256', prod)
        self.assertIn("assert !(builtins.tryEval wrongOperator.system.build.toplevel.drvPath).success;", flake)
        self.assertIn("assert !(builtins.tryEval wrongBroker.system.build.toplevel.drvPath).success;", flake)
        self.assertIn("assert !(builtins.tryEval wrongRelease.system.build.toplevel.drvPath).success;", flake)
        self.assertIn("grabowski-release-artifacts =", flake)
        self.assertIn('if observed != expected:', flake)
        self.assertIn('if len(expected) != 203:', flake)
        self.assertIn('"cmdline"', flake)
        self.assertIn("test -x ${operator}/bin/grabowski-operator", flake)
        self.assertIn("test -x ${broker}/bin/grabowski-privileged-broker", flake)
        self.assertIn('builtins.match "/nix/store/[0-9a-z]{32}-unit-grabowski-operator[.]service" unitStore', flake)

    def test_nixos_broker_port_keeps_original_peer_authority_checks(self):
        broker = (MODULES / "grabowski-broker-package.nix").read_text()
        prod = (MODULES / "grabowski-production.nix").read_text()
        helper = (MODULES / "grabowski-nixos-unit-authority.py").read_text()
        self.assertIn("grabowski_nixos_unit_authority as nixos_auth", broker)
        self.assertIn("nixos_auth.fragment_trusted(", broker)
        self.assertIn("nixos_auth.expected_operator_argv()", broker)
        for original_peer_gate in (
            "systemd_main_pid != pid",
            "_socket_peer_credentials(descriptor)",
            "_validate_system_cgroup_authority(",
            "_process_cmdline(pid, proc_root=proc_root) != effective_expected_argv",
        ):
            self.assertIn(original_peer_gate, broker)
        self.assertIn("GRABOWSKI_NIXOS_OPERATOR_ENTRYPOINT=${cfg.operatorPackage}", prod)
        self.assertIn('OPERATOR_ENTRYPOINT_ENV = "GRABOWSKI_NIXOS_OPERATOR_ENTRYPOINT"', helper)
        self.assertIn('stat.S_ISLNK(link.st_mode)', helper)
        self.assertIn('fragment.resolve(strict=True)', helper)
        self.assertIn('stat.S_ISREG(meta.st_mode)', helper)
        self.assertIn('trusted_uid: int = 0', helper)
        self.assertNotIn('users.users.alex.extraGroups = lib.mkIf admit', prod)



if __name__ == "__main__":
    unittest.main()