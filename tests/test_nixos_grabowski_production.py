"""Offline regression gates for the real, pinned NixOS Grabowski broker package.

These static tests complement actual isolated Nix builds and MCP protocol checks.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "nixos" / "system" / "modules"
REVISION = "6a6360a92be11d24d85e9b002bb34ac2b07672d5"
TARBALL_HASH = "sha256-qxPpTXFUQ7m7ZCX3eGiy26rDoMyVpmjnzgSgmgKcmdk="


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
        self.assertIn('Group = "users";', production)
        self.assertIn("XDG_RUNTIME_DIR=/run/user/1000", production)
        self.assertIn("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus", production)


    def test_full_operator_is_hash_locked_and_release_identity_is_shared(self):
        op = (MODULES / "grabowski-operator-package.nix").read_text()
        broker = (MODULES / "grabowski-broker-package.nix").read_text()
        prod = (MODULES / "grabowski-production.nix").read_text()
        flake = (ROOT / "nixos/system/flake.nix").read_text()
        release_id = "6a6360a92be1-srcset8a29601ce885-lock264e747ad05a-contract8414018c4b85"
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
        self.assertIn('GRABOWSKI_NIXOS_GIT_BIN', op)
        self.assertIn('GRABOWSKI_NIXOS_GH_BIN', op)
        self.assertIn('"src/grabowski_operator.py": (4, 1)', op)
        self.assertIn('"src/grabowski_self_deploy.py": (2, 0)', op)
        self.assertIn('makeWrapper ${pkgs.git}/bin/git', op)
        self.assertIn('makeWrapper ${pkgs.gh}/bin/gh', op)
        self.assertIn("grabowski_operator --transport streamable-http", op)
        self.assertIn('--argv0 "$out/bin/grabowski-operator"', op)
        # The deployment manifest maps runtime.py to grabowski_operator and
        # the previous grabowski_operator.py to grabowski_operator_core.
        self.assertIn('contract.get("source") == "src/grabowski_runtime.py"', op)
        self.assertIn('len(expected) == 203', op)
        self.assertIn('len(supporting) != 129', op)
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

    def test_private_root_policy_is_not_a_nix_store_secret(self):
        production = (MODULES / "grabowski-production.nix").read_text()
        installer = (MODULES / "grabowski-private-policy-install.py").read_text()
        flake = (ROOT / "nixos/system/flake.nix").read_text()
        self.assertIn('systemd.services.grabowski-private-policy-install = lib.mkIf admit', production)
        self.assertIn('ExecStart = "${pkgs.python3}/bin/python3 -B ${./grabowski-private-policy-install.py}"', production)
        self.assertIn('ConfigurationDirectory = "grabowski"', production)
        self.assertIn('ConfigurationDirectoryMode = "0755"', production)
        self.assertIn('RequiresMountsFor = "/persist"', production)
        self.assertIn('AssertPathIsMountPoint = "/persist"', production)
        self.assertIn('requires = [ "grabowski-private-policy-install.service" ];', production)
        self.assertIn('wantedBy = [ "multi-user.target" ];', production)
        self.assertIn('unitConfig.DefaultDependencies = false;', production)
        self.assertIn('after = [ "basic.target" "grabowski-private-policy-install.service" ];', production)
        self.assertIn('requires = [ "grabowski-privileged-broker.socket" "grabowski-private-policy-install.service" "user@1000.service" ];', production)
        self.assertIn('SOURCE = Path("/persist/secrets/grabowski/privileged-actions.json")', installer)
        self.assertIn('DESTINATION = Path("/etc/grabowski/privileged-actions.json")', installer)
        self.assertIn('flags |= os.O_NOFOLLOW', installer)
        self.assertIn('stat.S_IMODE(before.st_mode) != 0o600', installer)
        self.assertIn('os.replace(temp_path, destination)', installer)
        self.assertNotIn("environment.etc.\"grabowski/privileged-actions.json\"", production)
        self.assertNotIn("pkgs.writeText", production)
        self.assertIn('policyUnit.unitConfig.AssertPathIsMountPoint == "/persist"', flake)

    def test_nixos_broker_port_keeps_original_peer_authority_checks(self):
        broker = (MODULES / "grabowski-broker-package.nix").read_text()
        prod = (MODULES / "grabowski-production.nix").read_text()
        helper = (MODULES / "grabowski-nixos-unit-authority.py").read_text()
        self.assertIn("grabowski_nixos_unit_authority as nixos_auth", broker)
        self.assertIn("nixos_auth.fragment_trusted(", broker)
        self.assertIn("nixos_auth.expected_operator_argv()", broker)
        self.assertIn("extracted/tools/grabowski_privileged_request.py", broker)
        self.assertIn('"$out/bin/grabowski-privileged-request"', broker)
        self.assertIn("GRABOWSKI_PRIVILEGED_BROKER=${cfg.brokerPackage}/bin/grabowski-privileged-broker", prod)
        self.assertIn('PATH=${cfg.brokerPackage}/bin:', prod)
        self.assertIn("test -x ${broker}/bin/grabowski-privileged-request", (ROOT / "nixos/system/flake.nix").read_text())
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



    def test_nixos_live_interpreter_identity_is_kernel_bound_and_wrapper_pinned(self):
        identity = (MODULES / "grabowski-nixos-integrity.py").read_text()
        flake = (ROOT / "nixos/system/flake.nix").read_text()
        package = (MODULES / "grabowski-operator-package.nix").read_text()

        # The operator uses exec -a for the broker MainPID/cmdline check.
        # CPython reflects argv[0] in sys.executable, so the kernel's
        # real /proc/self/exe must be checked independently.
        self.assertIn('Path("/proc/self/exe").resolve(strict=True)', identity)
        self.assertIn('argv0_bin in (python_bin, wrapper_bin)', identity)
        self.assertIn('Path(module_path).resolve() == root / REQUIRED_MODULE', identity)
        self.assertIn('--argv0 "$out/bin/grabowski-operator"', package)
        self.assertIn('exec -a "$1" "$2" -B -c "$3" "$4" "$5"', flake)
        # The Nix build sandbox remaps root-owned store inputs to uid 65534:
        # verify executable identity there, and leave the root-ownership
        # positive/negative check to the unchanged production validator.
        self.assertIn('if observed_argv0 != expected_argv0:', flake)
        self.assertIn('Nix kernel Python and distinct operator/forged argv0 identities verified', flake)
        self.assertIn('Nix sandbox full source/lock/module/asset manifest verified', flake)



    def test_native_restic_lock_mount_writable_in_operator_sandbox(self):
        prod = (MODULES / "grabowski-production.nix").read_text()
        flake = (ROOT / "nixos/system/flake.nix").read_text()
        marker = "systemd.services.grabowski-operator = lib.mkIf admit {"
        self.assertEqual(prod.count(marker), 1)
        operator = prod.split(marker, 1)[1]
        self.assertIn('ProtectSystem = "strict";', operator)
        self.assertIn('NoNewPrivileges = false;', operator)
        self.assertIn('"-/var/lib/heim-pc-backup"', operator)
        self.assertIn(
            'builtins.elem "-/var/lib/heim-pc-backup" operator.ReadWritePaths;',
            flake,
        )

    def test_nix_fetcher_cache_writable_in_operator_sandbox(self):
        prod = (MODULES / "grabowski-production.nix").read_text()
        flake = (ROOT / "nixos/system/flake.nix").read_text()
        operator = prod.split("systemd.services.grabowski-operator = lib.mkIf admit {", 1)[1]
        self.assertIn('ProtectSystem = "strict";', operator)
        self.assertIn('ProtectHome = "read-only";', operator)
        self.assertIn('"-/home/alex/.cache/nix"', operator)
        self.assertIn(
            'builtins.elem "-/home/alex/.cache/nix" operator.ReadWritePaths;',
            flake,
        )


    def test_nix_cache_coldstart_tmpfiles_provisions_absent_directories(self):
        prod = (MODULES / "grabowski-production.nix").read_text()
        rule_block = prod.split("systemd.tmpfiles.rules = lib.optionals admit [", 1)[1].split("];", 1)[0]
        expected = (
            "d /home/alex/.cache 0755 alex users -",
            "d /home/alex/.cache/nix 0755 alex users -",
        )
        for rule in expected:
            self.assertIn(f'"{rule}"', rule_block)
        self.assertLess(rule_block.index(expected[0]), rule_block.index(expected[1]))

        tmpfiles = shutil.which("systemd-tmpfiles")
        if tmpfiles is None:
            self.skipTest("systemd-tmpfiles is not installed on this test host")
        with tempfile.TemporaryDirectory(prefix="grabowski-cache-coldstart-") as tmp:
            scratch = Path(tmp)
            root = scratch / "root"
            (root / "etc").mkdir(parents=True)
            # --root resolves users/groups inside this isolated synthetic fixture;
            # never mutate the real cache, passwd, group, or running service.
            uid, gid = os.getuid(), os.getgid()
            (root / "etc/passwd").write_text(
                f"root:x:0:0:root:/root:/bin/sh\nalex:x:{uid}:{gid}:alex:/home/alex:/bin/sh\n"
            )
            (root / "etc/group").write_text(
                f"root:x:0:\nusers:x:{gid}:alex\n"
            )
            config = scratch / "cache-tmpfiles.conf"
            config.write_text("\n".join(expected) + "\n")
            directories = (
                root / "home/alex/.cache",
                root / "home/alex/.cache/nix",
            )
            self.assertTrue(all(not directory.exists() for directory in directories))
            argv = [tmpfiles, "--root=" + str(root), "--create", str(config)]
            for _ in range(2):
                completed = subprocess.run(
                    argv, capture_output=True, text=True, timeout=30, check=False
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                for directory in directories:
                    self.assertTrue(directory.is_dir(), str(directory))
                    stats = directory.stat()
                    self.assertEqual((stats.st_uid, stats.st_gid), (uid, gid))
                    self.assertEqual(stats.st_mode & 0o777, 0o755)


class GrabowskiNixEntrypointMetadataRegression(unittest.TestCase):
    """Exercise the real adapter's metadata producer, not source-text anchors."""

    def test_verified_entrypoint_contract_is_exposed_and_mismatch_is_rejected(self):
        import hashlib
        import importlib.util
        import json
        import platform
        import sys
        import tempfile
        from types import SimpleNamespace
        from unittest.mock import patch

        spec = importlib.util.spec_from_file_location(
            "grabowski_nixos_integrity_under_test",
            MODULES / "grabowski-nixos-integrity.py",
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        adapter = importlib.util.module_from_spec(spec)
        with patch.object(sys, "dont_write_bytecode", True):
            spec.loader.exec_module(adapter)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module_relative = adapter.REQUIRED_MODULE
            module_path = root / module_relative
            module_path.parent.mkdir(parents=True)
            module_bytes = b"synthetic immutable module bytes"
            module_path.write_bytes(module_bytes)
            wrapper = root / "bin/grabowski-operator"
            wrapper.parent.mkdir(parents=True)
            wrapper.write_bytes(b"synthetic wrapper")
            contract_bytes = b'{"kind":"synthetic pinned entrypoint contract"}'
            contract = json.loads(contract_bytes)
            digest = hashlib.sha256(contract_bytes).hexdigest()
            pinned_lock = b"synthetic pinned lock"
            agent_sha = "a" * 64
            release_bytes = json.dumps({
                "release_id": adapter.PINNED_RELEASE,
                "source_revision": adapter.PINNED_REVISION,
                "runtime_lock_sha256": adapter.PINNED_LOCK_SHA256,
                "entrypoint": "bin/grabowski-operator",
            }).encode()
            doc = {
                "schema_version": 1,
                "kind": "grabowski-nixos-immutable-runtime-integrity",
                "release_id": adapter.PINNED_RELEASE,
                "repo_head": adapter.PINNED_REVISION,
                "runtime_lock_sha256": adapter.PINNED_LOCK_SHA256,
                "entrypoint_contract_sha256": digest,
                "entrypoint_contract": contract,
                "module_sha256s": {"grabowski_mcp": hashlib.sha256(module_bytes).hexdigest()},
                "runtime_asset_sha256s": {},
                "agent_instructions_sha256": agent_sha,
                "python_executable": str(Path("/proc/self/exe").resolve(strict=True)),
                "python_version": platform.python_version(),
                "python_implementation": platform.python_implementation(),
            }
            for matches in (True, False):
                with self.subTest(contract_matches=matches):
                    current_doc = dict(doc)
                    if not matches:
                        current_doc["entrypoint_contract_sha256"] = "0" * 64
                    files = {
                        adapter.MANIFEST_RELATIVE: json.dumps(current_doc).encode(),
                        adapter.CONTRACT_RELATIVE: contract_bytes,
                        adapter.LOCK_RELATIVE: pinned_lock,
                        adapter.RELEASE_RELATIVE: release_bytes,
                        module_relative: module_bytes,
                    }

                    def fixture_hash(payload):
                        if payload == pinned_lock:
                            return adapter.PINNED_LOCK_SHA256
                        return hashlib.sha256(payload).hexdigest()

                    with (
                        patch.object(adapter, "store_root", return_value=root),
                        patch.object(adapter, "_read", side_effect=lambda _root, path, **_kw: files[path]),
                        patch.object(adapter, "_sha", side_effect=fixture_hash),
                        patch.object(adapter, "_contract_entries", return_value=({"grabowski_mcp": module_relative}, {})),
                        patch.object(adapter.importlib.util, "find_spec", return_value=SimpleNamespace(origin=str(module_path))),
                    ):
                        result = adapter.deployment_metadata(
                            module_path, expected_agent_sha256=agent_sha
                        )
                    if matches:
                        self.assertEqual(result["completion_status"], "complete")
                        self.assertTrue(result["provenance_valid"])
                        self.assertEqual(result["entrypoint_contract_sha256"], digest)
                        self.assertIs(result["entrypoint_contract_identity_valid"], True)

                        # In the installed pinned Nix runtime, run the unchanged
                        # durable-result consumer rather than duplicating its gate.
                        # Source-only CI lacks this separately built runtime.
                        try:
                            import grabowski_mcp as pinned_consumer
                        except ImportError:
                            pinned_consumer = None
                        if pinned_consumer is not None:
                            serving = {
                                "matches_deployed_manifest": True,
                                "process_release_id": adapter.PINNED_RELEASE,
                                "process_repo_head": adapter.PINNED_REVISION,
                            }
                            with (
                                patch.object(pinned_consumer, "_deployment_metadata", return_value=result),
                                patch.object(pinned_consumer.grabowski_serving_process, "identity", return_value=serving),
                            ):
                                binding, blocker = pinned_consumer._grip_result_readback_runtime_preflight()
                            self.assertIsNone(blocker)
                            self.assertEqual(binding["entrypoint_contract_sha256"], digest)
                    else:
                        self.assertEqual(result["completion_status"], "incomplete")
                        self.assertIs(result["entrypoint_contract_identity_valid"], False)
                        self.assertIsNone(result["entrypoint_contract_sha256"])

if __name__ == "__main__":
    unittest.main()