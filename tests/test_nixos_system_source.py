from pathlib import Path
import hashlib
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "nixos" / "system"
SOURCE_SNAPSHOT_SHA256 = "525047db02763b2d12e6e1ab3cccf1dc70cd93114508f1d2ce0200d801e17528"
ROOT_LOCK_SHA256 = "19d83aededafff8a80ca354e4fba18c1470d638b683079bd983639eb5719e26d"


class T(unittest.TestCase):
    def test_root_flake_is_thin_adapter(self):
        root_flake = (ROOT / "flake.nix").read_text()
        nested = (SOURCE / "flake.nix").read_text()
        self.assertTrue(root_flake.startswith("{\n"))
        # Static drift guard only; the Nix CI lane proves actual evaluation.
        metadata = r'description = "[^"\n]+";'
        inputs = r"  inputs = \{.*?\n  \};"
        self.assertEqual(re.search(metadata, root_flake).group(), re.search(metadata, nested).group())
        self.assertEqual(re.search(inputs, root_flake, re.S).group(), re.search(inputs, nested, re.S).group())
        self.assertIn("outputs = inputs@{ self, nixpkgs, microvm }:", root_flake)
        self.assertIn("(import ./nixos/system/flake.nix).outputs inputs", root_flake)
        self.assertNotIn("(import ./nixos/system/flake.nix).description", root_flake)
        self.assertNotIn("(import ./nixos/system/flake.nix).inputs", root_flake)

    def test_nix_workflow_binds_exact_source_without_lock_update(self):
        workflow = (ROOT / ".github/workflows/heim-pc-nix.yml").read_text()
        self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_SOURCE_REVISION"', workflow)
        self.assertIn("nix flake check --no-build --no-update-lock-file", workflow)
        self.assertIn(".#checks.x86_64-linux.profile-contract", workflow)

    def test_root_lock_is_bound(self):
        self.assertEqual(hashlib.sha256((ROOT / "flake.lock").read_bytes()).hexdigest(), ROOT_LOCK_SHA256)

    def test_current_nixos_source_snapshot_is_bound(self):
        digest = hashlib.sha256()
        files = sorted(path for path in SOURCE.rglob("*") if path.is_file())
        for path in files:
            relative = str(path.relative_to(SOURCE)).encode()
            digest.update(relative + b"\0" + path.read_bytes() + b"\0")
        self.assertEqual(len(files), 21)
        self.assertEqual(digest.hexdigest(), SOURCE_SNAPSHOT_SHA256)

    def test_canonical_source_layout(self):
        for relative in (
            "flake.nix", "README.md", "hosts/heim-pc/default.nix",
            "modules/audio.nix", "modules/backup.nix", "modules/bureau.nix",
            "modules/containers.nix", "modules/desktop.nix", "modules/development.nix",
            "modules/grabowski.nix", "modules/live-media.nix", "modules/networking.nix",
            "modules/nvidia.nix", "modules/observability.nix", "modules/physical-gates.nix",
            "modules/storage-layout.nix",
            "tests/integration.nix", "tests/trust-zones.nix", "tests/vsock-broker.nix",
            "zones/agent.nix",
        ):
            self.assertTrue((SOURCE / relative).is_file(), relative)

    def test_managed_root_entrypoint_exists(self):
        flake = (SOURCE / "flake.nix").read_text()
        host = (SOURCE / "hosts/heim-pc/default.nix").read_text()
        self.assertIn("nixosConfigurations.heim-pc", flake)
        self.assertIn("system.configurationRevision = sourceRevision", host)
        self.assertIn("NIXOS_PROTOTYPE_DO_NOT_INSTALL", host)
        self.assertIn("boot.loader.efi.canTouchEfiVariables = false", host)

    def test_storage_target_build_is_contract_derived_and_separate_from_prototype(self):
        flake = (SOURCE / "flake.nix").read_text()
        host = (SOURCE / "hosts/heim-pc/default.nix").read_text()
        layout = (SOURCE / "modules/storage-layout.nix").read_text()
        deployment = (ROOT / "nixos" / "deployment" / "contract-v1.json").read_text()
        self.assertIn("nixosConfigurations.heim-pc-storage-target", flake)
        self.assertIn("./modules/storage-layout.nix", flake)
        self.assertIn("../../rehearsal/contract-v1.json", layout)
        self.assertIn("boot.initrd.luks.devices.${mapperName}", layout)
        self.assertIn("fileSystems = lib.mkForce", layout)
        self.assertIn(
            ".#nixosConfigurations.heim-pc-storage-target.config.system.build.toplevel",
            deployment,
        )
        self.assertIn("NIXOS_PROTOTYPE_DO_NOT_INSTALL", host)

    def test_live_media_excludes_boot_and_heavy_model_gates(self):
        live = (SOURCE / "modules/live-media.nix").read_text()
        gates = (SOURCE / "modules/physical-gates.nix").read_text()
        self.assertIn("bootReadiness = false", live)
        self.assertIn("modelRuntime = false", live)
        self.assertIn('"networkmanager"', live)
        self.assertIn('fail "persistent-disk-mount-inventory"', live)
        self.assertIn("findmnt --json --list -o TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN", live)
        self.assertIn("lsblk --json --list --paths", live)
        self.assertIn("${./live-block-inventory.jq}", live)
        self.assertNotIn("done < <(lsblk", live)
        self.assertIn('fail "raw-block-device-inventory"; exit 1;', live)
        self.assertIn("lib.optional cfg.bootReadiness gateDReport", gates)
        self.assertIn("lib.optional cfg.modelRuntime llamaCuda", gates)
        self.assertIn("services.ollama = lib.mkIf cfg.modelRuntime", gates)
        self.assertNotIn("mesa-demos", live)

    def test_declarative_nixos_system_source_remains_non_destructive(self):
        content = "\n".join(
            path.read_text() for path in SOURCE.rglob("*")
            if path.is_file() and path.suffix in {".nix", ".sh", ".py"}
        )
        for marker in ("/dev/nvme0", "parted ", "mkfs.", "nixos-install", "efibootmgr"):
            self.assertNotIn(marker, content)

    def test_gate_a_uses_pinned_nvidia_binary_and_exact_pinned_cdi_contract(self):
        gate = (SOURCE / "modules/physical-gates.nix").read_text()
        self.assertIn("lib.getExe' config.hardware.nvidia.package \"nvidia-smi\"", gate)
        self.assertIn("/run/cdi/nvidia-container-toolkit.json", gate)
        self.assertNotIn("/etc/cdi/nvidia-container-toolkit.json", gate)
        self.assertIn('any(.devices[]?; .name == "all")', gate)
        self.assertNotIn('.devices[]?.name == "all"', gate)
        self.assertNotIn('gpu_info="$(nvidia-smi ', gate)
        self.assertIn("c5c4a43b0e8056328ec4529f735cabdb8f1942bb", gate)
        self.assertIn("for _attempt in $(seq 1 90)", gate)
        self.assertIn("systemctl is-failed --quiet nvidia-container-toolkit-cdi-generator.service", gate)
        self.assertNotIn("mesa-demos", gate)

    def test_integration_test_is_scoped_to_grabowski_and_bureau(self):
        integration = (SOURCE / "tests/integration.nix").read_text()
        self.assertIn("../modules/grabowski.nix", integration)
        self.assertIn("../modules/bureau.nix", integration)
        for unrelated in (
            "../modules/audio.nix",
            "../modules/development.nix",
            "../modules/containers.nix",
            "../modules/networking.nix",
            "../modules/backup.nix",
            "../modules/observability.nix",
        ):
            self.assertNotIn(unrelated, integration)
        self.assertIn("virtualisation.memorySize = 1024", integration)
        self.assertIn("virtualisation.cores = 1", integration)

    def test_readme_separates_current_snapshot_from_historical_runtime_evidence(self):
        readme = (SOURCE / "README.md").read_text()
        self.assertIn("## Current snapshot evidence status", readme)
        self.assertIn("not re-established Nix/QEMU/KVM execution evidence", readme)
        self.assertIn("## Historical evidence from earlier revisions", readme)
        self.assertIn("../../tests/test_nixos_system_source.py", readme)
        self.assertNotIn("../../tests/test_nixos_heim_pc_prototype.py", readme)

    def test_grabowski_operator_readback_is_nonsecret_and_user_readable(self):
        module = (SOURCE / "modules/grabowski.nix").read_text()
        integration = (SOURCE / "tests/integration.nix").read_text()
        self.assertIn('RuntimeDirectoryMode = "0755"', module)
        self.assertIn('chmod 0644 "$RUNTIME_DIRECTORY/readback.json"', module)
        self.assertIn("jq -cn", module)
        self.assertIn("su -s /bin/sh -c 'grabowski-demo-operator status' alex", integration)

    def test_nix_and_python_provenance_contracts_both_require_40_hex(self):
        flake = (SOURCE / "flake.nix").read_text()
        managed = (ROOT / "scripts/managed_nix.py").read_text()
        self.assertIn("^[0-9a-f]{40}$", flake)
        self.assertIn("len(value) != 40", managed)
        self.assertNotIn("len(value) not in {40, 64}", managed)


if __name__ == "__main__":
    unittest.main()
