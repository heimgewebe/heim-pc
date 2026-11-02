from pathlib import Path
import fcntl
import hashlib
import json
import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "nixos" / "system"
SOURCE_SNAPSHOT_SHA256 = "5b7ba44ba1eec48fc441831358207cf7eae60fd34a5932dcbf6e6d6a03a8a0ca"
ROOT_LOCK_SHA256 = "419e0c20ee1d118560a0171929be7fbf3a446bd9b52eda9581cad00942dc303d"
TEST_SOURCE_REVISION = "a" * 40


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
        self.assertIn("outputs = inputs@{ self, nixpkgs, microvm, nixer }:", root_flake)
        self.assertIn("(import ./nixos/system/flake.nix).outputs inputs", root_flake)
        self.assertNotIn("(import ./nixos/system/flake.nix).description", root_flake)
        self.assertNotIn("(import ./nixos/system/flake.nix).inputs", root_flake)
        self.assertIn(
            'nixer.url = "github:heimgewebe/nixer/c252b62b0fcd0bd5442681bb68d809a4b5984c61";',
            nested,
        )

    def test_nixer_nar_contract_binds_both_root_and_system_locks(self):
        # The reviewed source NAR is a separate, immutable trust decision.
        # Equality of two mutable lockfiles alone is not that decision.
        trust = json.loads((ROOT / "nixos/production/trust-contract-v1.json").read_text())
        root_lock = json.loads((ROOT / "flake.lock").read_text())
        system_lock = json.loads((SOURCE / "flake.lock").read_text())
        pin = trust["inputs"]["nixer"]
        nar = "sha256-aaDoiW4Eg/0/kE+I3qGUzFzwnH/7DRMStC8h5FcUSDE="
        rev = "c252b62b0fcd0bd5442681bb68d809a4b5984c61"
        self.assertEqual(pin["required_nar_hash"], nar)
        self.assertEqual(pin["required_revision"], rev)
        self.assertRegex(nar, r"^sha256-[A-Za-z0-9+/]{43}=$")

        flake = (SOURCE / "flake.nix").read_text()
        for assertion in (
            "systemLock = builtins.fromJSON (builtins.readFile ./flake.lock);",
            "systemRootNode.inputs.nixer == contract.inputs.nixer.lock_node;",
            "nixerNode.locked.rev == contract.inputs.nixer.required_revision;",
            "nixerNode.locked.narHash == contract.inputs.nixer.required_nar_hash;",
            "systemNixerNode.locked.rev == contract.inputs.nixer.required_revision;",
            "systemNixerNode.locked.narHash == contract.inputs.nixer.required_nar_hash;",
        ):
            self.assertIn(assertion, flake)

        def bound(contract, root, system):
            nixer = contract["inputs"]["nixer"]
            name = nixer["lock_node"]
            return all((
                root["nodes"][root["root"]]["inputs"]["nixer"] == name,
                system["nodes"][system["root"]]["inputs"]["nixer"] == name,
                root["nodes"][name]["locked"]["rev"] == nixer["required_revision"],
                root["nodes"][name]["locked"]["narHash"] == nixer["required_nar_hash"],
                system["nodes"][name]["locked"]["rev"] == nixer["required_revision"],
                system["nodes"][name]["locked"]["narHash"] == nixer["required_nar_hash"],
            ))
        self.assertTrue(bound(trust, root_lock, system_lock))

        for attack in (
            "contract_nar", "root_nar", "system_nar",
            "root_rev", "system_rev", "root_edge", "system_edge",
        ):
            altered_trust = json.loads(json.dumps(trust))
            altered_root = json.loads(json.dumps(root_lock))
            altered_system = json.loads(json.dumps(system_lock))
            name = pin["lock_node"]
            if attack == "contract_nar":
                altered_trust["inputs"]["nixer"]["required_nar_hash"] = "sha256-" + "A" * 43 + "="
            elif attack == "root_nar":
                altered_root["nodes"][name]["locked"]["narHash"] = "sha256-" + "A" * 43 + "="
            elif attack == "system_nar":
                altered_system["nodes"][name]["locked"]["narHash"] = "sha256-" + "A" * 43 + "="
            elif attack == "root_rev":
                altered_root["nodes"][name]["locked"]["rev"] = "0" * 40
            elif attack == "system_rev":
                altered_system["nodes"][name]["locked"]["rev"] = "0" * 40
            elif attack == "root_edge":
                altered_root["nodes"][altered_root["root"]]["inputs"]["nixer"] = "microvm"
            else:
                altered_system["nodes"][altered_system["root"]]["inputs"]["nixer"] = "microvm"
            with self.subTest(attack=attack):
                self.assertFalse(bound(altered_trust, altered_root, altered_system))

    def test_nixer_image_preparation_has_bounded_network_retry(self):
        module = (SOURCE / "modules/nixer.nix").read_text()
        self.assertIn("runtimeInputs = [ pkgs.coreutils pkgs.podman ];", module)
        self.assertIn("max_attempts=6", module)
        self.assertIn("while ! podman pull", module)
        self.assertIn("delay=$((attempt * 5))", module)
        self.assertIn('sleep "$delay"', module)
        self.assertNotIn('after = [ "network-online.target" ];', module)
        self.assertNotIn('wants = [ "network-online.target" ];', module)
        self.assertIn("wants = lib.mkForce [ ];", module)
        self.assertIn('after = lib.mkForce [ "nixer-image.service" ];', module)

    def test_nix_workflow_binds_exact_source_without_lock_update(self):
        workflow = (ROOT / ".github/workflows/heim-pc-nix.yml").read_text()
        self.assertNotIn("\n    paths:\n", workflow)
        self.assertIn("jobs:\n  detect:", workflow)
        self.assertIn("fetch-depth: 0", workflow)
        self.assertIn(
            "BASE_SOURCE_REVISION: ${{ github.event.pull_request.base.sha || github.event.before }}",
            workflow,
        )
        self.assertIn("Detect Nix CI control-plane changes independently", workflow)
        self.assertIn(
            "control_changed: ${{ steps.control.outputs.control_changed }}",
            workflow,
        )
        self.assertIn(
            ".github/workflows/heim-pc-nix.yml scripts/ci/nix_changed.py",
            workflow,
        )
        self.assertIn(
            "if: steps.control.outputs.control_changed == 'false'",
            workflow,
        )
        self.assertIn(
            'git show "${BASE_SOURCE_REVISION}:scripts/ci/nix_changed.py"',
            workflow,
        )
        self.assertIn('python3 "$detector"', workflow)
        self.assertIn("Validate detector outputs", workflow)
        self.assertIn(
            "CONTROL_CHANGED: ${{ steps.control.outputs.control_changed }}",
            workflow,
        )
        self.assertIn(
            "NIX_CHANGED: ${{ steps.changes.outputs.nix_changed }}",
            workflow,
        )
        self.assertIn('case "$CONTROL_CHANGED" in', workflow)
        self.assertIn('case "$NIX_CHANGED" in', workflow)
        self.assertIn("true|false) ;;", workflow)
        self.assertIn("needs: detect", workflow)
        self.assertIn("needs.detect.result != 'success'", workflow)
        self.assertIn(
            "needs.detect.outputs.control_changed != 'false'",
            workflow,
        )
        self.assertIn(
            "needs.detect.outputs.nix_changed != 'false'",
            workflow,
        )
        self.assertNotIn("if: needs.detect.outputs.nix_changed == 'true'", workflow)
        self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_SOURCE_REVISION"', workflow)
        self.assertIn("nix flake check --no-build --no-update-lock-file", workflow)
        self.assertIn(".#checks.x86_64-linux.profile-contract", workflow)
        self.assertIn(".#checks.x86_64-linux.supply-chain-trust", workflow)
        self.assertIn(".#checks.x86_64-linux.nix-lifecycle-contract", workflow)
        self.assertIn(".#checks.x86_64-linux.recovery-readiness-contract", workflow)
        self.assertIn(".#checks.x86_64-linux.intentional-break-rejected", workflow)
        self.assertIn(".#checks.x86_64-linux.agent-zone-contract", workflow)
        self.assertIn(".#packages.x86_64-linux.physical-gate-proprietary-system", workflow)
        self.assertIn(".#packages.x86_64-linux.physical-gate-open-system", workflow)
        self.assertIn(".#packages.x86_64-linux.physical-gate-live-proprietary-iso", workflow)
        self.assertIn(".#packages.x86_64-linux.physical-gate-live-open-iso", workflow)
        self.assertIn(".#packages.x86_64-linux.physical-gate-live-inventory-iso", workflow)
        self.assertIn(".#packages.x86_64-linux.agent-vsock-proof-microvm", workflow)
        self.assertIn(".#checks.x86_64-linux.firstboot-credentials", workflow)

    def test_firstboot_vm_proof_is_exact_source_headless_and_input_free(self):
        flake = (SOURCE / "flake.nix").read_text()
        proof = (SOURCE / "tests/firstboot-credentials.nix").read_text()
        self.assertIn("inherit pkgs sourceRevision;", flake)
        self.assertNotIn("eb260b0b82199e380d881b2436e403dcda64ca32", flake)
        self.assertIn("expectedHostSha256", proof)
        self.assertIn("expectedHelperSha256", proof)
        self.assertIn('${pkgs.shadow}/bin/chpasswd "$@"', proof)
        self.assertIn('systemctl is-failed heim-pc-firstboot-credentials.service', proof)
        self.assertIn('.alex-password-initialized.pending', proof)
        self.assertIn('heim-pc-test-chpasswd-count', proof)
        self.assertIn('machine.start(allow_reboot=True)', proof)
        self.assertNotIn('machine.start()', proof)
        self.assertIn('interrupted.start()', proof)
        self.assertNotIn('start_all()', proof)
        self.assertIn('virtualisation.memorySize = 3072;', proof)
        self.assertIn('services.xserver.enable = lib.mkForce false;', proof)
        self.assertIn('services.displayManager.sddm.enable = lib.mkForce false;', proof)
        self.assertIn('services.displayManager.sddm.wayland.enable = lib.mkForce false;', proof)
        self.assertIn('services.desktopManager.plasma6.enable = lib.mkForce false;', proof)
        self.assertIn('pkgs.coreutils', proof)
        self.assertIn('pkgs.getent', proof)
        state_machine_subtests = (
            "missing bootstrap staging fails closed before user sessions",
            "invalid authority fails closed without mutating shadow",
            "real chpasswd bootstrap publishes durable marker and consumes staging",
            "later password rotation survives reboot and bootstrap does not replay",
            "late interrupted publication is recovery-required and recoverable under lock",
            "real post-mutation child timeout leaves pending and never replays",
        )
        self.assertEqual(proof.count('with subtest("'), len(state_machine_subtests))
        for name in state_machine_subtests:
            self.assertIn(f'with subtest("{name}"):', proof)
        self.assertIn('machine.fail("systemctl is-active systemd-user-sessions.service")', proof)
        self.assertIn('heim-pc-firstboot-test-stage invalid-authority', proof)
        self.assertIn('assert shadow_field(machine) in ("!", "!!", "*")', proof)
        self.assertIn('assert bootstrap_hash.startswith("$y$j9T$")', proof)
        self.assertGreaterEqual(
            proof.count('test -f /persist/heim-pc/bootstrap/alex-password-initialized'),
            3,
        )
        self.assertGreaterEqual(
            proof.count('test ! -e /persist/secrets/heim-pc/first-boot/alex-password-hash'),
            2,
        )
        self.assertGreaterEqual(
            proof.count('test ! -e /persist/secrets/heim-pc/first-boot/alex-password-bootstrap-authority'),
            2,
        )
        self.assertEqual(proof.count('machine.reboot()'), 2)
        self.assertIn('assert rotated_hash != bootstrap_hash', proof)
        self.assertIn('assert shadow_field(machine) == rotated_hash', proof)
        self.assertIn('ln /persist/heim-pc/bootstrap/alex-password-initialized', proof)
        self.assertIn('exec 9>/persist/heim-pc/bootstrap/.alex-password-bootstrap.lock; flock -n 9;', proof)
        self.assertIn('assert recovery_hash != rotated_hash', proof)
        self.assertIn('assert shadow_field(machine) == recovery_hash', proof)
        self.assertIn('interrupted.fail("systemctl start heim-pc-firstboot-credentials.service", timeout=30)', proof)
        self.assertIn('interrupted.fail("systemctl start heim-pc-firstboot-credentials.service", timeout=10)', proof)
        self.assertGreaterEqual(proof.count('test $(cat /run/heim-pc-test-chpasswd-count) -eq 1'), 2)
        self.assertIn('assert shadow_field(interrupted) == interrupted_hash', proof)
        forbidden = (
            "qmp",
            "input-send-event",
            ".send_key(",
            ".send_chars(",
            "graphical_login",
            "select_alex_user",
            "wait_for_alex_wayland",
            "Message received from greeter: Login",
            "journalctl",
            "loginctl",
            "node.sleep(",
            "enableOCR",
            "node.wait_for_text(",
            "ocr",
            "screenshot",
            "ydotool",
            "display-manager.service",
            "virtualisation.resolution",
            "virtualisation.qemu.options",
            "hardware.graphics.enable",
            "services.displayManager.sddm.wayland.compositor",
        )
        for marker in forbidden:
            with self.subTest(forbidden=marker):
                self.assertNotIn(marker.lower(), proof.lower())
        self.assertNotIn('environment.systemPackages = lib.mkForce', proof)
        test_script_source = proof.split("  testScript = ''\n", 1)[1].rsplit("  '';\n}", 1)[0]
        self.assertTrue(all(not line.strip() or line.startswith("    ") for line in test_script_source.splitlines()))
        compile(textwrap.dedent(test_script_source), "firstboot-testScript", "exec")
        self.assertNotIn("WAYLAND_DEBUG", proof)

    def test_desktop_disables_automatic_sleep_without_blocking_manual_suspend(self):
        desktop = (SOURCE / "modules/desktop.nix").read_text()
        flake = (SOURCE / "flake.nix").read_text()
        self.assertIn('services.logind.settings.Login.IdleAction = "ignore";', desktop)
        self.assertIn('environment.etc."xdg/powerdevilrc".text', desktop)
        self.assertEqual(desktop.count("AutoSuspendAction[$i]=0"), 3)
        self.assertNotIn("systemd.sleep.settings.Sleep =", desktop)
        for key in ("AllowSuspend", "AllowHibernation", "AllowSuspendThenHibernate", "AllowHybridSleep"):
            self.assertNotIn(f'{key} = "no";', desktop)
            self.assertIn(f'!(c.systemd.sleep.settings.Sleep ? {key})', flake)
        self.assertIn('c.services.logind.settings.Login.IdleAction == "ignore"', flake)

    def test_root_lock_is_bound(self):
        root_lock = (ROOT / "flake.lock").read_bytes()
        system_lock = (SOURCE / "flake.lock").read_bytes()
        self.assertEqual(hashlib.sha256(root_lock).hexdigest(), ROOT_LOCK_SHA256)
        root_nodes = json.loads(root_lock)["nodes"]
        system_nodes = json.loads(system_lock)["nodes"]
        root_nixpkgs = root_nodes["root"]["inputs"]["nixpkgs"]
        system_nixpkgs = system_nodes["root"]["inputs"]["nixpkgs"]
        self.assertEqual(root_nodes[root_nixpkgs]["locked"], system_nodes[system_nixpkgs]["locked"])

    def test_limine_secure_boot_proof_is_options_only_and_not_activatable(self):
        flake = (SOURCE / "flake.nix").read_text(encoding="utf-8")
        self.assertIn("limine-secureboot-module-options-eval =", flake)
        self.assertNotIn("limine-storage-target-proof =", flake)
        self.assertIn("cfg.boot.initrd.luks.devices == {}", flake)
        self.assertIn('nixpkgs.lib.hasPrefix "rd.luks." param', flake)
        self.assertIn("boot.loader.systemd-boot.enable = lib.mkForce false", flake)
        self.assertNotIn("nixosConfigurations.heim-pc-storage-limine-proof =", flake)
        self.assertIn('pkgs.runCommand "heim-pc-limine-module-options-only"', flake)

    def test_limine_synthetic_luks_cmdline_stays_private_and_non_admitting(self):
        flake = (SOURCE / "flake.nix").read_text(encoding="utf-8")
        production = json.loads(
            (ROOT / "nixos" / "production" / "contract-v1.json").read_text(encoding="utf-8")
        )
        self.assertIn("limineSyntheticLuksArgsProof = nixpkgs.lib.nixosSystem", flake)
        self.assertIn("limine-synthetic-luks-cmdline-eval =", flake)
        self.assertIn(
            "rd.luks.name=11111111-2222-4333-8444-555555555555=heimpc-nixos-crypt",
            flake,
        )
        self.assertIn(
            "rd.luks.options=11111111-2222-4333-8444-555555555555=tpm2-device=auto,headless=yes",
            flake,
        )
        self.assertNotIn("nixosConfigurations.heim-pc-storage-limine-luks-proof =", flake)
        self.assertNotIn("limine-synthetic-luks-cmdline-proof =", flake)
        self.assertIn(
            'assert (builtins.filter (arg: nixpkgs.lib.hasPrefix "rd.luks." arg)',
            flake,
        )
        self.assertIn("assert !cfg.boot.loader.efi.canTouchEfiVariables;", flake)
        self.assertIn("assert cfg.boot.loader.limine.enrollConfig;", flake)
        self.assertEqual(
            production["boot"]["authenticated_boot"]["signed_target_bootchain_state"],
            "unproven",
        )
        self.assertEqual(
            production["boot"]["authenticated_boot"]["status"],
            "blocked-until-reviewed-signed-chain",
        )

    def test_trust_zones_vm_broker_reachability_is_bounded_and_fail_closed(self):
        proof = (SOURCE / "tests/trust-zones.nix").read_text()
        self.assertIn('control.wait_for_unit("grabowski-broker-boundary.service")', proof)
        self.assertIn('control.wait_for_open_port(18444)', proof)
        # The control-VM listener does not prove that the agent network is ready.
        self.assertIn(
            'agent.wait_until_succeeds("curl --fail --silent --max-time 3 http://control:18444/ | grep -xq broker-ok", timeout=30)',
            proof,
        )
        self.assertNotIn(
            'agent.succeed("curl --fail --silent --max-time 3 http://control:18444/',
            proof,
        )
        # Keep negative cross-zone reachability and secret-exposure assertions.
        self.assertIn(
            'agent.fail("curl --fail --silent --max-time 2 http://control:22/")',
            proof,
        )
        self.assertIn('agent.fail("test -e /etc/control-plane-secret")', proof)
        self.assertIn(
            'control.succeed("test $(systemctl show grabowski-broker-boundary.service -p NoNewPrivileges --value) = yes")',
            proof,
        )

    def test_stage0_no_usb_is_nonproductive_and_isolated(self):
        flake = (SOURCE / "flake.nix").read_text()
        stage0 = (SOURCE / "modules/stage0-no-usb.nix").read_text()
        self.assertIn("nixosConfigurations.heim-pc-stage0", flake)
        self.assertIn("stage0-no-usb-contract", flake)
        self.assertIn("heim-pc-stage0-system", flake)
        self.assertIn('rootDevice = "/dev/disk/by-label/NIXOS_STAGE0_ROOT";', stage0)
        self.assertIn('device = "/dev/disk/by-label/NIXOS2_EFI";', stage0)
        self.assertIn("boot.loader.efi.canTouchEfiVariables = false;", stage0)
        self.assertIn("services.openssh.enable = false;", stage0)
        self.assertIn("users.mutableUsers = true;", stage0)
        self.assertIn("security.sudo.wheelNeedsPassword = true;", stage0)
        self.assertNotIn("autologinUser =", stage0)
        self.assertNotIn("initialPassword", stage0)
        self.assertNotIn("hashedPassword =", stage0)
        self.assertNotIn("nvme0n1", stage0)
        self.assertNotIn("nvme1n1", stage0)
        self.assertNotIn("mkfs", stage0)
        self.assertNotIn("tpm2", stage0.lower())
        self.assertNotIn("nixos_production_install", stage0)

    def test_nixos_local_task_capture_python_keeps_remote_ssh_interpreter(self):
        package = (SOURCE / "modules/grabowski-operator-package.nix").read_text()
        self.assertIn('if original == "src/grabowski_tasks.py":', package)
        self.assertIn('if original == "src/grabowski_fleet.py":', package)
        self.assertIn('unexpected pinned task capture Python topology', package)
        self.assertIn('unexpected pinned fleet cleanup Python guard', package)
        self.assertIn('else TASK_OUTPUT_CAPTURE_PYTHON', package)
        self.assertIn('else TASK_OUTPUT_READ_PYTHON', package)

    def test_operator_has_native_diagnostic_tools_in_systemd_path(self):
        module = (SOURCE / "modules/grabowski-production.nix").read_text()
        # NixOS tools and tmux must be available without mutable user paths.
        self.assertIn(
            "${pkgs.openssh}/bin:${pkgs.tailscale}/bin:${pkgs.procps}/bin:${pkgs.iproute2}/bin:${pkgs.tmux}/bin:/run/current-system/sw/bin",
            module,
        )

    def test_drkonqi_requires_a_graphical_user_session(self):
        desktop = (SOURCE / "modules/desktop.nix").read_text()
        self.assertIn('systemd.user.services."drkonqi-coredump-launcher@"', desktop)
        self.assertIn('overrideStrategy = "asDropin";', desktop)
        self.assertIn(
            'unitConfig.ConditionEnvironment = [ "|DISPLAY" "|WAYLAND_DISPLAY" ];',
            desktop,
        )
        self.assertNotIn("services.coredump.enable = false", desktop)

    def test_xrdp_tailnet_only_and_local_wayland_unchanged(self):
        desktop = (SOURCE / "modules/desktop.nix").read_text()
        self.assertIn("services.xrdp = lib.mkIf config.services.tailscale.enable", desktop)
        self.assertIn('networking.firewall.interfaces."tailscale0".allowedTCPPorts', desktop)
        self.assertIn("lib.optionals config.services.tailscale.enable [ 3389 ];", desktop)
        self.assertIn("openFirewall = false;", desktop)
        self.assertIn('defaultWindowManager = "${pkgs.writeShellScript ', desktop)
        self.assertIn('if [ "$(${pkgs.coreutils}/bin/id -un)" = alex ]; then', desktop)
        self.assertIn('exec ${pkgs.kdePackages.plasma-workspace}/bin/startplasma-x11', desktop)
        self.assertIn('exec ${pkgs.xfce4-session}/bin/startxfce4', desktop)
        self.assertIn("services.xserver.desktopManager.xfce.enable = true;", desktop)
        self.assertIn('services.displayManager.defaultSession = "plasma";', desktop)
        self.assertIn("users.users.ander = {", desktop)
        self.assertIn("uid = 1001;", desktop)
        self.assertIn("packages = [ pkgs.google-chrome ];", desktop)
        self.assertNotIn("pkgs.firefox", desktop)
        self.assertIn("services.displayManager.sddm.wayland.enable = true;", desktop)

    def test_grosser_adler_nixos_declares_independent_observer(self):
        module = (SOURCE / "modules/grosser-adler.nix").read_text()
        host = (SOURCE / "hosts/heim-pc/default.nix").read_text()
        self.assertIn('heimPc.grosserAdler.enable = heimPcProfile.physical or false;', host)
        # PR #290's physical prototype import alone does not reach the
        # active Seagate Grabowski production profile.
        flake = (SOURCE / "flake.nix").read_text()
        seagate_operator = flake.split(
            "nixosConfigurations.heim-pc-seagate-grabowski-headless-candidate =", 1
        )[1].split("# Negative pre-deployment proof", 1)[0]
        self.assertIn("./modules/grosser-adler.nix", seagate_operator)
        self.assertIn("heimPc.grosserAdler.enable = true;", seagate_operator)
        # This physical release candidate needs compressed swap under high
        # Nix/Qt compile pressure; the storage fallback stays untouched.
        self.assertIn("zramSwap = {", seagate_operator)
        self.assertIn('algorithm = "zstd";', seagate_operator)
        self.assertIn("memoryPercent = 25;", seagate_operator)
        self.assertIn("priority = 1000;", seagate_operator)
        self.assertNotIn(
            "grosser-adler.nix",
            (SOURCE / "modules/seagate-primary-candidate.nix").read_text(),
        )
        self.assertIn('systemd.user.services."grosser-adler-mcp" = {', module)
        self.assertIn('systemd.user.services."tunnel-client-grosser-adler" = {', module)
        self.assertIn('unitConfig.ConditionUser = "alex";', module)
        self.assertIn('"d /home/alex/labs 0700 alex users -"', module)
        self.assertIn('/home/alex/.local/bin/tunnel-client run --profile grosser-adler', module)
        self.assertIn('ProtectHome = "read-only";', module)
        self.assertIn('ReadWritePaths = [ "/home/alex/.local/state/grosser-adler" ];', module)

    def test_current_nixos_source_snapshot_is_bound(self):
        # The Nix Git flake contains tracked files only; ignored local
        # host-specific files must not change the published source identity.
        tracked = subprocess.check_output(
            ["git", "ls-files", "-z", "--", "nixos/system"], cwd=ROOT
        )
        files = sorted(ROOT / os.fsdecode(name)
                       for name in tracked.split(b"\0") if name)
        self.assertEqual(len(files), 50)
        digest = hashlib.sha256()
        for path in files:
            self.assertTrue(path.is_file(), str(path))
            relative = str(path.relative_to(SOURCE)).encode()
            digest.update(relative + b"\0" + path.read_bytes() + b"\0")
        self.assertEqual(digest.hexdigest(), SOURCE_SNAPSHOT_SHA256)

    def test_native_restic_uses_systemd_automount_with_idle_release(self):
        module = (SOURCE / "modules/restic-seagate-backup.nix").read_text()
        self.assertIn('"x-systemd.automount"', module)
        self.assertIn('"x-systemd.idle-timeout=60s"', module)
        self.assertNotIn('"noauto"', module)
        self.assertNotIn("backupCleanupCommand", module)
        self.assertIn(
            "test -f /var/lib/heim-pc-backup/restic/heim-pc/config", module
        )
        self.assertIn('RequiresMountsFor', module)
        self.assertIn('initialize = false;', module)
        self.assertIn('pruneOpts = [ ];', module)
        # These active identities are not covered by /home, /persist or /etc.
        for critical in (
            "/var/lib/tailscale", "/var/lib/NetworkManager",
            "/var/lib/nixos", "/var/lib/grabowski",
        ):
            self.assertIn(f'"{critical}"', module)
        self.assertNotIn('"/var/lib/systemd"', module)
        self.assertNotIn('"/root"', module)
        # Only the independent fixed root-owned service may restore data.
        self.assertIn('systemd.services."heim-pc-restic-recovery-probe" = {', module)
        self.assertIn('User = "root";', module)
        self.assertIn('NoNewPrivileges = true;', module)
        self.assertIn('StateDirectory = "heim-pc-restic-recovery-probe";', module)
        self.assertNotIn('security.polkit.extraConfig', module)
        self.assertNotIn('polkit.addRule', module)

    def test_canonical_source_layout(self):
        for relative in (
            "flake.nix", "README.md", "hosts/heim-pc/default.nix",
            "hosts/heim-pc/firstboot-credentials.py",
            "modules/audio.nix", "modules/backup.nix", "modules/build-reproducibility.nix", "modules/bureau.nix",
            "modules/containers.nix", "modules/day2-activation.nix", "modules/desktop.nix", "modules/development.nix",
            "modules/grabowski.nix", "modules/grabowski-production.nix", "modules/grabowski-broker-package.nix", "modules/grosser-adler.nix", "modules/host-protection.nix", "modules/live-media.nix", "modules/networking.nix",
            "modules/nix-lifecycle.nix", "modules/nix-trust.nix", "modules/restic-seagate-backup.nix", "modules/fotoatelier.nix", "modules/heim-pc-restic-recovery-probe.py",
            "modules/nvidia.nix", "modules/nixer.nix", "modules/observability.nix", "modules/physical-gates.nix",
            "modules/storage-layout.nix", "modules/seagate-primary-candidate.nix",
            "tests/firstboot-credentials.nix", "tests/firstboot-gui-proof.nix", "tests/host-protection.nix", "tests/integration.nix", "tests/trust-zones.nix", "tests/vsock-broker.nix",
            "zones/agent.nix",
        ):
            self.assertTrue((SOURCE / relative).is_file(), relative)

    def test_production_build_reproducibility_is_fixed_at_generators(self):
        host = (SOURCE / "hosts/heim-pc/default.nix").read_text()
        module = (SOURCE / "modules/build-reproducibility.nix").read_text()
        workflow = (ROOT / ".github/workflows/nixos-production-build-attest.yml").read_text()

        self.assertIn("../../modules/build-reproducibility.nix", host)
        self.assertIn("hwdbRoot=/tmp/heim-pc-hwdb-root", module)
        self.assertIn('systemd-hwdb --root="$hwdbRoot" update', module)
        self.assertIn(
            "-fdebug-prefix-map=$NIX_BUILD_TOP=/build/nvidia-kernel-modules",
            module,
        )
        self.assertIn(
            "-ffile-prefix-map=$NIX_BUILD_TOP=/build/nvidia-kernel-modules",
            module,
        )
        self.assertIn("preferLocalBuild = true;", module)
        self.assertIn("allowSubstitutes = false;", module)
        self.assertIn("verify_independent_rebuild_candidate", workflow)
        self.assertNotIn("historical_reproducibility", workflow)

    def test_day1_workload_parity_contract_is_fail_closed_and_scoped(self):
        contract = json.loads(
            (ROOT / "nixos/production/day1-workload-parity-contract-v1.json").read_text()
        )
        doc = (ROOT / "architecture/nixos-day1-workload-parity-2026.md").read_text()
        restplan = (ROOT / "architecture/nixos-dual-os-restplan-2026.md").read_text()
        repo_index = (ROOT / "manifest/repo-index.yaml").read_text()
        doc_frontmatter = doc.split("---", 2)[1]
        restplan_frontmatter = restplan.split("---", 2)[1]
        self.assertNotIn(
            "  - nixos-dual-os-restplan-2026\n",
            doc_frontmatter,
        )
        self.assertIn(
            "  - nixos-day1-workload-parity-2026\n",
            restplan_frontmatter,
        )

        self.assertEqual(contract["schema_version"], 1)
        self.assertEqual(
            contract["kind"], "heim_pc.nixos_day1_workload_parity_contract"
        )
        self.assertEqual(
            contract["scope"], "productive-nixos-day1-role-assumption"
        )
        self.assertEqual(
            contract["classification_values"],
            [
                "day1-required",
                "post-migration",
                "replaced",
                "retired",
                "unclassified",
            ],
        )

        admission = contract["admission"]
        self.assertEqual(admission["default"], "blocked")
        self.assertEqual(
            admission["current_status"],
            "blocked-until-fresh-heim-pc-inventory",
        )
        self.assertTrue(admission["ready_requires_fresh_heim_pc_inventory"])
        self.assertTrue(admission["ready_requires_no_unclassified_candidates"])
        self.assertTrue(
            admission["ready_requires_day1_required_implementation_target"]
        )
        self.assertTrue(
            admission["ready_requires_day1_required_acceptance_evidence"]
        )
        self.assertFalse(admission["historical_inventory_may_grant_readiness"])

        enforcement = contract["enforcement"]
        self.assertFalse(enforcement["runtime_consumer_implemented"])
        self.assertFalse(
            enforcement["absence_of_runtime_consumer_may_grant_readiness"]
        )
        self.assertEqual(
            enforcement["current_authority"],
            "normative-contract-and-regression-gate-only",
        )
        self.assertIn(
            "reviewed productive-role-assumption consumer",
            enforcement["successor_requirement"],
        )

        inventory = contract["inventory"]
        self.assertEqual(inventory["authoritative_host"], "heim-pc")
        self.assertIsNone(inventory["current_binding"])
        self.assertEqual(
            inventory["unreachable_or_unbound_behavior"],
            "block-classification-and-readiness",
        )

        pipeline = inventory["collection_pipeline"]
        self.assertEqual(
            pipeline["software"]["collector_and_renderer"],
            "scripts/generate_software_inventory.py",
        )
        self.assertEqual(
            pipeline["software"]["canonical_outputs"],
            ["runtime/software-inventory.md"],
        )
        self.assertEqual(
            pipeline["program"]["collector"],
            "scripts/collect_program_inventory.py",
        )
        self.assertEqual(
            pipeline["program"]["renderer"],
            "scripts/generate_program_inventory.py",
        )
        self.assertEqual(
            pipeline["program"]["raw_artifacts_policy"],
            "host-local-outside-git",
        )
        self.assertEqual(
            pipeline["program"]["canonical_outputs"],
            [
                "runtime/program-inventory-summary.md",
                "runtime/program-inventory.v1.json",
            ],
        )
        self.assertEqual(
            inventory["canonical_outputs"],
            [
                "runtime/software-inventory.md",
                "runtime/program-inventory-summary.md",
                "runtime/program-inventory.v1.json",
            ],
        )

        expected_seeds = {
            "runtime/software-inventory.md": (
                "2026-07-09T17:16:37Z",
                "c3d0622a17cf755a8f69ec53b867a1a1913503cbe57a9cf675d939699ae0c36d",
            ),
            "runtime/program-inventory-summary.md": (
                "2026-07-09T18:15:00Z",
                "8b6abbeae959996e7bcb396780d8fc31655035c1e3b129fc82efb9e500824640",
            ),
            "runtime/program-inventory.v1.json": (
                "2026-07-09T18:15:00Z",
                "2726fa724206d01c61e59ea5ad6c7b9eaced7bfe32251073538fd2bf4bc3eeb3",
            ),
        }
        seeds = {seed["path"]: seed for seed in inventory["historical_seed"]}
        self.assertEqual(set(seeds), set(expected_seeds))
        for path, (observed_at, sha256) in expected_seeds.items():
            seed = seeds[path]
            self.assertEqual(seed["authority"], "candidate-seed-only")
            self.assertEqual(
                seed["source_revision"],
                "d2260b32094fdde5c6efc158e561142d48fe9171",
            )
            self.assertEqual(seed["observed_at"], observed_at)
            self.assertEqual(seed["sha256"], sha256)

        historical_binding = inventory["historical_seed_binding"]
        self.assertEqual(
            historical_binding["identity"],
            "source-revision-path-sha256",
        )
        self.assertFalse(
            historical_binding["mutable_current_outputs_may_replace_historical_seed"]
        )
        self.assertTrue(
            historical_binding[
                "historical_seed_remains_authoritative_after_current_output_refresh"
            ]
        )

        current_binding_schema = inventory["current_binding_schema"]
        self.assertEqual(current_binding_schema["schema_version"], 1)
        self.assertEqual(
            current_binding_schema["required_fields"],
            ["host", "source_revision", "observation", "outputs", "provenance"],
        )
        self.assertEqual(current_binding_schema["host_must_equal"], "heim-pc")
        self.assertEqual(
            current_binding_schema["source_revision_format"],
            "40-lowercase-hex",
        )
        self.assertEqual(
            current_binding_schema["output_binding"],
            "path+sha256+observed_at+observation_id",
        )
        observation = current_binding_schema["observation"]
        self.assertEqual(observation["kind"], "bounded-session-v1")
        self.assertEqual(
            observation["required_fields"],
            ["id", "started_at", "completed_at"],
        )
        self.assertEqual(observation["id_format"], "64-lowercase-hex")
        self.assertTrue(observation["all_required_outputs_must_share_id"])
        self.assertTrue(observation["output_observed_at_must_be_within_session"])
        provenance = current_binding_schema["provenance"]
        self.assertEqual(provenance["required_fields"], ["software", "program"])
        self.assertTrue(
            provenance["software"]["collector_sha256_must_match_source_revision"]
        )
        self.assertTrue(
            provenance["software"]["execution_receipt_sha256_required"]
        )
        self.assertTrue(
            provenance["software"]["execution_receipt_must_bind_observation_id_and_argv"]
        )
        self.assertTrue(
            provenance["program"]["collector_and_renderer_sha256_must_match_source_revision"]
        )
        self.assertTrue(
            provenance["program"]["execution_receipt_sha256_required"]
        )
        self.assertTrue(
            provenance["program"]["execution_receipt_must_bind_observation_id_and_argv"]
        )
        self.assertTrue(provenance["program"]["raw_manifest_sha256_required"])
        self.assertEqual(
            current_binding_schema["required_output_paths"],
            inventory["canonical_outputs"],
        )
        self.assertEqual(
            current_binding_schema["required_output_metadata"],
            ["observed_at", "observation_id", "binding_eligible"],
        )
        self.assertTrue(current_binding_schema["binding_eligible_must_be_true"])
        self.assertTrue(current_binding_schema["output_host_must_equal_authoritative_host"])
        self.assertTrue(
            current_binding_schema["freshness_required_at_productive_role_assumption"]
        )
        self.assertTrue(
            current_binding_schema["freshness_policy_must_be_bound_by_reviewed_consumer"]
        )

        reconciliation = inventory["historical_reconciliation"]
        self.assertTrue(reconciliation["required"])
        self.assertEqual(
            reconciliation["seed_source"],
            "revision-and-sha256-bound-historical-seed",
        )
        self.assertEqual(
            reconciliation["granularity"], "individual-observed-item"
        )
        self.assertTrue(
            reconciliation["every_historical_item_requires_disposition"]
        )
        self.assertFalse(reconciliation["silent_omission_allowed"])
        self.assertTrue(reconciliation["candidate_groups_are_planning_only"])
        self.assertEqual(
            set(reconciliation["allowed_dispositions"]),
            {
                "present-and-classified",
                "absent-and-retired",
                "absent-and-replaced",
            },
        )

        candidates = contract["historical_candidates"]
        self.assertGreaterEqual(len(candidates), 6)
        self.assertEqual(
            {candidate["classification"] for candidate in candidates},
            {"unclassified"},
        )
        self.assertEqual(
            len({candidate["id"] for candidate in candidates}),
            len(candidates),
        )

        excluded = contract["excluded_path"]
        self.assertEqual(
            excluded["migration_mode"],
            "isolated-parallel-disk-dual-os",
        )
        self.assertTrue(
            excluded[
                "isolated_installation_and_test_boot_may_proceed_under_existing_storage_boot_attestation_gates"
            ]
        )
        self.assertFalse(excluded["productive_role_assumption_authorized"])

        self.assertIn(
            "nixos-day1-workload-parity-2026.md",
            repo_index,
        )
        self.assertIn(
            "kein Installationsgate für den isolierten Dual-OS-Testpfad",
            doc,
        )
        self.assertIn(
            "Ein fehlender oder blockierter Day-1-Paritätsnachweis erweitert die Storage-Autorität nicht",
            restplan,
        )
        self.assertNotIn(
            '"current_status": "ready"',
            (ROOT / "nixos/production/day1-workload-parity-contract-v1.json").read_text(),
        )

    def test_pre_cutover_contracts_are_machine_readable_and_fail_closed(self):
        trust = json.loads((ROOT / "nixos/production/trust-contract-v1.json").read_text())
        lifecycle = json.loads((ROOT / "nixos/production/nix-lifecycle-contract-v1.json").read_text())
        recovery = json.loads((ROOT / "nixos/production/recovery-contract-v1.json").read_text())
        critical_path = ROOT / "nixos/production/critical-user-data-contract-v1.json"
        critical_home_path = ROOT / "nixos/production/critical-user-home-data-contract-v1.json"
        critical = json.loads(critical_path.read_text())
        critical_home = json.loads(critical_home_path.read_text())
        critical_sha256 = hashlib.sha256(critical_path.read_bytes()).hexdigest()
        critical_home_sha256 = hashlib.sha256(critical_home_path.read_bytes()).hexdigest()
        host = (SOURCE / "hosts/heim-pc/default.nix").read_text()
        trust_module = (SOURCE / "modules/nix-trust.nix").read_text()
        lifecycle_module = (SOURCE / "modules/nix-lifecycle.nix").read_text()
        backup_module = (SOURCE / "modules/backup.nix").read_text()
        validate_workflow = (ROOT / ".github/workflows/heim-pc-validate.yml").read_text()

        self.assertEqual(trust["kind"], "heim_pc.nixos_supply_chain_trust_contract")
        self.assertEqual(trust["nix"]["trusted_users"], ["root"])
        self.assertTrue(trust["nix"]["require_sigs"])
        self.assertFalse(trust["nix"]["accept_flake_config"])
        self.assertFalse(trust["nix"]["trust_tarballs_from_git_forges"])
        self.assertEqual(trust["nix"]["experimental_features"], ["nix-command", "flakes"])
        self.assertEqual(
            trust["inputs"]["nixer"]["required_revision"],
            "c252b62b0fcd0bd5442681bb68d809a4b5984c61",
        )
        self.assertTrue(trust["inputs"]["nixer"]["owns_runtime_nixpkgs"])
        self.assertIn("nix.settings", trust_module)
        self.assertIn("trusted-users = lib.mkForce", trust_module)
        self.assertIn("experimental-features = lib.mkForce", trust_module)
        self.assertIn("trust-tarballs-from-git-forges = lib.mkForce", trust_module)
        self.assertIn("../../modules/nix-trust.nix", host)
        flake = (SOURCE / "flake.nix").read_text()
        self.assertIn("builtins.readFile ../../flake.lock", flake)
        self.assertIn("target.nix.settings.trust-tarballs-from-git-forges", flake)
        self.assertIn(
            "rootNixpkgsNode.locked.rev == contract.inputs.root_nixpkgs.required_revision",
            flake,
        )
        self.assertIn(
            "rootNixpkgsNode.original.ref == contract.inputs.root_nixpkgs.required_ref",
            flake,
        )
        self.assertIn('microvmNode.inputs.nixpkgs == [ "nixpkgs" ]', flake)
        self.assertIn(
            "nixerNode.inputs.nixpkgs == contract.inputs.nixer.runtime_nixpkgs_lock_node",
            flake,
        )
        self.assertIn(
            "contract.inputs.nixer.runtime_nixpkgs_required_revision",
            flake,
        )
        from scripts.ci import check_pinned_nix_find_contract as verifier_check

        verifier = trust["managed_nix_verifier"]
        self.assertEqual(
            verifier_check.verify_managed_nix_verifier_contract(
                ROOT / "nixos/production/trust-contract-v1.json"
            ),
            {
                "image_id": verifier["image_id"],
                "image_tag": verifier["image_tag"],
                "image_ref": verifier["image_ref"],
            },
        )
        mismatches = {
            "image_id": "sha256:" + ("0" * 64),
            "image_tag": "nixos/nix:0.0.0",
            "image_ref": "nixos/nix@sha256:" + ("0" * 64),
        }
        for field, value in mismatches.items():
            mutated = json.loads(json.dumps(trust))
            mutated["managed_nix_verifier"][field] = value
            with self.subTest(verifier_pin=field), tempfile.TemporaryDirectory() as tmp:
                contract_path = Path(tmp) / "trust-contract.json"
                contract_path.write_text(json.dumps(mutated), encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, field):
                    verifier_check.verify_managed_nix_verifier_contract(contract_path)
        with mock.patch.object(
            verifier_check.installer,
            "PINNED_NIX_CONTAINERD_IMAGE_REF",
            "docker.io/nixos/nix:0.0.0",
        ):
            with self.assertRaisesRegex(RuntimeError, "containerd Nix image reference"):
                verifier_check.verify_managed_nix_verifier_contract(
                    ROOT / "nixos/production/trust-contract-v1.json"
                )
        self.assertIn("check_pinned_nix_find_contract.py", flake)
        self.assertIn("--trust-contract-only", flake)
        self.assertNotIn("pythonAssignment", flake)

        self.assertEqual(lifecycle["kind"], "heim_pc.nixos_store_lifecycle_contract")
        self.assertFalse(lifecycle["automatic_gc"])
        self.assertFalse(lifecycle["budget"]["automatic_reclaim_authorized"])
        self.assertTrue(lifecycle["admission"]["initial_cutover_requires_contract"])
        self.assertFalse(lifecycle["admission"]["initial_cutover_requires_live_audit"])
        self.assertTrue(lifecycle["admission"]["automatic_gc_requires_fresh_audit"])
        self.assertTrue(lifecycle["admission"]["automatic_gc_requires_separate_reviewed_enablement"])
        self.assertTrue(
            lifecycle["protected_generations"]["last_known_good_must_be_enumerated_gc_root"]
        )
        self.assertIn("nix.gc.automatic = lib.mkForce false;", lifecycle_module)
        self.assertIn("root_target_is_enumerated", lifecycle_module)
        self.assertIn("blocked-unrooted-last-known-good", lifecycle_module)
        self.assertIn("last_known_good_gc_rooted", lifecycle_module)
        self.assertIn("gc_root_readback_ok=false", lifecycle_module)
        self.assertIn("blocked-gc-root-enumeration-failed", lifecycle_module)
        self.assertNotIn("--print-roots 2>/dev/null || true", lifecycle_module)
        self.assertIn("target_is_system_profile_generation", lifecycle_module)
        self.assertIn("/nix/var/nix/profiles/system-*-link", lifecycle_module)
        self.assertIn("blocked-last-known-good-not-system-generation", lifecycle_module)
        self.assertIn("last_known_good_is_system_generation", lifecycle_module)
        self.assertIn('"d /persist/heim-pc 0700 root root -"', lifecycle_module)
        self.assertIn('"d /persist/heim-pc/nix-lifecycle 0700 root root -"', lifecycle_module)
        self.assertIn("heim-pc-nix-lifecycle-audit", lifecycle_module)
        self.assertNotIn("nix-collect-garbage", lifecycle_module)
        self.assertIn("../../modules/nix-lifecycle.nix", host)

        self.assertEqual(critical["schema_version"], 1)
        self.assertEqual(critical["kind"], "heim_pc.critical_user_data_scope_contract")
        self.assertEqual(critical["scope"], "critical-user-data")
        self.assertEqual(critical["scope_semantics"], "explicit-positive-selection")
        implementation = critical["inventory_implementation"]
        self.assertEqual(
            implementation["root_inventory_script_sha256"],
            hashlib.sha256(
                (ROOT / "scripts/nixos_critical_user_data_inventory.py").read_bytes()
            ).hexdigest(),
        )
        self.assertEqual(
            implementation["aggregate_inventory_script_sha256"],
            hashlib.sha256(
                (ROOT / "scripts/nixos_critical_data_inventory.py").read_bytes()
            ).hexdigest(),
        )
        self.assertEqual(implementation["aggregate_execution_mode"], "external-verified-payload-exec-v1")
        self.assertEqual(
            implementation["authoritative_member_source_stability"],
            "kernel-local-pci-nvme-readonly-mountinfo-v3",
        )
        self.assertEqual([member["id"] for member in critical["members"]], ["home"])
        (home_member,) = critical["members"]
        self.assertEqual(home_member["contract_file"], "critical-user-home-data-contract-v1.json")
        self.assertEqual(home_member["contract_sha256"], critical_home_sha256)
        self.assertEqual(home_member["destination"], {"nixos_storage_domain": "per-entry-policy", "logical_path": "materialization-policy"})
        self.assertEqual(home_member["restore_mode"], "source-scope-with-role-specific-materialization")
        self.assertEqual(critical_home["scope"], "critical-user-data-home")
        self.assertEqual(critical_home["root"], "/home/alex")
        self.assertEqual(critical_home["scope_semantics"], "explicit-path-set")
        self.assertEqual(
            critical_home["inventory"]["algorithm"],
            "canonical-record-stream-sha256-v7",
        )
        self.assertTrue(critical_home["inventory"]["uid_gid_bound"])
        self.assertTrue(
            critical_home["inventory"]["explicit_ancestor_metadata_bound"]
        )
        self.assertTrue(critical_home["inventory"]["xattrs_sha256_bound"])
        selected = {item["path"] for item in critical_home["includes"]}
        for required in {
            "/home/alex/collections/bibliothek",
            "/home/alex/repos/schotter",
            "/home/alex/repos/fotoatelier",
            "/home/alex/.ssh",
            "/home/alex/.config/grabowski/review-evidence-signing-ed25519",
            "/home/alex/.local/state/grabowski/tasks.sqlite3",
            "/home/alex/.local/state/bureau/bureau.sqlite3",
            "/home/alex/.local/state/chronik/data",
            "/home/alex/.local/state/grosser-adler/findings",
        }:
            self.assertIn(required, selected)
        for excluded in {
            "/home/alex/vault-gewebe",
            "/home/alex/CZURScannerDoc",
            "/home/alex/Digitalisierer",
            "/home/alex/.local/share/heim-utilities/paperless",
            "/home/alex/repos/arden-relaunch-demo",
            "/home/alex/repos/wolf-drechsel-local-ai",
            "/var/lib/docker/volumes",
        }:
            self.assertNotIn(excluded, selected)
        by_source = {item["path"]: item for item in critical_home["includes"]}
        recovery_signer = by_source[
            "/home/alex/.config/grabowski/review-evidence-signing-ed25519"
        ]
        self.assertEqual(recovery_signer["class"], "credentials-and-identity")
        self.assertEqual(recovery_signer["capture"], "file")
        self.assertEqual(recovery_signer["restore_mode"], "private-credential-file")
        self.assertEqual(by_source["/home/alex/collections/bibliothek"]["class"], "legacy-library-preservation")
        self.assertEqual(by_source["/home/alex/collections/bibliothek"]["restore_mode"], "cold-preservation-tree")
        for repo_name in ("schotter", "fotoatelier"):
            self.assertEqual(by_source[f"/home/alex/repos/{repo_name}"]["restore_mode"], "cold-preservation-git-capsule")

        materialization = critical_home["materialization_policy"]
        cold_root = "/var/lib/heim-pc-data/import/legacy-2026"
        self.assertEqual(materialization["kind"], "heim_pc.critical_user_data_materialization_policy")
        self.assertTrue(materialization["source_scope_and_nixos_target_layout_are_separate"])
        self.assertTrue(materialization["source_equivalent_disposable_restore_required"])
        self.assertEqual(materialization["cold_import_root"], cold_root)
        self.assertEqual(materialization["schema_version"], 1)
        self.assertFalse(materialization["first_productive_boot_requires_cold_import_completion"])
        self.assertTrue(materialization["roles"]["bootstrap-direct"]["source_path_is_live_target_path"])
        self.assertFalse(materialization["roles"]["authority-reconcile"]["source_path_is_live_target_path"])
        self.assertTrue(materialization["roles"]["authority-reconcile"]["direct_activation_forbidden"])
        self.assertFalse(materialization["roles"]["cold-preservation"]["required_before_first_productive_boot"])
        cold = {item["source_path"]: item for item in materialization["cold_entries"]}
        self.assertEqual(cold["/home/alex/collections/bibliothek"]["target_path"], cold_root + "/bibliothek")
        self.assertFalse(cold["/home/alex/collections/bibliothek"]["old_source_path_becomes_active_path"])
        self.assertTrue(cold["/home/alex/collections/bibliothek"]["future_importer_required"])
        for repo_name in ("schotter", "fotoatelier"):
            capsule = cold[f"/home/alex/repos/{repo_name}"]
            self.assertEqual(capsule["capsule_kind"], "git-bundle-plus-working-tree-overlay")
            self.assertEqual(capsule["bundle_path"], f"{cold_root}/repos/{repo_name}.gitbundle")
            self.assertEqual(capsule["bundle_mode"], "--all")
            self.assertEqual(capsule["working_tree_overlay_policy"], "required-iff-tracked-dirty-or-untracked")
            self.assertFalse(capsule["active_checkout_created_automatically"])

        self.assertIn('"d ${coldImportRoot}/authority 0700 root root -"', backup_module)
        self.assertIn('"d ${coldImportRoot}/repos 0700 root root -"', backup_module)
        self.assertEqual(critical_home["selection_policy"]["default"], "exclude")
        self.assertFalse(critical_home["selection_policy"]["unlisted_paths_are_migration_data"])
        self.assertEqual(critical["migration_policy"]["selection_model"], "explicit-positive-allowlist")
        self.assertFalse(critical["migration_policy"]["unlisted_data_migrated"])
        self.assertTrue(critical["migration_policy"]["system_state_recreated_from_nix"])
        self.assertTrue(critical["migration_policy"]["old_system_disk_preserved_as_independent_fallback"])
        self.assertTrue(critical["migration_policy"]["remote_reproducible_repositories_excluded"])
        self.assertTrue(critical["migration_policy"]["operator_state_restored_via_authority_reconcile"])
        self.assertFalse(critical["migration_policy"]["legacy_docker_volume_tree_migrated"])
        self.assertFalse(critical["migration_policy"]["root_owned_grabowski_runtime_state_migrated"])
        self.assertTrue(critical["migration_policy"]["root_owned_grabowski_runtime_state_reinitialized_from_verified_deploy"])
        self.assertFalse(critical["migration_policy"]["source_paths_define_nixos_target_layout"])
        self.assertEqual(critical["migration_policy"]["cold_preservation_storage_domain"], "@data")
        self.assertEqual(critical["migration_policy"]["cold_preservation_import_root"], cold_root)
        self.assertFalse(critical["migration_policy"]["cold_preservation_required_before_first_productive_boot"])
        self.assertFalse(critical["migration_policy"]["local_only_repository_auto_checkout"])
        self.assertFalse(critical["migration_policy"]["legacy_library_source_path_restored"])
        self.assertTrue(critical["migration_policy"]["operator_state_direct_restore_forbidden"])
        self.assertFalse((ROOT / "nixos/production/critical-docker-volume-data-contract-v1.json").exists())
        self.assertEqual(
            recovery["critical_user_data_scope"],
            {
                "contract_kind": "heim_pc.critical_user_data_scope_contract",
                "scope": "critical-user-data",
                "sha256": critical_sha256,
                "off_host_restore_critical_scope_sha256_bound": True,
                "off_host_restore_source_inventory_sha256_bound": True,
                "off_host_restore_restored_inventory_sha256_bound": True,
                "off_host_restore_inventory_sha256_equality_required": True,
                "aggregate_member_contracts_bound": True,
            },
        )

        self.assertTrue(
            recovery["readiness_bundle"]["critical_user_data_contract_sha256_bound"]
        )
        self.assertEqual(recovery["status"], "external-evidence-required")
        self.assertEqual(
            recovery["admission_scope"],
            {
                "complete_evidence_required_for": "destructive-source-cutover",
                "excluded_installation": {
                    "migration_mode": "isolated-parallel-disk-dual-os",
                    "source_preservation_mode": "retained-protected-source",
                    "destructive_source_cutover": False,
                    "pre_cutover_readiness_required": False,
                },
            },
        )
        self.assertTrue(recovery["admission"]["point_of_no_return_blocked_without_complete_evidence"])
        self.assertTrue(
            recovery["admission"]["destructive_source_cutover_blocked_without_complete_evidence"]
        )
        self.assertNotIn(
            "production_storage_mutation_blocked_without_complete_evidence",
            recovery["admission"],
        )
        self.assertFalse(recovery["same_disk_recovery_partition_is_off_host_backup"])
        self.assertEqual(recovery["evidence_freshness"]["maximum_age_seconds"], 604800)
        self.assertEqual(recovery["evidence_freshness"]["future_skew_seconds"], 5)
        self.assertEqual(
            recovery["evidence_receipt"]["kind"],
            "heim_pc.nixos_recovery_evidence_receipt",
        )
        receipt_contract = recovery["evidence_receipt"]