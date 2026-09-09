{ pkgs, sourceRevision }:
let
  hostModule = ../hosts/heim-pc;
  expectedHostSha256 = "567f4c3a15c0e15672c5e653b5a181fab8e04dde6383fdedbdec1055aa6fff7d";
  expectedHelperSha256 = "eddc72630fa2d5c5d1a298d6352eb97d80515101a589db2ddc6fd0b44e5e24b7";

  stageTool = pkgs.writeShellApplication {
    name = "heim-pc-firstboot-test-stage";
    runtimeInputs = with pkgs; [ coreutils mkpasswd ];
    text = ''
      set -eu
      mode="''${1:-valid}"
      case "$mode" in
        valid|invalid-authority) ;;
        *) echo "unsupported staging mode" >&2; exit 64 ;;
      esac

      umask 077
      install -d -m 0700 -o root -g root \
        /persist/secrets \
        /persist/secrets/heim-pc \
        /persist/secrets/heim-pc/first-boot

      password_file=/run/heim-pc-test-password
      if [ ! -s "$password_file" ]; then
        od -An -N12 -tx1 /dev/urandom | tr -d ' \n' > "$password_file"
        printf '\n' >> "$password_file"
        chmod 0600 "$password_file"
      fi

      secret=/persist/secrets/heim-pc/first-boot/alex-password-hash
      authority=/persist/secrets/heim-pc/first-boot/alex-password-bootstrap-authority
      hash="$(mkpasswd -m yescrypt -s < "$password_file")"
      printf '%s\n' "$hash" > "$secret"
      chmod 0600 "$secret"
      secret_sha="$(sha256sum "$secret" | cut -d ' ' -f 1)"
      {
        printf 'schema_version=1\n'
        printf 'user=alex\n'
        printf 'action=initialize-password\n'
        printf 'source_revision=%s\n' '${sourceRevision}'
        printf 'password_hash_sha256=%s\n' "$secret_sha"
      } > "$authority"
      chmod 0600 "$authority"

      if [ "$mode" = invalid-authority ]; then
        printf 'invalid\n' > "$authority"
      fi
      sync -f /persist/secrets/heim-pc/first-boot
    '';
  };

  interruptChpasswd = pkgs.writeShellApplication {
    name = "chpasswd";
    runtimeInputs = with pkgs; [ coreutils ];
    text = ''
      set -eu
      ${pkgs.shadow}/bin/chpasswd "$@"
      count_file=/run/heim-pc-test-chpasswd-count
      count=0
      if [ -r "$count_file" ]; then count="$(cat "$count_file")"; fi
      count=$((count + 1))
      printf '%s\n' "$count" > "$count_file"
      chmod 0600 "$count_file"
      # The production helper's own 10-second child timeout must fire only
      # after the real shadow mutation has completed.
      sleep 30
    '';
  };

  commonNode = { lib, pkgs, ... }: {
    imports = [ hostModule ];
    # runNixOSTest supplies pkgs and makes nixpkgs.config read-only. Force the
    # constant config required by the imported physical host module; referring
    # back to pkgs.config here would recurse through _module.args.
    nixpkgs.config = lib.mkForce { allowUnfree = true; };
    _module.args = {
      self = { rev = sourceRevision; };
      heimPcProfile = {
        physical = true;
        nvidia = false;
        nvidiaOpen = false;
        desktop = true;
        physicalGates = false;
      };
    };

    # QEMU owns the disposable root image. A second auto-formatted image is the
    # persistent /persist surface so marker/authority behavior survives reboot.
    virtualisation.useDefaultFilesystems = true;
    virtualisation.emptyDiskImages = [ 512 ];
    virtualisation.fileSystems."/" = {
      device = "/dev/disk/by-label/nixos";
      fsType = "ext4";
    };
    virtualisation.fileSystems."/persist" = {
      device = "/dev/vdb";
      fsType = "ext4";
      autoFormat = true;
    };
    fileSystems."/persist" = {
      device = "/dev/vdb";
      fsType = "ext4";
    };

    virtualisation.memorySize = 3072;
    virtualisation.cores = 2;
    # The physical desktop profile runs SDDM itself on Wayland. QEMU's default
    # std VGA produces a corrupt greeter framebuffer under that path, so use
    # the virtio GPU shape used by upstream NixOS Wayland VM tests.
    virtualisation.qemu.options = [ "-vga none -device virtio-gpu-pci" ];
    documentation.enable = false;
    hardware.enableAllFirmware = lib.mkForce false;
    # The production NVIDIA profile normally enables the NixOS graphics stack.
    # This test deliberately disables NVIDIA, so enable generic Mesa/DRM support
    # explicitly for the virtio GPU used by the disposable Wayland VM.
    hardware.graphics.enable = true;
    # Plasma defaults SDDM's Wayland greeter compositor to KWin. The QEMU
    # virtio display is sufficient for a real SDDM/PAM login proof but exposes
    # a KWin-specific empty-DRM-node failure unrelated to credential bootstrap.
    # Keep the greeter on Wayland while using SDDM's supported Weston path;
    # the authenticated desktop session remains the real Plasma Wayland session.
    services.displayManager.sddm.wayland.compositor = lib.mkForce "weston";

    # Keep the proof scoped to the credential and real desktop/PAM path. Heavy
    # unrelated services stay disabled below, but retain normal NixOS package
    # composition because SDDM and Plasma publish runtime dependencies through
    # environment.systemPackages. Add the test-driver tools without replacing it.
    services.pipewire.enable = lib.mkForce false;
    security.rtkit.enable = lib.mkForce false;
    virtualisation.podman.enable = lib.mkForce false;
    programs.nix-ld.enable = lib.mkForce false;
    programs.appimage.enable = lib.mkForce false;
    programs.appimage.binfmt = lib.mkForce false;
    environment.systemPackages = [
      stageTool
      pkgs.bashInteractive
      pkgs.coreutils
      pkgs.gawk
      pkgs.glibc.bin
      pkgs.getent
      pkgs.gnugrep
      pkgs.procps
      pkgs.shadow
      pkgs.systemd
      pkgs.util-linux
    ];
  };
in
assert builtins.hashFile "sha256" ../hosts/heim-pc/default.nix == expectedHostSha256;
assert builtins.hashFile "sha256" ../hosts/heim-pc/firstboot-credentials.py == expectedHelperSha256;
pkgs.testers.runNixOSTest {
  name = "heim-pc-firstboot-credentials";
  globalTimeout = 3600;
  enableOCR = true;

  nodes.machine = commonNode;
  nodes.interrupted = { lib, pkgs, ... }: {
    imports = [ commonNode ];
    systemd.services.heim-pc-firstboot-credentials.path = lib.mkForce [ interruptChpasswd pkgs.shadow ];
  };

  testScript = ''
    machine.start()

    def shadow_field(node):
        return node.succeed("getent shadow alex | cut -d: -f2").strip()

    def wait_for_alex_wayland(node):
        node.wait_until_succeeds(
            r"""for id in $(loginctl list-sessions --no-legend | awk '$3 == "alex" {print $1}'); do
            test "$(loginctl show-session "$id" -p Type --value)" = wayland &&
            test "$(loginctl show-session "$id" -p Active --value)" = yes && exit 0
            done
            exit 1""",
            timeout=180,
        )

    def graphical_login(node, password_path):
        node.wait_for_unit("display-manager.service", timeout=180)
        node.wait_until_succeeds("pgrep -u sddm -f sddm-greeter", timeout=180)
        node.wait_for_text("(?i)select your user", timeout=180)
        # succeed() logs the command but does not log successful stdout. Never
        # call send_chars(): it logs repr(chars). send_key(log=False) keeps the
        # runtime-only password out of the public VM-test log.
        password = node.succeed(f"cat {password_path}").strip()
        assert password
        for char in password:
            node.send_key(char, log=False)
        node.send_key("ret")
        wait_for_alex_wayland(node)

    with subtest("missing bootstrap staging fails closed before login"):
        machine.wait_until_succeeds("systemctl is-failed heim-pc-firstboot-credentials.service", timeout=180)
        machine.fail("systemctl is-active systemd-user-sessions.service")
        machine.fail("systemctl is-active display-manager.service")
        assert shadow_field(machine) in ("!", "!!", "*")
        machine.fail("test -e /persist/heim-pc/bootstrap/alex-password-initialized")

    with subtest("invalid authority fails closed without mutating shadow"):
        machine.succeed("heim-pc-firstboot-test-stage invalid-authority")
        machine.succeed("systemctl reset-failed heim-pc-firstboot-credentials.service")
        machine.fail("systemctl start heim-pc-firstboot-credentials.service")
        assert shadow_field(machine) in ("!", "!!", "*")
        machine.fail("test -e /persist/heim-pc/bootstrap/alex-password-initialized")
        machine.fail("test -e /persist/heim-pc/bootstrap/.alex-password-initialized.pending")

    with subtest("real chpasswd bootstrap publishes durable marker and consumes staging"):
        machine.succeed("heim-pc-firstboot-test-stage valid")
        machine.succeed("systemctl reset-failed heim-pc-firstboot-credentials.service")
        machine.succeed("systemctl start heim-pc-firstboot-credentials.service")
        bootstrap_hash = shadow_field(machine)
        assert bootstrap_hash.startswith("$y$j9T$")
        machine.succeed("test -f /persist/heim-pc/bootstrap/alex-password-initialized")
        machine.succeed("test ! -e /persist/heim-pc/bootstrap/.alex-password-initialized.pending")
        machine.succeed("test ! -e /persist/secrets/heim-pc/first-boot/alex-password-hash")
        machine.succeed("test ! -e /persist/secrets/heim-pc/first-boot/alex-password-bootstrap-authority")

    with subtest("real graphical SDDM Plasma Wayland login works without autologin"):
        machine.succeed("systemctl start systemd-user-sessions.service display-manager.service")
        graphical_login(machine, "/run/heim-pc-test-password")

    with subtest("later password rotation survives reboot and bootstrap does not replay"):
        machine.succeed("loginctl terminate-user alex || true")
        machine.wait_until_fails("loginctl list-sessions --no-legend | grep -q ' alex '", timeout=60)
        machine.succeed(
            "umask 077; od -An -N12 -tx1 /dev/urandom | tr -d ' \\n' > /persist/.heim-pc-test-password-rotated; "
            "printf '\\n' >> /persist/.heim-pc-test-password-rotated; chmod 0600 /persist/.heim-pc-test-password-rotated; "
            "{ printf 'alex:'; cat /persist/.heim-pc-test-password-rotated; } | chpasswd; "
            "sync -f /persist"
        )
        rotated_hash = shadow_field(machine)
        assert rotated_hash.startswith("$y$j9T$")
        assert rotated_hash != bootstrap_hash
        machine.reboot()
        machine.wait_for_unit("heim-pc-firstboot-credentials.service", timeout=180)
        assert shadow_field(machine) == rotated_hash
        graphical_login(machine, "/persist/.heim-pc-test-password-rotated")

    with subtest("late interrupted publication is recovery-required and recoverable under lock"):
        machine.succeed("loginctl terminate-user alex || true")
        machine.succeed(
            "ln /persist/heim-pc/bootstrap/alex-password-initialized "
            "/persist/heim-pc/bootstrap/.alex-password-initialized.pending; "
            "sync -f /persist/heim-pc/bootstrap"
        )
        machine.reboot()
        machine.wait_until_succeeds("systemctl is-failed heim-pc-firstboot-credentials.service", timeout=180)
        machine.fail("systemctl is-active display-manager.service")
        machine.succeed("test $(stat -c %h /persist/heim-pc/bootstrap/alex-password-initialized) -eq 2")
        machine.succeed(
            "umask 077; od -An -N12 -tx1 /dev/urandom | tr -d ' \\n' > /persist/.heim-pc-test-password-recovery; "
            "printf '\\n' >> /persist/.heim-pc-test-password-recovery; chmod 0600 /persist/.heim-pc-test-password-recovery; "
            "exec 9>/persist/heim-pc/bootstrap/.alex-password-bootstrap.lock; flock -n 9; "
            "{ printf 'alex:'; cat /persist/.heim-pc-test-password-recovery; } | chpasswd; "
            "getent shadow alex | cut -d: -f2 | grep -Eq '^\\$y\\$j9T\\$'; "
            "rm /persist/heim-pc/bootstrap/.alex-password-initialized.pending; "
            "sync -f /persist/heim-pc/bootstrap; "
            "test $(stat -c %h /persist/heim-pc/bootstrap/alex-password-initialized) -eq 1"
        )
        machine.succeed("systemctl reset-failed heim-pc-firstboot-credentials.service")
        machine.succeed("systemctl start heim-pc-firstboot-credentials.service")
        machine.succeed("systemctl start systemd-user-sessions.service display-manager.service")
        graphical_login(machine, "/persist/.heim-pc-test-password-recovery")

    with subtest("real post-mutation child timeout leaves pending and never replays"):
        machine.shutdown()
        interrupted.start()
        interrupted.wait_until_succeeds("systemctl is-failed heim-pc-firstboot-credentials.service", timeout=180)
        interrupted.succeed("heim-pc-firstboot-test-stage valid")
        interrupted.succeed("systemctl reset-failed heim-pc-firstboot-credentials.service")
        interrupted.fail("systemctl start heim-pc-firstboot-credentials.service", timeout=30)
        interrupted.succeed("test $(cat /run/heim-pc-test-chpasswd-count) -eq 1")
        interrupted.succeed("test -f /persist/heim-pc/bootstrap/.alex-password-initialized.pending")
        interrupted.fail("test -e /persist/heim-pc/bootstrap/alex-password-initialized")
        interrupted.succeed("test -f /persist/secrets/heim-pc/first-boot/alex-password-hash")
        interrupted.succeed("test -f /persist/secrets/heim-pc/first-boot/alex-password-bootstrap-authority")
        interrupted_hash = shadow_field(interrupted)
        assert interrupted_hash.startswith("$y$j9T$")
        interrupted.succeed("systemctl reset-failed heim-pc-firstboot-credentials.service")
        interrupted.fail("systemctl start heim-pc-firstboot-credentials.service", timeout=10)
        interrupted.succeed("test $(cat /run/heim-pc-test-chpasswd-count) -eq 1")
        assert shadow_field(interrupted) == interrupted_hash

    interrupted.shutdown()
  '';
}
