{ config, lib, pkgs, ... }:
let
  # Keep the already-reviewed comparison and its documentation in the same
  # immutable target closure. No live checkout, network or mutable user path.
  integrationInventory = pkgs.runCommand "heim-pc-integration-inventory" {} ''
    mkdir -p "$out/scripts"
    cp ${../../../scripts/generate_nixos_program_inventory.py} "$out/scripts/generate_nixos_program_inventory.py"
    cp ${../../../README.md} "$out/README.md"
  '';
in
{
  # The observed Seagate Stage0 Btrfs layout is the only admissible source of
  # filesystem mounts here. Importing storage-layout.nix would incorrectly
  # require an as-yet-uncreated LUKS2/TPM2 mapper and different labels.
  # This profile is an evaluation/build candidate, NOT a productive cutover.
  imports = [
    ./stage0-no-usb.nix
    ./boot-approved-profiles.nix
    ./brotli-security.nix
    ./networking.nix
    ./nix-trust.nix
    ./nix-lifecycle.nix
    ./observability.nix
    ./day2-activation.nix
    ./grabowski-production.nix
    ./grabowski-broker-package.nix
  ];

  # This is the physically booted Seagate host; the generic hosts/heim-pc
  # keymap configuration is not imported here. Load Stage0's existing "de"
  # console keymap in the initrd, before any console password prompt.
  console.earlySetup = true;
  # SDDM/X11 must use the same German keyboard as early console and KDE.
  services.xserver.xkb.layout = "de";

  # The WD_BLACK remains the independent bootable Pop!_OS fallback. Expose all
  # its data partitions without writes, journal replay or boot-time dependency.
  # The swap partition is intentionally not activated.
  fileSystems."/mnt/wd-black/pop-os" = {
    device = "/dev/disk/by-uuid/d25d44aa-5334-4b9d-9cc2-2475e9123776";
    fsType = "ext4";
    options = [ "ro" "noload" "nosuid" "nodev" "nofail" "x-systemd.automount" ];
    noCheck = true;
  };
  fileSystems."/mnt/wd-black/efi" = {
    device = "/dev/disk/by-uuid/78FD-6130";
    fsType = "vfat";
    options = [ "ro" "nofail" "x-systemd.automount" "uid=1000" "gid=100" "umask=0077" ];
    noCheck = true;
  };
  fileSystems."/mnt/wd-black/recovery" = {
    device = "/dev/disk/by-uuid/78FD-60C8";
    fsType = "vfat";
    options = [ "ro" "nofail" "x-systemd.automount" "uid=1000" "gid=100" "umask=0077" ];
    noCheck = true;
  };

  networking.hostName = lib.mkForce "heim-pc";
  networking.firewall.enable = true;

  # Accessible independently of SDDM, a user manager, or a local login.
  # SSH authorized_keys must be installed privately in the retained @home;
  # no public/private login keys are embedded in this Nix derivation.
  services.openssh = {
    enable = lib.mkForce true;
    openFirewall = true;
    settings = {
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
      PermitRootLogin = "no";
      PermitEmptyPasswords = false;
      PubkeyAuthentication = true;
      AllowUsers = [ "alex" ];
    };
  };

  # Deliberately no tailscale up/auth key here. NixOS must be separately
  # enrolled; Pop!_OS's machine identity is not copied or shared.
  services.tailscale.enable = true;

  # Monitor the actual Seagate workstation disks via native SMART health checks.
  services.smartd.enable = true;
  # This host runs KDE/Wayland. The xmessage default targets DISPLAY=":",
  # which is not a usable Wayland desktop notification channel.
  services.smartd.notifications.x11.enable = false;
  services.smartd.notifications.systembus-notify.enable = true;
  # SMART polling must not wake sleeping USB backup or fallback disks.
  services.smartd.defaults.autodetected = "-a -n standby";

  # The one-shot first-boot remote profile allowed these conveniences.
  # They are explicitly forbidden in a permanent primary-system candidate.
  services.getty.autologinUser = lib.mkForce null;
  security.sudo.wheelNeedsPassword = lib.mkForce true;
  # Preserve the already active Gen19 owner-specific passwordless sudo rule.
  # General wheel sudo still requires a password.
  security.sudo.extraRules = [{
    users = [ "alex" ];
    commands = [{ command = "ALL"; options = [ "NOPASSWD" ]; }];
  }];

  # The base profile keeps its user manager session-bound. Only the opt-in
  # full Grabowski profile enables linger for original systemd-run --user jobs.
  # Nixer and the main operator remain independently started system services.
  users.users.alex.linger = false;

  # Reuse the existing gated executor; it provides no root service, sudo
  # policy, or unattended activation permission on its own.
  heimPc.day2Activation.enable = true;

  # NixOS supplies the exact target closure and switch action as $1/$2.
  # Advisory only: a structural observation is not a release/health gate.
  # Keep recovery and boot working even when the inventory is unavailable.
  system.preSwitchChecks.heim-pc-integration-inventory =
    lib.mkIf config.heimPc.grabowskiProduction.enable ''
      case "$2" in
        switch|test|boot)
          if [ -e /run/current-system ]; then
            echo "Heim-PC integration inventory ($2):"
            if ! ${pkgs.coreutils}/bin/timeout --kill-after=2s 15s \
                ${pkgs.python3}/bin/python3 -I -B \
                ${integrationInventory}/scripts/generate_nixos_program_inventory.py \
                --baseline-closure /run/current-system --compare-closure "$1"; then
              echo "WARNING: Heim-PC integration inventory unavailable; inspect rollout separately." >&2
            fi
          else
            echo "Heim-PC integration inventory: no active baseline; comparison skipped."
          fi
          ;;
      esac
      true
    '';

  # Consume the already-computed catalog CI report. The timer remains native
  # and only alex's user manager may register proposal-only Bureau candidates.
  systemd.user.services.systemkatalog-drift-watch =
    lib.mkIf config.heimPc.grabowskiProduction.enable {
      description = "Consume central Systemkatalog CI drift report";
      unitConfig.ConditionUser = "alex";
      serviceConfig = {
        Type = "oneshot";
        WorkingDirectory = "/home/alex";
        Environment = [
          "HOME=/home/alex"
          "PATH=${lib.makeBinPath [ pkgs.gh pkgs.coreutils pkgs.git pkgs.openssh pkgs.systemd pkgs.python3 ]}:/home/alex/.local/bin:/run/current-system/sw/bin"
        ];
        ExecStart = "${pkgs.python3}/bin/python3 -I -B ${../../../scripts/systemkatalog_drift_watch.py}";
        TimeoutStartSec = "180s";
        Nice = 10;
      };
    };

  systemd.user.timers.systemkatalog-drift-watch =
    lib.mkIf config.heimPc.grabowskiProduction.enable {
      description = "Hourly Systemkatalog CI drift report consumer";
      unitConfig.ConditionUser = "alex";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = "hourly";
        Persistent = true;
        RandomizedDelaySec = "5min";
        Unit = "systemkatalog-drift-watch.service";
      };
    };

  assertions = [
    {
      assertion = config.fileSystems."/".device == "/dev/disk/by-label/NIXOS_STAGE0_ROOT";
      message = "Seagate primary candidate must retain the physically tested Btrfs root";
    }
    {
      assertion = config.fileSystems."/boot".device == "/dev/disk/by-label/NIXOS2_EFI";
      message = "Seagate primary candidate must never select the protected WD EFI";
    }
    {
      assertion = !config.boot.loader.efi.canTouchEfiVariables;
      message = "Candidate evaluations and activations must not edit UEFI BootOrder";
    }
    {
      assertion = config.services.getty.autologinUser == null
        && config.security.sudo.wheelNeedsPassword;
      message = "Primary candidate forbids auto-login and blanket passwordless wheel sudo";
    }
    {
      assertion =
        config.users.users.alex.linger == config.heimPc.grabowskiProduction.enable;
      message = "Only full Grabowski may enable the headless alex user manager";
    }
  ];
}
