{ config, lib, ... }:
{
  # The observed Seagate Stage0 Btrfs layout is the only admissible source of
  # filesystem mounts here. Importing storage-layout.nix would incorrectly
  # require an as-yet-uncreated LUKS2/TPM2 mapper and different labels.
  # This profile is an evaluation/build candidate, NOT a productive cutover.
  imports = [
    ./stage0-no-usb.nix
    ./networking.nix
    ./nix-trust.nix
    ./nix-lifecycle.nix
    ./observability.nix
    ./day2-activation.nix
    ./grabowski-production.nix
    ./grabowski-broker-package.nix
  ];

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

  # The one-shot first-boot remote profile allowed these conveniences.
  # They are explicitly forbidden in a permanent primary-system candidate.
  services.getty.autologinUser = lib.mkForce null;
  security.sudo.wheelNeedsPassword = lib.mkForce true;

  # The base profile keeps its user manager session-bound. Only the opt-in
  # full Grabowski profile enables linger for original systemd-run --user jobs.
  # Nixer and the main operator remain independently started system services.
  users.users.alex.linger = false;

  # Reuse the existing gated executor; it provides no root service, sudo
  # policy, or unattended activation permission on its own.
  heimPc.day2Activation.enable = true;

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
        && config.security.sudo.wheelNeedsPassword
        && !(lib.any (rule:
          lib.any (command:
            builtins.elem "NOPASSWD" command.options
          ) rule.commands
        ) config.security.sudo.extraRules);
      message = "Primary candidate forbids auto-login and passwordless sudo exceptions";
    }
    {
      assertion =
        config.users.users.alex.linger == config.heimPc.grabowskiProduction.enable;
      message = "Only full Grabowski may enable the headless alex user manager";
    }
  ];
}
