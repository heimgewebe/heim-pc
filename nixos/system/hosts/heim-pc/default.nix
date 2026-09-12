{ self, heimPcProfile ? { }, config, lib, pkgs, ... }:
let
  sourceRevision =
    if self ? rev then self.rev
    else if self ? dirtyRev then self.dirtyRev
    else "prototype-unbound";
  sourceRevisionIsClean = builtins.match "^[0-9a-f]{40}$" sourceRevision != null;

  # Credential bootstrap is deliberately narrower than "physical": it is
  # enabled only for the current desktop-shaped, storage-backed physical
  # profiles. A future headless physical profile therefore fails closed until
  # it gets an explicit reviewed credential design.
  physicalDesktopProfile =
    (heimPcProfile.physical or false) && (heimPcProfile.desktop or false);
  persistConfigured = builtins.hasAttr "/persist" config.fileSystems;
  firstBootCredentialBootstrap = physicalDesktopProfile && persistConfigured;
  physicalPrototypeWithoutPersist =
    physicalDesktopProfile
    && !persistConfigured
    && config.fileSystems."/".device
      == "/dev/disk/by-label/NIXOS_PROTOTYPE_DO_NOT_INSTALL";
  alexPasswordOptionsAreUnset =
    let alex = config.users.users.alex;
    in builtins.all (value: value == null) [
      alex.password
      alex.hashedPassword
      alex.hashedPasswordFile
      alex.initialPassword
      alex.initialHashedPassword
    ];

  firstBootCredentialSource = builtins.readFile ./firstboot-credentials.py;
  firstBootCredentialProgram = pkgs.writeText "heim-pc-firstboot-credentials.py" (
    builtins.replaceStrings
      [ "@SOURCE_REVISION_JSON@" ]
      [ (builtins.toJSON sourceRevision) ]
      firstBootCredentialSource
  );
in
{
  imports = [ ../../modules/desktop.nix ../../modules/nvidia.nix ../../modules/audio.nix ../../modules/development.nix ../../modules/containers.nix ../../modules/grabowski.nix ../../modules/bureau.nix ../../modules/networking.nix ../../modules/backup.nix ../../modules/observability.nix ../../modules/physical-gates.nix ];
  networking.hostName = "heim-pc";
  nixpkgs.config.allowUnfree = true;

  # Canonical local interaction policy for the physical workstation.  Reuse the
  # XKB definition for the early console so LUKS and SDDM see the same layout.
  services.xserver.xkb.layout = "de";
  console.useXkbConfig = true;
  i18n.defaultLocale = "de_DE.UTF-8";
  time.timeZone = "Europe/Berlin";

  # Placeholder boot surface for heim-pc and the VM proof only. The physical
  # storage target and gate profiles replace it with storage-layout.nix, derived
  # from the production storage contract. Neither profile authorizes installation.
  fileSystems."/" = {
    device = "/dev/disk/by-label/NIXOS_PROTOTYPE_DO_NOT_INSTALL";
    fsType = "ext4";
  };
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = false;
  system.stateVersion = "26.05";

  assertions = [
    {
      assertion = !firstBootCredentialBootstrap || sourceRevisionIsClean;
      message = "physical first-boot credentials require a clean 40-hex Git-backed source revision at evaluation time";
    }
    {
      assertion = !(heimPcProfile.physical or false) || (heimPcProfile.desktop or false);
      message = "physical headless heim-pc profiles require an explicit credential design before evaluation";
    }
    {
      assertion =
        !physicalDesktopProfile
        || firstBootCredentialBootstrap
        || physicalPrototypeWithoutPersist;
      message = "physical desktop heim-pc profiles without /persist are allowed only for the explicit non-installable prototype";
    }
    {
      assertion = !firstBootCredentialBootstrap || alexPasswordOptionsAreUnset;
      message = "physical first-boot credential bootstrap forbids declarative alex password options";
    }
  ];

  # Physical hardware policy must not leak into the hardware-neutral VM proof.
  hardware.cpu.amd.updateMicrocode = heimPcProfile.physical or false;

  # Runtime identity is always observable. The explicit provenance bundle in
  # flake.nix is the fail-closed gate that rejects dirty or path-only sources.
  system.configurationRevision = sourceRevision;
  environment.etc."heim-pc/source-revision".text = sourceRevision;

  heimPc.desktop.enable = heimPcProfile.desktop or false;
  heimPc.hardware.nvidia = {
    enable = heimPcProfile.nvidia or false;
    openKernelModule = heimPcProfile.nvidiaOpen or false;
  };
  heimPc.physicalGates.enable = heimPcProfile.physicalGates or false;

  # Host policy: users.mutableUsers is intentionally global (and is the NixOS
  # default), because later password rotations must survive activation. No
  # declarative password field belongs on alex while this bootstrap exists.
  users.mutableUsers = true;
  users.users.alex = {
    isNormalUser = true;
    uid = 1000;
    extraGroups = [ "wheel" "audio" "video" "networkmanager" ];
  };

  # Console autologin belongs solely to the non-physical VM proof. A future
  # physical headless profile must define credentials explicitly instead of
  # inheriting an autologin escape hatch.
  services.getty.autologinUser = lib.mkIf (
    !(heimPcProfile.physical or false)
    && !(heimPcProfile.desktop or false)
  ) "alex";

  systemd.services.heim-pc-firstboot-credentials = lib.mkIf firstBootCredentialBootstrap {
    description = "Fail-closed one-shot Heim-PC credential bootstrap";
    after = [ "local-fs.target" "persist.mount" ];
    requires = [ "persist.mount" ];

    # systemd-user-sessions.service removes the global PAM nologin gate. Keep it
    # required and ordered behind the complete transaction, not merely behind
    # the password write. The display manager is separately held behind it too.
    before = [ "systemd-user-sessions.service" "display-manager.service" ];
    requiredBy = [ "systemd-user-sessions.service" "display-manager.service" ];

    path = [ pkgs.shadow ];
    serviceConfig = {
      Type = "oneshot";
      TimeoutStartSec = "30s";
      ExecStart = "${pkgs.python3}/bin/python3 ${firstBootCredentialProgram}";
      RemainAfterExit = true;
      User = "root";
      Group = "root";
      UMask = "0077";
    };
  };
}
