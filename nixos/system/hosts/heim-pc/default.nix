{ self, heimPcProfile ? { }, lib, ... }:
let
  sourceRevision =
    if self ? rev then self.rev
    else if self ? dirtyRev then self.dirtyRev
    else "prototype-unbound";
in
{
  imports = [ ../../modules/desktop.nix ../../modules/nvidia.nix ../../modules/audio.nix ../../modules/development.nix ../../modules/containers.nix ../../modules/grabowski.nix ../../modules/bureau.nix ../../modules/networking.nix ../../modules/backup.nix ../../modules/observability.nix ../../modules/physical-gates.nix ];
  networking.hostName = "heim-pc";
  nixpkgs.config.allowUnfree = true;

  # Placeholder boot surface for heim-pc and the VM proof only. The physical
  # storage target and gate profiles replace it with storage-layout.nix, derived
  # from the same rehearsal contract. Neither profile authorizes installation.
  fileSystems."/" = {
    device = "/dev/disk/by-label/NIXOS_PROTOTYPE_DO_NOT_INSTALL";
    fsType = "ext4";
  };
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = false;
  system.stateVersion = "26.05";

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

  # A secure first-boot credential bootstrap remains a pre-bare-metal gate.
  # No password or password hash is embedded in this build-only source.
  users.users.alex = { isNormalUser = true; extraGroups = [ "wheel" "audio" "video" "networkmanager" ]; };
  services.getty.autologinUser = lib.mkIf (!(heimPcProfile.desktop or false)) "alex";
}
