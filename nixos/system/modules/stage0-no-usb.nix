{ pkgs, ... }:
let
  # Explicitly nonproduction: unencrypted Btrfs on the independent Seagate.
  # The installer must first validate that this label belongs uniquely to
  # the freshly identified Seagate partition. Never use kernel NVMe indices.
  rootDevice = "/dev/disk/by-label/NIXOS_STAGE0_ROOT";
  subvolume = name: {
    device = rootDevice;
    fsType = "btrfs";
    options = [ "subvol=${name}" "compress=zstd" ];
  };
in
{
  # Stage0 is deliberately separate from heim-pc-storage-target and cannot
  # satisfy, impersonate or bypass its production installation contracts.
  networking.hostName = "heim-pc-stage0";
  networking.networkmanager.enable = true;
  services.openssh.enable = false;
  services.xserver.enable = false;

  # Headless console first boot, with NO passwordless login and NO default
  # password in the source or Nix store. Before boot the installer must set a
  # strong private password for alex in the installed /etc/shadow.
  users.mutableUsers = true;
  users.users.alex = {
    isNormalUser = true;
    uid = 1000;
    extraGroups = [ "wheel" "networkmanager" ];
  };
  security.sudo.wheelNeedsPassword = true;

  # Never share or rewrite Pop!_OS's WD EFI partition or firmware entries.
  boot.loader.systemd-boot.enable = true;
  boot.loader.systemd-boot.editor = false;
  boot.loader.systemd-boot.configurationLimit = 3;
  boot.loader.efi.efiSysMountPoint = "/boot";
  boot.loader.efi.canTouchEfiVariables = false;

  # Conservative graphical fallback on the physical NVIDIA-only workstation;
  # Stage0 is intentionally text-only and does not load a GPU display manager.
  boot.kernelParams = [ "nomodeset" ];
  boot.blacklistedKernelModules = [ "nouveau" ];
  boot.initrd.availableKernelModules = [ "nvme" "ahci" "xhci_pci" ];

  fileSystems."/" = subvolume "@root";
  fileSystems."/nix" = subvolume "@nix";
  fileSystems."/home" = subvolume "@home";
  fileSystems."/persist" = subvolume "@persist";
  fileSystems."/boot" = {
    device = "/dev/disk/by-label/NIXOS2_EFI";
    fsType = "vfat";
    options = [ "umask=0077" ];
  };
  swapDevices = [ ];

  i18n.defaultLocale = "de_DE.UTF-8";
  console.keyMap = "de";
  time.timeZone = "Europe/Berlin";
  nix.settings.experimental-features = [ "nix-command" "flakes" ];
  environment.systemPackages = with pkgs; [ git vim pciutils ];

  system.stateVersion = "26.05";
}
