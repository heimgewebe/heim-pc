# No physical block devices, firmware or Pop!_OS writes. VM-only test.
let
  stageFlake = builtins.getFlake "path:/source";
  cfg = stageFlake.nixosConfigurations."heim-pc-stage0";
  pkgs = cfg.pkgs;
  autoFormatVMRoot = pkgs.path + "/nixos/tests/common/auto-format-root-device.nix";
  targetSystem = (cfg.extendModules {
    modules = [
      { boot.initrd.availableKernelModules = [ "virtio_pci" "virtio_blk" "virtio_scsi" ]; }
    ];
  }).config.system.build.toplevel;
  installer = cfg.config.system.build.nixos-install;
  common = {
    virtualisation.diskImage = "./stage0-fake-seagate.qcow2";
    virtualisation.diskSize = 8192;
    virtualisation.memorySize = 3072;
    virtualisation.cores = 2;
  };
in
pkgs.testers.runNixOSTest {
  name = "stage0-fake-seagate-gpt-btrfs-uefi-login-r4";
  nodes = {
    installer = { pkgs, lib, ... }: {
      imports = [
        common
        autoFormatVMRoot
      ];
      virtualisation.emptyDiskImages = [ 1024 ];
      virtualisation.rootDevice = "/dev/vdb";
      virtualisation.fileSystems."/".autoFormat = true;
      boot.initrd.systemd.enable = true;
      environment.systemPackages = [
        pkgs.gptfdisk pkgs.dosfstools pkgs.btrfs-progs pkgs.e2fsprogs
        pkgs.parted pkgs.util-linux pkgs.gnugrep pkgs.coreutils installer
      ];
      system.extraDependencies = [ targetSystem ];
      nix.settings.substituters = lib.mkForce [ ];
      services.openssh.enable = false;
    };
    target = { ... }: {
      imports = [ common /source/nixos/system/modules/stage0-no-usb.nix ];
      virtualisation.useBootLoader = true;
      virtualisation.useEFIBoot = true;
      virtualisation.useDefaultFilesystems = false;
      virtualisation.fileSystems = builtins.mapAttrs (_: fs: { device = pkgs.lib.mkForce fs.device; inherit (fs) fsType options; }) cfg.config.fileSystems;
      virtualisation.efi.keepVariables = false;
      boot.initrd.availableKernelModules = [ "virtio_pci" "virtio_blk" "virtio_scsi" ];
    };
  };
  testScript = ''
    installer.start()
    installer.wait_for_unit("multi-user.target", timeout=300)
    installer.succeed("udevadm settle", timeout=90)
    # /dev/vda is a generated 8 GiB QEMU disk, not any host device.
    installer.succeed(
      "sgdisk --zap-all /dev/vda",
      "sgdisk --clear --new=1:2048:+256M --typecode=1:ef00 --change-name=1:NIXOS2_EFI --new=2:0:+64M --typecode=2:8300 --change-name=2:NIXOS2_RECOVERY --new=3:0:0 --typecode=3:8300 --change-name=3:NIXOS_STAGE0_ROOT /dev/vda",
      "udevadm settle",
      "test -b /dev/vda1 && test -b /dev/vda2 && test -b /dev/vda3",
      "mkfs.vfat -F32 -n NIXOS2_EFI /dev/vda1",
      "mkfs.ext4 -F -L NIXOS2_RECOVERY /dev/vda2",
      "mkfs.btrfs -f -L NIXOS_STAGE0_ROOT /dev/vda3",
      "mkdir -p /mnt",
      "mount -t btrfs /dev/vda3 /mnt",
      "btrfs subvolume create /mnt/@root",
      "btrfs subvolume create /mnt/@nix",
      "btrfs subvolume create /mnt/@home",
      "btrfs subvolume create /mnt/@persist",
      "umount /mnt",
      "mount -t btrfs -o subvol=@root,compress=zstd /dev/vda3 /mnt",
      "mkdir -p /mnt/nix /mnt/home /mnt/persist /mnt/boot",
      "mount -t btrfs -o subvol=@nix,compress=zstd /dev/vda3 /mnt/nix",
      "mount -t btrfs -o subvol=@home,compress=zstd /dev/vda3 /mnt/home",
      "mount -t btrfs -o subvol=@persist,compress=zstd /dev/vda3 /mnt/persist",
      "mount -t vfat /dev/vda1 /mnt/boot",
      "findmnt -n -o FSTYPE /mnt | grep -Fx btrfs",
      "findmnt -n -o FSTYPE /mnt/boot | grep -Fx vfat",
      timeout=240
    )
    installer.succeed(
      "${installer}/bin/nixos-install --root /mnt --system ${targetSystem} --no-root-passwd --no-channel-copy < /dev/null",
      timeout=900
    )
    # Inject only a disposable VM-only salted test hash. This intentionally
    # does not replace the physical installer credential_bootstrap proof.
    # No real user secret, host /etc/shadow or physical block device is used.
    installer.succeed(
      "command -v sed >/dev/null",
      "sed -i 's|^alex:[^:]*:|alex:$6$stage0vmtestsalt$Ok9cb1Ynt/cvHAkUe0ptq8tsR1ZgEQ5blXsLLKhgkpYatvn/t17ZuIJMDE3gNT/Pxi9Eyf6205lCV9M2e6YnQ0:|' /mnt/etc/shadow",
      "test -f /mnt/etc/shadow",
      timeout=90
    )
    installer.succeed(
      "test -f /mnt/boot/EFI/BOOT/BOOTX64.EFI",
      "test -e /mnt/nix/var/nix/profiles/system",
      "test -f /mnt/etc/shadow",
      "grep -rl 'root=fstab' /mnt/boot/loader/entries/",
      "test $(blkid -s LABEL -o value /dev/vda2) = NIXOS2_RECOVERY",
      timeout=120
    )
    installer.succeed("umount -R /mnt", "sync", timeout=120)
    installer.shutdown()
    target.state_dir = installer.state_dir
    target.start()
    # QEMU OVMF -> systemd-boot -> installed Btrfs root -> VGA tty1.
    # Without SSH or any test-agent backdoor, a successful authenticated
    # user+sudo command MUST power off the virtual machine via QMP event.
    target.wait_for_console_text(r"BdsDxe: starting Boot0002", timeout=120)
    import time
    time.sleep(55)
    target.screenshot("stage0-gpt-btrfs-efi-r4-before-login")
    target.send_chars("alex\n")
    time.sleep(4)
    target.send_chars("stage0consoleboot2026\n")
    time.sleep(5)
    target.screenshot("stage0-gpt-btrfs-efi-r4-user-login")
    target.send_chars("sudo poweroff\n")
    time.sleep(4)
    target.send_chars("stage0consoleboot2026\n")
    target.wait_for_qmp_event(lambda event: event.get("event") == "SHUTDOWN", timeout=100)
    target.wait_for_shutdown()
    print("STAGE0_VIRTUAL_GPT_BTRFS_UEFI_REAL_USER_SUDO_POWEROFF_OK")
  '';
}