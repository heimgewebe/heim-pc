{ lib, ... }:
let
  contract = builtins.fromJSON (builtins.readFile ../../rehearsal/contract-v1.json);
  topology = contract.topology;
  partitionByRole = role:
    let
      matches = builtins.filter (partition: partition.role == role) topology.partitions;
    in
    if builtins.length matches == 1 then
      builtins.head matches
    else
      throw "storage contract must contain exactly one ${role} partition";

  efi = partitionByRole "efi-system-partition";
  recovery = partitionByRole "recovery-surface";
  encrypted = partitionByRole "encrypted-system";
  mapperName = topology.luks.mapper_name;
  mapperDevice = "/dev/mapper/${mapperName}";

  btrfsFileSystems = builtins.listToAttrs (map (subvolume: {
    name = subvolume.mountpoint;
    value = {
      device = mapperDevice;
      fsType = "btrfs";
      options = [ "subvol=${subvolume.name}" ];
    };
  }) topology.btrfs.subvolumes);

  surfaceFileSystems = {
    ${efi.mountpoint} = {
      device = "/dev/disk/by-partlabel/${efi.label}";
      fsType = efi.filesystem;
    };
    ${recovery.mountpoint} = {
      device = "/dev/disk/by-partlabel/${recovery.label}";
      fsType = recovery.filesystem;
    };
  };
in
{
  assertions = [
    {
      assertion = contract.schema_version == 1
        && contract.kind == "heim_pc.nixos_storage_rehearsal_contract";
      message = "storage target requires rehearsal contract v1";
    }
    {
      assertion = topology.partition_table == "gpt";
      message = "storage target requires the rehearsed GPT topology";
    }
    {
      assertion = efi.filesystem == "vfat"
        && efi.mountpoint == "/boot"
        && recovery.filesystem == "ext4"
        && recovery.mountpoint == "/recovery"
        && encrypted.encryption == "luks2"
        && encrypted.filesystem == "btrfs"
        && topology.luks.version == 2;
      message = "storage target must stay bound to EFI/recovery/LUKS2/Btrfs rehearsal semantics";
    }
  ];

  boot.initrd.luks.devices.${mapperName}.device =
    "/dev/disk/by-partlabel/${encrypted.label}";

  fileSystems = lib.mkForce (btrfsFileSystems // surfaceFileSystems);

  # This closure describes the rehearsed install/boot target only. It still
  # cannot mutate EFI variables by itself and does not partition or format disks.
  boot.loader.efi.canTouchEfiVariables = false;
}
