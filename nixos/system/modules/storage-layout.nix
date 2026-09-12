{ lib, ... }:
let
  contract = builtins.fromJSON (builtins.readFile ../../production/contract-v1.json);
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

  # PARTLABELs describe public topology. Exact PARTUUIDs remain private and
  # are enforced by the installer before this closure is ever booted.
  partitionDevice = partition: "/dev/disk/by-partlabel/${partition.label}";

  surfaceFileSystems = {
    ${efi.mountpoint} = {
      device = partitionDevice efi;
      fsType = efi.filesystem;
    };
    ${recovery.mountpoint} = {
      device = partitionDevice recovery;
      fsType = recovery.filesystem;
    };
  };
in
{
  assertions = [
    {
      assertion = contract.schema_version == 1
        && contract.kind == "heim_pc.nixos_production_storage_contract";
      message = "storage target requires production storage contract v1";
    }
    {
      assertion = topology.partition_table == "gpt"
        && topology.partition_identity_policy == "private-identity-contract-assigned-partuuid";
      message = "storage target requires the production GPT topology";
    }
    {
      assertion = efi.filesystem == "vfat"
        && efi.mountpoint == "/boot"
        && recovery.filesystem == "ext4"
        && recovery.mountpoint == "/recovery"
        && encrypted.encryption == "luks2"
        && encrypted.filesystem == "btrfs"
        && topology.luks.version == 2;
      message = "storage target must stay bound to isolated EFI/recovery/LUKS2/Btrfs production semantics";
    }
  ];

  boot.initrd.luks.devices.${mapperName}.device = partitionDevice encrypted;

  fileSystems = lib.mkForce (btrfsFileSystems // surfaceFileSystems);

  # This closure describes only the isolated production boot/storage topology.
  # Runtime target selection remains a separate exact by-id gate; this module
  # cannot partition/format disks or mutate EFI variables by itself.
  boot.loader.efi.canTouchEfiVariables = false;
}
