{ lib, pkgs, ... }:
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

  # The private LUKS token is the only unlock authority for this profile, so the
  # loader-entry selector must not drift.  Pin the sort key here and reuse the
  # same value in the entry matcher instead of assuming the nixpkgs default.
  loaderSortKey = "nixos";
  loaderSortKeyLine = "sort-key ${loaderSortKey}";

  btrfsFileSystems = builtins.listToAttrs (map (subvolume: {
    name = subvolume.mountpoint;
    value = {
      device = mapperDevice;
      fsType = "btrfs";
      options = [ "subvol=${subvolume.name}" ];
    };
  }) topology.btrfs.subvolumes);

  privateStorageTool = pkgs.writeShellApplication {
    name = "heim-pc-private-storage";
    runtimeInputs = [ pkgs.coreutils pkgs.util-linux pkgs.gnugrep ];
    text = ''
      set -euo pipefail
      identity=/persist/heim-pc/private-storage-identity.env
      mapper_name=${lib.escapeShellArg mapperName}
      fail() { printf '%s\n' "heim-pc private storage: $*" >&2; exit 1; }

      load_identity() {
        [[ -f "$identity" && ! -L "$identity" ]] || fail "private identity is missing or unsafe"
        [[ "$(stat -c '%u:%g:%a' -- "$identity")" == "0:0:600" ]] || fail "private identity ownership/mode mismatch"
        schema_version=""
        efi_partuuid=""
        recovery_partuuid=""
        encrypted_partuuid=""
        file_mapper_name=""
        seen_schema=0; seen_efi=0; seen_recovery=0; seen_encrypted=0; seen_mapper=0
        while IFS='=' read -r key value; do
          [[ -n "$key" && -n "$value" ]] || fail "private identity contains an empty field"
          case "$key" in
            schema_version) (( seen_schema == 0 )) || fail "duplicate schema_version"; schema_version="$value"; seen_schema=1 ;;
            efi_partuuid) (( seen_efi == 0 )) || fail "duplicate efi_partuuid"; efi_partuuid="$value"; seen_efi=1 ;;
            recovery_partuuid) (( seen_recovery == 0 )) || fail "duplicate recovery_partuuid"; recovery_partuuid="$value"; seen_recovery=1 ;;
            encrypted_partuuid) (( seen_encrypted == 0 )) || fail "duplicate encrypted_partuuid"; encrypted_partuuid="$value"; seen_encrypted=1 ;;
            mapper_name) (( seen_mapper == 0 )) || fail "duplicate mapper_name"; file_mapper_name="$value"; seen_mapper=1 ;;
            *) fail "unexpected private identity field" ;;
          esac
        done < "$identity"
        [[ "$schema_version" == 1 && "$file_mapper_name" == "$mapper_name" ]] || fail "private identity schema/mapper mismatch"
        uuid_re='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        [[ "$efi_partuuid" =~ $uuid_re && "$recovery_partuuid" =~ $uuid_re && "$encrypted_partuuid" =~ $uuid_re ]] || fail "private PARTUUID is invalid"
        [[ "$efi_partuuid" != "$recovery_partuuid" && "$efi_partuuid" != "$encrypted_partuuid" && "$recovery_partuuid" != "$encrypted_partuuid" ]] || fail "private PARTUUIDs are not unique"
      }

      resolve_partuuid() {
        local uuid="$1" link real
        link="/dev/disk/by-partuuid/$uuid"
        [[ -L "$link" ]] || fail "private PARTUUID alias is missing"
        real="$(readlink -f -- "$link")"
        [[ -b "$real" ]] || fail "private PARTUUID alias does not resolve to a block device"
        printf '%s\n' "$real"
      }

      ensure_mount() {
        local target="$1" uuid="$2" fs="$3" expected current
        expected="$(resolve_partuuid "$uuid")"
        install -d -m 0755 -- "$target"
        if current="$(findmnt --first-only --nofsroot -rn -o SOURCE --mountpoint "$target" 2>/dev/null)"; then
          [[ -n "$current" && "$current" != *$'\n'* ]] || fail "$target mount source is invalid"
          [[ "$(readlink -f -- "$current")" == "$expected" ]] || fail "$target is mounted from the wrong device"
          return 0
        else
          rc=$?
        fi
        (( rc == 1 )) || fail "$target mount state could not be inspected"
        mount -t "$fs" "/dev/disk/by-partuuid/$uuid" "$target"
        current="$(findmnt --first-only --nofsroot -rn -o SOURCE --mountpoint "$target" 2>/dev/null)" || fail "$target mount identity could not be read"
        [[ -n "$current" && "$current" != *$'\n'* ]] || fail "$target mount source is invalid"
        [[ "$(readlink -f -- "$current")" == "$expected" ]] || fail "$target mount identity could not be verified"
      }

      patch_entries() {
        load_identity
        local boot_source expected_boot entry options_count options expected_token token seen tmp persist_target
        expected_boot="$(resolve_partuuid "$efi_partuuid")"
        boot_source="$(findmnt --first-only --nofsroot -rn -o SOURCE --mountpoint /boot 2>/dev/null)" || fail "/boot is not mounted as an exact private EFI mountpoint"
        [[ -n "$boot_source" && "$boot_source" != *$'\n'* && "$(readlink -f -- "$boot_source")" == "$expected_boot" ]] || fail "/boot is not the private EFI partition"
        expected_token="rd.luks.name=$encrypted_partuuid=$mapper_name"
        shopt -s nullglob
        entries=(/boot/loader/entries/*.conf)
        found=0
        tmp=
        cleanup_tmp() { [[ -z "$tmp" ]] || rm -f -- "$tmp"; }
        trap cleanup_tmp EXIT
        for entry in "''${entries[@]}"; do
          [[ -f "$entry" && ! -L "$entry" ]] || fail "loader entry is unsafe"
          grep -qxF ${lib.escapeShellArg loaderSortKeyLine} "$entry" || continue
          found=$((found + 1))
          options_count="$(grep -c '^options ' "$entry" || true)"
          [[ "$options_count" == 1 ]] || fail "NixOS loader entry must contain exactly one options line"
          options="$(grep '^options ' "$entry")"
          read -r -a words <<< "''${options#options }"
          kept=(); seen=0
          for token in "''${words[@]}"; do
            if [[ "$token" == rd.luks.name=*="${mapperName}" ]]; then
              [[ "$token" == "$expected_token" && "$seen" == 0 ]] || fail "conflicting private LUKS token in loader entry"
              seen=1
            else
              kept+=("$token")
            fi
          done
          new_options="options"
          for token in "''${kept[@]}"; do new_options+=" $token"; done
          new_options+=" $expected_token"
          tmp="$(mktemp --tmpdir="$(dirname -- "$entry")" .heim-pc-loader.XXXXXX)"
          chmod --reference="$entry" "$tmp"
          chown --reference="$entry" "$tmp"
          while IFS= read -r line || [[ -n "$line" ]]; do
            if [[ "$line" == options\ * ]]; then printf '%s\n' "$new_options"; else printf '%s\n' "$line"; fi
          done < "$entry" > "$tmp"
          sync -f "$tmp"
          mv -T -- "$tmp" "$entry"
          tmp=
        done
        (( found > 0 )) || fail "no NixOS systemd-boot entries found"
        sync -f /boot/loader/entries
        trap - EXIT
      }

      case "''${1:-}" in
        mount-surfaces)
          load_identity
          ensure_mount /boot "$efi_partuuid" vfat
          ensure_mount /recovery "$recovery_partuuid" ext4
          ;;
        patch-loader-entries)
          if [[ ! -e "$identity" ]]; then
            persist_target="$(findmnt -rn -o TARGET -T /persist 2>/dev/null || true)"
            [[ "$persist_target" != /persist ]] || fail "private identity is missing from mounted /persist"
            exit 0
          fi
          patch_entries
          ;;
        *) fail "expected mount-surfaces or patch-loader-entries" ;;
      esac
    '';
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

  boot.initrd.systemd.enable = true;
  boot.initrd.luks.forceLuksSupportInInitrd = true;
  fileSystems = lib.mkForce btrfsFileSystems;

  systemd.services.heim-pc-private-storage-mounts = {
    description = "Mount Heim-PC private EFI and recovery surfaces";
    unitConfig.RequiresMountsFor = [ "/persist" ];
    after = [ "local-fs.target" ];
    before = [ "multi-user.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${privateStorageTool}/bin/heim-pc-private-storage mount-surfaces";
    };
  };

  boot.loader.systemd-boot.sortKey = loaderSortKey;
  boot.loader.systemd-boot.extraInstallCommands =
    "${privateStorageTool}/bin/heim-pc-private-storage patch-loader-entries";
  boot.loader.efi.canTouchEfiVariables = false;
}
