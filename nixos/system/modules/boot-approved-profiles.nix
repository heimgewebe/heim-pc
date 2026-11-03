{ config, lib, pkgs, ... }:
let
  loaderSortKeyLine = "sort-key ${config.boot.loader.systemd-boot.sortKey}";
  # Reuses the existing NixOS systemd-boot install lifecycle. No extra
  # service, boot-time hook, firmware BootOrder manipulation or new state DB.
  bootProfileSelection = pkgs.writeShellApplication {
    name = "heim-pc-boot-profile-selection";
    runtimeInputs = [ pkgs.coreutils pkgs.gnugrep pkgs.systemd pkgs.util-linux ];
    text = ''
      set -euo pipefail
      fail() { printf '%s\n' "heim-pc approved boot: $*" >&2; exit 1; }

      # The normal system profile is allowed to advance without changing the
      # boot-approved generation. Named Nix profiles keep both pinned closures
      # (and their kernel/initrd) in systemd-boot beyond configurationLimit.
      pinned_entry() {
        local name="$1" link="/nix/var/nix/profiles/system-profiles/$name"
        local ref generation closure entry options token seen=0
        [[ -L "$link" ]] || fail "missing pinned boot profile $name"
        ref="$(readlink -- "$link")"
        [[ "$ref" =~ ^$name-([1-9][0-9]*)-link$ ]] || fail "invalid pinned profile generation $name"
        generation="''${BASH_REMATCH[1]}"
        closure="$(readlink -f -- "$link")"
        [[ "$closure" == /nix/store/*-nixos-system-* && -x "$closure/init" ]] || fail "unsafe pinned system closure $name"
        entry="nixos-$name-generation-$generation.conf"
        [[ -f "/boot/loader/entries/$entry" && ! -L "/boot/loader/entries/$entry" ]] || fail "missing pinned boot entry $entry"
        grep -qxF ${lib.escapeShellArg loaderSortKeyLine} "/boot/loader/entries/$entry" || fail "wrong sort-key for $entry"
        [[ "$(grep -c '^options ' "/boot/loader/entries/$entry" || true)" == 1 ]] || fail "ambiguous boot options in $entry"
        options="$(grep '^options ' "/boot/loader/entries/$entry")"
        read -r -a tokens <<< "''${options#options }"
        for token in "''${tokens[@]}"; do
          if [[ "$token" == init=* ]]; then
            [[ "$token" == "init=$closure/init" && "$seen" == 0 ]] || fail "pinned entry closure mismatch: $entry"
            seen=1
          fi
        done
        [[ "$seen" == 1 ]] || fail "missing pinned init in $entry"
        printf '%s\n' "$entry"
      }

      select_approved_boot() {
        local approved fallback conf=/boot/loader/loader.conf tmp line status
        approved="$(pinned_entry heim-pc-approved)"
        fallback="$(pinned_entry heim-pc-recovery)"
        [[ -f "$conf" && ! -L "$conf" ]] || fail "unsafe loader.conf"
        [[ "$(grep -c '^default ' "$conf" || true)" == 1 ]] || fail "ambiguous loader.conf default"

        # EFI LoaderEntryDefault overrides loader.conf. Keep both aligned
        # after EVERY normal NixOS bootloader regeneration. SysFail stays a
        # separately pinned, already boot-proven recovery system.
        bootctl --esp-path=/boot set-default "$approved"
        bootctl --esp-path=/boot set-sysfail "$fallback"
        tmp="$(mktemp --tmpdir=/boot/loader .heim-pc-default.XXXXXX)"
        cleanup_default() { [[ -z "$tmp" ]] || rm -f -- "$tmp"; }
        trap cleanup_default EXIT
        chmod --reference="$conf" "$tmp"
        chown --reference="$conf" "$tmp"
        while IFS= read -r line || [[ -n "$line" ]]; do
          if [[ "$line" == default\ * ]]; then
            printf 'default %s\n' "$approved"
          else
            printf '%s\n' "$line"
          fi
        done < "$conf" > "$tmp"
        sync -f "$tmp"
        mv -T -- "$tmp" "$conf"
        tmp=
        sync -f /boot/loader
        trap - EXIT

        grep -qxF "default $approved" "$conf" || fail "loader.conf did not retain approved entry"
        status="$(LC_ALL=C bootctl --esp-path=/boot status --no-pager)"
        [[ "$status" == *"Default Entry: $approved"* ]] || fail "EFI default did not retain approved entry"
        [[ "$status" == *"SysFail Entry: $fallback"* ]] || fail "EFI recovery entry did not retain pinned fallback"
      }

      # Refuse accidental writes against a missing or wrongly mounted ESP.
      [[ "$#" == 0 ]] || fail "no arguments accepted"
      [[ "$(findmnt --first-only -r -n -o FSTYPE --mountpoint /boot)" == "vfat" ]] || fail "/boot is not a mounted vfat EFI partition"
      select_approved_boot
    '';
  };
in
{
  # Reapply *after* the NixOS-generated loader.conf and any separate private
  # LUKS entry patch. EFI LoaderEntryDefault takes precedence over loader.conf.
  boot.loader.systemd-boot.extraInstallCommands =
    lib.mkAfter "${bootProfileSelection}/bin/heim-pc-boot-profile-selection";
}
