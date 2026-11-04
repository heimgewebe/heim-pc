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
        local name="$1"
        local link="/nix/var/nix/profiles/system-profiles/$name"
        local ref generation closure entry entry_file candidate entry_digest actual_digest options token matches=0 seen=0
        [[ -L "$link" ]] || fail "missing pinned boot profile $name"
        ref="$(readlink -- "$link")"
        [[ "$ref" =~ ^$name-([1-9][0-9]*)-link$ ]] || fail "invalid pinned profile generation $name"
        generation="''${BASH_REMATCH[1]}"
        closure="$(readlink -f -- "$link")"
        [[ "$closure" == /nix/store/*-nixos-system-* && -x "$closure/init" ]] || fail "unsafe pinned system closure $name"
        entry="nixos-$name-generation-$generation.conf"
        entry_file="/boot/loader/entries/$entry"
        if [[ ! -f "$entry_file" ]]; then
          # NixOS 26.11 names generated boot entries by their content hash,
          # not by profile/generation. Keep 26.05's names as a safe fallback.
          entry_file=""
          for candidate in /boot/loader/entries/nixos-*.conf; do
            [[ -f "$candidate" && ! -L "$candidate" ]] || continue
            [[ "''${candidate##*/}" =~ ^nixos-([0-9a-f]{64})(\+[0-9]+(-[0-9]+)?)?\.conf$ ]] || continue
            entry_digest="''${BASH_REMATCH[1]}"
            actual_digest="$(sha256sum -- "$candidate")"
            [[ "''${actual_digest%% *}" == "$entry_digest" ]] || continue
            grep -qxF "title NixOS [$name]" "$candidate" || continue
            grep -qxF ${lib.escapeShellArg loaderSortKeyLine} "$candidate" || continue
            grep -q "^version Generation $generation " "$candidate" || continue
            matches=$((matches + 1))
            [[ "$matches" == 1 ]] || fail "ambiguous pinned boot entries for $name"
            entry_file="$candidate"
          done
          [[ "$matches" == 1 ]] || fail "missing pinned boot entry for $name"
          entry="''${entry_file##*/}"
          # Boot counting adds a mutable +tries suffix. Use the stable ID
          # also returned by upstream's BootFile.from_entry().
          if [[ "$entry" =~ ^(nixos-[0-9a-f]{64})(\+[0-9]+(-[0-9]+)?)?\.conf$ ]]; then
            entry="''${BASH_REMATCH[1]}.conf"
          fi
        fi
        [[ -f "$entry_file" && ! -L "$entry_file" ]] || fail "missing pinned boot entry $entry"
        grep -qxF "title NixOS [$name]" "$entry_file" || fail "wrong profile for $entry"
        grep -qxF ${lib.escapeShellArg loaderSortKeyLine} "$entry_file" || fail "wrong sort-key for $entry"
        [[ "$(grep -c '^version ' "$entry_file" || true)" == 1 ]] || fail "ambiguous boot version in $entry"
        grep -q "^version Generation $generation " "$entry_file" || fail "wrong pinned generation in $entry"
        [[ "$(grep -c '^options ' "$entry_file" || true)" == 1 ]] || fail "ambiguous boot options in $entry"
        options="$(grep '^options ' "$entry_file")"
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
