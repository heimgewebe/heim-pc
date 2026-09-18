{ lib, pkgs, ... }:
let
  contract = builtins.fromJSON (builtins.readFile ../../production/nix-lifecycle-contract-v1.json);
  markerPath = contract.protected_generations.last_known_good_marker;
  evidencePath = contract.read_only_audit.evidence_path;
  auditTool = pkgs.writeShellApplication {
    name = "heim-pc-nix-lifecycle-audit";
    runtimeInputs = with pkgs; [ coreutils findutils gawk jq nix ];
    text = ''
      set -euo pipefail
      umask 077

      state_dir=/var/lib/heim-pc-nix-lifecycle
      output=${lib.escapeShellArg evidencePath}
      marker=${lib.escapeShellArg markerPath}
      install -d -m 0700 -o root -g root "$state_dir"

      resolve_link() {
        local path="$1"
        if [ -L "$path" ]; then
          readlink -f -- "$path"
        else
          printf '%s' ""
        fi
      }

      running="$(resolve_link /run/current-system)"
      boot_default="$(resolve_link /nix/var/nix/profiles/system)"
      last_known_good=""
      if [ -f "$marker" ] && [ ! -L "$marker" ]; then
        last_known_good="$(head -n 1 -- "$marker")"
      fi

      roots="$(${pkgs.nix}/bin/nix-store --gc --print-roots 2>/dev/null || true)"
      if [ -n "$roots" ]; then
        root_count="$(printf '%s\n' "$roots" | awk 'NF { count += 1 } END { print count + 0 }')"
      else
        root_count=0
      fi
      store_bytes="$(du -sb /nix/store | awk '{print $1}')"

      readiness=ready
      [ -n "$running" ] || readiness=blocked-missing-running-system
      [ -n "$boot_default" ] || readiness=blocked-missing-boot-default
      [ -n "$last_known_good" ] || readiness=blocked-missing-last-known-good
      if [ -n "$last_known_good" ] && [ ! -e "$last_known_good" ]; then
        readiness=blocked-invalid-last-known-good
      fi

      tmp="$(mktemp "$state_dir/.latest.XXXXXX")"
      trap 'rm -f -- "$tmp"' EXIT
      jq -n \
        --arg kind heim_pc.nixos_store_lifecycle_audit \
        --arg observed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg running "$running" \
        --arg boot_default "$boot_default" \
        --arg last_known_good "$last_known_good" \
        --arg readiness "$readiness" \
        --argjson gc_root_count "$root_count" \
        --argjson store_bytes "$store_bytes" \
        '{
          schema_version: 1,
          kind: $kind,
          observed_at: $observed_at,
          running_system: $running,
          boot_default_system: $boot_default,
          last_known_good_system: $last_known_good,
          gc_root_count: $gc_root_count,
          store_bytes: $store_bytes,
          automatic_gc_authorized: false,
          readiness: $readiness
        }' > "$tmp"
      chmod 0600 "$tmp"
      sync -f "$tmp"
      mv -T -- "$tmp" "$output"
      sync -f "$state_dir"
      trap - EXIT
    '';
  };
in
{
  assertions = [
    {
      assertion =
        contract.schema_version == 1
        && contract.kind == "heim_pc.nixos_store_lifecycle_contract";
      message = "Nix lifecycle module requires lifecycle contract v1";
    }
    {
      assertion =
        !contract.automatic_gc
        && !contract.delete_older_than_allowed
        && !contract.budget.automatic_reclaim_authorized;
      message = "Nix lifecycle must remain non-destructive until retention evidence exists";
    }
  ];

  nix.gc.automatic = lib.mkForce false;

  environment.etc."heim-pc/nix-lifecycle-contract.json".source =
    ../../production/nix-lifecycle-contract-v1.json;

  systemd.tmpfiles.rules = [
    "d /var/lib/heim-pc-nix-lifecycle 0700 root root -"
    "d /persist/heim-pc/nix-lifecycle 0700 root root -"
  ];

  systemd.services.heim-pc-nix-lifecycle-audit = {
    description = "Audit protected Nix generations and store budget without garbage collection";
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${auditTool}/bin/heim-pc-nix-lifecycle-audit";
      NoNewPrivileges = true;
      PrivateTmp = true;
      PrivateDevices = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectControlGroups = true;
      RestrictSUIDSGID = true;
      RestrictRealtime = true;
      LockPersonality = true;
      ReadWritePaths = [ "/var/lib/heim-pc-nix-lifecycle" ];
    };
  };

  systemd.timers.heim-pc-nix-lifecycle-audit = {
    description = "Periodic read-only Nix lifecycle audit";
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnCalendar = "daily";
      RandomizedDelaySec = "30m";
      Persistent = true;
      Unit = "heim-pc-nix-lifecycle-audit.service";
    };
  };
}
