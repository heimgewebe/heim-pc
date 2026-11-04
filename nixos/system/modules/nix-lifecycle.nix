{ config, lib, pkgs, ... }:
let
  downgrade = config.heimPc.downgradeProtection;
  candidateVersions = builtins.toJSON {
    kernel = config.boot.kernelPackages.kernel.modDirVersion;
    systemd = config.systemd.package.version;
    nix = config.nix.package.version;
    nixos = config.system.nixos.version;
  };
  # Native preSwitchChecks run before activation for test/switch/boot. Read
  # the running closure, never the mutable boot-default profile or /etc.
  downgradeCheck = pkgs.writeText "heim-pc-downgrade-check.py" ''
    import json
    from pathlib import Path
    import re
    import subprocess
    import sys

    def version(value):
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value):
            raise ValueError("unsupported version: " + value)
        return tuple(int(part) for part in value.split("."))

    def output(executable):
        return subprocess.check_output(
            [str(executable), "--version"], text=True, timeout=10,
            stderr=subprocess.STDOUT,
        ).splitlines()[0]

    def check(current, candidate):
        # NixOS versions bind release/date/revision. Compare release/date only;
        # unrelated Git hashes have no chronological ordering.
        def release(value):
            match = re.fullmatch(r"([0-9]+\.[0-9]+\.[0-9]{8})\.[0-9a-f]+", value)
            if match is None:
                raise ValueError("unsupported NixOS version: " + value)
            return match.group(1)

        kernels = list((current / "kernel-modules/lib/modules").iterdir())
        if len(kernels) != 1 or not kernels[0].is_dir():
            raise ValueError("running kernel version is ambiguous or missing")
        systemd = re.fullmatch(r"systemd [0-9]+ \(([0-9.]+)\)",
                              output(current / "sw/bin/systemctl"))
        nix = re.fullmatch(r"nix \(Nix\) ([0-9.]+)", output(current / "sw/bin/nix"))
        if systemd is None or nix is None:
            raise ValueError("running systemd/Nix version is unsupported")
        running = {
            "kernel": kernels[0].name,
            "systemd": systemd.group(1),
            "nix": nix.group(1),
            "nixos": release((current / "nixos-version").read_text().strip()),
        }
        candidate = dict(candidate, nixos=release(candidate["nixos"]))
        for name, old in running.items():
            if version(candidate[name]) < version(old):
                raise ValueError(name + " downgrade denied: " + old + " -> " + candidate[name])

    if __name__ == "__main__":
        try:
            check(Path(sys.argv[1]), json.loads(sys.argv[2]))
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            sys.exit("Heim-PC pre-switch downgrade protection: " + str(exc))
  '';
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

      gc_root_readback_ok=true
      if roots="$(${pkgs.nix}/bin/nix-store --gc --print-roots 2>/dev/null)"; then
        if [ -n "$roots" ]; then
          root_count="$(printf '%s\n' "$roots" | awk 'NF { count += 1 } END { print count + 0 }')"
        else
          root_count=0
        fi
      else
        # Never reinterpret a failed or partial enumeration as trustworthy
        # evidence. Discard any partial stdout and publish a blocked audit.
        roots=""
        root_count=0
        gc_root_readback_ok=false
      fi
      root_target_is_enumerated() {
        local target="$1"
        printf '%s\n' "$roots" | awk -v target="$target" '
          {
            suffix = " -> " target
            if (length($0) > length(suffix) && substr($0, length($0) - length(suffix) + 1) == suffix) {
              found = 1
            }
          }
          END { exit found ? 0 : 1 }
        '
      }

      target_is_system_profile_generation() {
        local target="$1"
        local generation resolved
        for generation in /nix/var/nix/profiles/system-*-link; do
          [ -L "$generation" ] || continue
          if resolved="$(readlink -f -- "$generation" 2>/dev/null)" \
              && [ "$resolved" = "$target" ]; then
            return 0
          fi
        done
        return 1
      }
      store_bytes="$(du -sb /nix/store | awk '{print $1}')"

      readiness=ready
      [ -n "$running" ] || readiness=blocked-missing-running-system
      [ -n "$boot_default" ] || readiness=blocked-missing-boot-default
      last_known_good_gc_rooted=false
      last_known_good_is_system_generation=false
      if [ -z "$last_known_good" ]; then
        readiness=blocked-missing-last-known-good
      else
        case "$last_known_good" in
          /nix/store/*)
            if [ ! -e "$last_known_good" ]; then
              readiness=blocked-invalid-last-known-good
            elif ! target_is_system_profile_generation "$last_known_good"; then
              readiness=blocked-last-known-good-not-system-generation
            else
              last_known_good_is_system_generation=true
              if root_target_is_enumerated "$last_known_good"; then
                last_known_good_gc_rooted=true
              else
                readiness=blocked-unrooted-last-known-good
              fi
            fi
            ;;
          *)
            readiness=blocked-invalid-last-known-good
            ;;
        esac
      fi
      if [ "$gc_root_readback_ok" != true ]; then
        readiness=blocked-gc-root-enumeration-failed
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
        --argjson gc_root_readback_ok "$gc_root_readback_ok" \
        --argjson last_known_good_gc_rooted "$last_known_good_gc_rooted" \
        --argjson last_known_good_is_system_generation "$last_known_good_is_system_generation" \
        --argjson store_bytes "$store_bytes" \
        '{
          schema_version: 1,
          kind: $kind,
          observed_at: $observed_at,
          running_system: $running,
          boot_default_system: $boot_default,
          last_known_good_system: $last_known_good,
          gc_root_count: $gc_root_count,
          gc_root_readback_ok: $gc_root_readback_ok,
          last_known_good_gc_rooted: $last_known_good_gc_rooted,
          last_known_good_is_system_generation: $last_known_good_is_system_generation,
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
  imports = [ {
    options.heimPc.downgradeProtection = {
      enable = lib.mkEnableOption "native pre-switch core package downgrade protection";
      overrideReason = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Explicit reviewed source override for an intentional rollback; remove after use.";
      };
    };
  } ];

  system.preSwitchChecks = lib.mkIf downgrade.enable {
    heim-pc-downgrade-protection =
      if downgrade.overrideReason != null then
        "echo " + lib.escapeShellArg ("Intentional Heim-PC downgrade override: " + downgrade.overrideReason) + " >&2"
      else
        "${pkgs.python3}/bin/python3 ${downgradeCheck} /run/current-system "
        + lib.escapeShellArg candidateVersions;
  };
  assertions = [
    {
      assertion = downgrade.overrideReason == null
        || builtins.match ".*[^[:space:]].*" downgrade.overrideReason != null;
      message = "An intentional downgrade override requires a nonempty reviewed reason";
    }
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
        && !contract.budget.automatic_reclaim_authorized
        && contract.protected_generations.last_known_good_must_be_enumerated_gc_root;
      message = "Nix lifecycle must remain non-destructive until retention evidence exists";
    }
  ];

  nix.gc.automatic = lib.mkForce false;

  environment.etc."heim-pc/nix-lifecycle-contract.json".source =
    ../../production/nix-lifecycle-contract-v1.json;

  systemd.tmpfiles.rules = [
    "d /var/lib/heim-pc-nix-lifecycle 0700 root root -"
    # This namespace is shared with the fail-closed credential bootstrap.
    # Declare the parent explicitly so tmpfiles never synthesizes it as 0755.
    "d /persist/heim-pc 0700 root root -"
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
