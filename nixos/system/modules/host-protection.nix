{ config, lib, pkgs, ... }:
let
  cfg = config.heimPc.hostProtection;
  memoryGuardPolicy = builtins.fromJSON (
    builtins.readFile ../../../config/memory-pressure-guard.v1.json
  );
  storagePressurePolicy = builtins.fromJSON (
    builtins.readFile ../../../config/storage-pressure.v1.json
  );
  memoryGuardTargetName =
    lib.removeSuffix ".service" memoryGuardPolicy.grabowski_guard.target_unit;
  maintenanceUnits = map (
    trigger: lib.removeSuffix ".service" trigger.unit
  ) storagePressurePolicy.service_triggers;
  maintenanceUnitsDeclared = builtins.all (
    unit: builtins.hasAttr unit config.systemd.user.services
  ) maintenanceUnits;

  memoryGuardSource = builtins.readFile ../../../scripts/grabowski_memory_guard.py;
  memoryGuardSystemctlMarker = "SYSTEMCTL = \"/usr/bin/systemctl\"";
  memoryGuardPatchedSource = builtins.replaceStrings
    [ memoryGuardSystemctlMarker ]
    [ "SYSTEMCTL = \"${pkgs.systemd}/bin/systemctl\"" ]
    memoryGuardSource;
  memoryGuardUsesNixSystemctl =
    lib.hasInfix memoryGuardSystemctlMarker memoryGuardSource
    && !lib.hasInfix memoryGuardSystemctlMarker memoryGuardPatchedSource;
  memoryGuardProgram =
    pkgs.writeText "heim-pc-grabowski-memory-guard.py" memoryGuardPatchedSource;

  storagePressureExec =
    "${pkgs.python3}/bin/python3 ${../../../scripts/storage_pressure_watch.py}"
    + " --policy ${../../../config/storage-pressure.v1.json}"
    + " --state %h/.local/state/heim-pc/storage-pressure-watch/latest.json"
    + lib.optionalString (!cfg.storagePressure.requestMaintenance) " --observe-only";

  # Generate administrator drop-ins in systemd's user-generator runtime tree.
  # This avoids colliding with NixOS' generated /etc/systemd/user store tree,
  # while still applying to higher-priority legacy main units in alex's home.
  legacyUserUnitGuardGenerator = pkgs.writeShellScript
    "heim-pc-host-protection-legacy-unit-guard"
    ''
      set -eu
      output="$1"
      for unit in heim-pc-storage-pressure-watch.service heim-pc-storage-pressure-watch.timer heim-pc-home-hygiene.service heim-pc-home-hygiene.timer heim-pc-coredump-retention.service heim-pc-coredump-retention.timer; do
        ${pkgs.coreutils}/bin/mkdir -p "$output/$unit.d"
        ${pkgs.coreutils}/bin/printf '%s\n' '[Unit]' 'ConditionUser=alex' "ConditionPathExists=!%h/.config/systemd/user/$unit" > "$output/$unit.d/zz-heim-pc-host-protection.conf"
      done
    '';
in
{
  options.heimPc.hostProtection = {
    enable = lib.mkEnableOption "Heim-PC physical-host pressure and hygiene protection";

    grabowskiGuard.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable the mutation-capable Grabowski memory guard. This remains false
        until the real grabowski-operator.service is declaratively present.
      '';
    };

    storagePressure.requestMaintenance = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Permit the storage-pressure observer to request maintenance units.
        NixOS stays observe-only until every declared maintenance owner exists.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion =
          !cfg.grabowskiGuard.enable
          || builtins.hasAttr memoryGuardTargetName config.systemd.services;
        message =
          "Grabowski memory guard requires its exact target system service before activation";
      }
      {
        assertion = !cfg.storagePressure.requestMaintenance || maintenanceUnitsDeclared;
        message =
          "storage-pressure maintenance requests require every declared user maintenance service";
      }
      {
        assertion = memoryGuardUsesNixSystemctl;
        message =
          "NixOS Grabowski memory guard must use the pinned Nix systemctl path";
      }
      {
        assertion = builtins.hasAttr config.users.users.alex.group config.users.groups;
        message =
          "pytest temp GC requires alex's declared primary group to exist";
      }
    ];

    # These user timers intentionally remain session-bound in this phase.
    # Starting alex's complete user manager before login via linger would grant
    # broader ambient startup than the two read-only/observe-only jobs need.
    users.users.alex.linger = false;

    # The pre-NixOS installers wrote these unit names into alex's home, which
    # outranks the declarative NixOS main units. Do not mutate the home here.
    # A user generator adds global fail-closed drop-ins at manager start/reload;
    # after deliberate legacy-file removal the NixOS inventory units take over.
    systemd.user.generators.heim-pc-host-protection-legacy-unit-guard =
      legacyUserUnitGuardGenerator;

    # Independent compressed swap: no swapfile or partition is added to either
    # production disk. 25% of 64 GiB approximates the former host swap capacity.
    zramSwap = {
      enable = true;
      algorithm = "zstd";
      memoryPercent = 25;
      priority = 1000;
    };

    # Keep oomd installed but deliberately grant no broad slice victim-selection
    # authority. architecture/runaway-guard.md excludes a competing host-wide
    # OOM killer until a separately calibrated policy is reviewed.
    systemd.oomd = {
      enable = true;
      enableRootSlice = false;
      enableSystemSlice = false;
      enableUserSlices = false;
    };

    # The existing fail-closed guard is declaratively available but dormant.
    # Enabling it before the real target unit exists is an evaluation error.
    systemd.services.heim-pc-grabowski-memory-guard =
      lib.mkIf cfg.grabowskiGuard.enable {
        description = "Protect Heim-PC from runaway Grabowski memory growth";
        after = [ "local-fs.target" memoryGuardPolicy.grabowski_guard.target_unit ];
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "simple";
          ExecStart =
            "${pkgs.python3}/bin/python3 ${memoryGuardProgram}"
            + " --policy ${../../../config/memory-pressure-guard.v1.json}"
            + " --state-dir /var/lib/heim-pc/grabowski-memory-guard --loop";
          Restart = "on-failure";
          RestartSec = "5s";
          KillMode = "mixed";
          SendSIGKILL = true;
          TimeoutStopSec = "150s";
          UMask = "0077";
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectControlGroups = true;
          ProtectClock = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          RestrictAddressFamilies = [ "AF_UNIX" ];
          StateDirectory = "heim-pc/grabowski-memory-guard";
          StateDirectoryMode = "0700";
          MemoryMax = "128M";
          MemorySwapMax = 0;
          CPUQuota = "10%";
          OOMScoreAdjust = -900;
        };
      };

    systemd.services.heim-pc-memory-pressure-snapshot = {
      description = "Collect bounded Heim-PC memory pressure evidence";
      serviceConfig = {
        Type = "oneshot";
        ExecStart =
          "${pkgs.python3}/bin/python3 ${../../../scripts/memory_pressure_snapshot.py}";
        User = "root";
        Group = "root";
        StateDirectory = "heim-pc/memory-pressure";
        StateDirectoryMode = "0700";
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        ReadWritePaths = [ "/var/lib/heim-pc/memory-pressure" ];
        MemoryMax = "128M";
        Nice = 10;
        IOSchedulingClass = "idle";
      };
    };
    systemd.timers.heim-pc-memory-pressure-snapshot = {
      description = "Collect Heim-PC memory pressure evidence every 30 seconds";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "30s";
        OnUnitActiveSec = "30s";
        AccuracySec = "2s";
        Unit = "heim-pc-memory-pressure-snapshot.service";
      };
    };

    systemd.services.heim-pc-pytest-temp-gc = {
      description = "Remove orphaned pytest garbage residues safely";
      after = [ "local-fs.target" ];
      serviceConfig = {
        Type = "oneshot";
        User = "alex";
        Group = config.users.users.alex.group;
        ExecStart =
          "${pkgs.python3}/bin/python3 ${../../../scripts/pytest_temp_gc.py} --min-age-seconds 600";
        PrivateTmp = false;
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ReadOnlyPaths = [ "/tmp" ];
        ReadWritePaths = [ "-/tmp/pytest-of-alex" ];
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        PrivateDevices = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictSUIDSGID = true;
        UMask = "0077";
        Nice = 10;
        IOSchedulingClass = "idle";
        IOSchedulingPriority = 7;
        TimeoutStartSec = "30min";
      };
    };
    systemd.timers.heim-pc-pytest-temp-gc = {
      description = "Periodically remove orphaned pytest garbage residues";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "10min";
        OnUnitActiveSec = "10min";
        AccuracySec = "1min";
        RandomizedDelaySec = "30s";
        Persistent = true;
        Unit = "heim-pc-pytest-temp-gc.service";
      };
    };

    # Observe-only by default. Maintenance requests remain disabled until every
    # policy-declared user maintenance service exists in the NixOS graph. Both
    # user timers below are session-bound because alex.linger is explicitly off.
    systemd.user.services.heim-pc-storage-pressure-watch = {
      description = "Observe lightweight root filesystem pressure";
      after = [ "default.target" ];
      unitConfig.ConditionUser = "alex";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = storagePressureExec;
        Environment = "PATH=${lib.makeBinPath [ pkgs.systemd ]}";
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        StateDirectory = "heim-pc/storage-pressure-watch";
        StateDirectoryMode = "0700";
        ProtectKernelTunables = true;
        ProtectControlGroups = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        ReadWritePaths = [ "%h/.local/state/heim-pc/storage-pressure-watch" ];
      };
    };
    systemd.user.timers.heim-pc-storage-pressure-watch = {
      description = "Observe lightweight root filesystem pressure hourly";
      wantedBy = [ "timers.target" ];
      unitConfig.ConditionUser = "alex";
      timerConfig = {
        OnBootSec = "20min";
        OnCalendar = "hourly";
        RandomizedDelaySec = "5min";
        Persistent = true;
        AccuracySec = "1min";
        Unit = "heim-pc-storage-pressure-watch.service";
      };
    };

    systemd.user.services.heim-pc-home-hygiene = {
      description = "Collect read-only Heim-PC home hygiene inventory";
      after = [ "default.target" ];
      unitConfig.ConditionUser = "alex";
      serviceConfig = {
        Type = "oneshot";
        ExecStart =
          "${pkgs.python3}/bin/python3 ${../../../scripts/home_hygiene.py}"
          + " --policy ${../../../config/home-hygiene.v1.json}"
          + " --home %h inventory"
          + " --output %h/.local/state/heim-pc/home-hygiene/latest-inventory.json";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        StateDirectory = "heim-pc/home-hygiene";
        StateDirectoryMode = "0700";
        ReadWritePaths = [ "%h/.local/state/heim-pc/home-hygiene" ];
        InaccessiblePaths = [
          "-%h/.ssh"
          "-%h/.gnupg"
          "-%h/.kube"
          "-%h/.password-store"
          "-%h/.local/share/keyrings"
        ];
        ProtectKernelTunables = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        UMask = "0077";
        TimeoutStartSec = "180s";
        MemoryMax = "512M";
        TasksMax = 64;
      };
    };
    systemd.user.timers.heim-pc-home-hygiene = {
      description = "Run read-only Heim-PC home hygiene inventory weekly";
      wantedBy = [ "timers.target" ];
      unitConfig.ConditionUser = "alex";
      timerConfig = {
        OnCalendar = "Mon *-*-* 03:30:00";
        RandomizedDelaySec = "30m";
        Persistent = true;
        AccuracySec = "5m";
        Unit = "heim-pc-home-hygiene.service";
      };
    };
  };
}