{ config, lib, ... }:
let
  cfg = config.heimPc.grabowskiProduction;
  packagesPresent = cfg.operatorPackage != null && cfg.brokerPackage != null;
  # Neither the Pop!_OS venv nor demo binary can be a production package.
  admit = cfg.enable && packagesPresent;
in
{
  options.heimPc.grabowskiProduction = {
    enable = lib.mkEnableOption
      "full system-level Grabowski and its single privileged broker (never the demo)";
    operatorPackage = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = "Pinned Nix-built package providing bin/grabowski-operator";
    };
    brokerPackage = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = "Pinned NixOS-compatible package providing bin/grabowski-privileged-broker";
    };
    releaseId = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Non-secret, source-bound expected runtime release identity";
    };
  };

  config = {
    assertions = [
      {
        assertion = !cfg.enable || packagesPresent;
        message = "Grabowski requires Nix-built operator and broker packages; Pop venv/demo forbidden";
      }
      {
        assertion = !cfg.enable || (
          cfg.releaseId != null
          && builtins.match "^[a-zA-Z0-9._-]+$" cfg.releaseId != null
        );
        message = "Grabowski needs a pinned runtime release identity";
      }
      {
        assertion = !cfg.enable || config.services.getty.autologinUser == null;
        message = "production Grabowski must not depend on auto-login";
      }
    ];

    # SocketGroup defines authorized local callers; it is not an unrestricted
    # root or agent capability. Admission must additionally validate the
    # broker's peer/UID/MainPID checks and root-only private allowlist.
    users.groups = lib.mkIf admit { grabowski = { }; };
    # The interactive alex account must NOT acquire the broker socket group.
    # Only the canonical system service gets this supplementary group.
    systemd.tmpfiles.rules = lib.optionals admit [
      "d /run/grabowski 0750 root grabowski -"
    ];

    systemd.sockets.grabowski-privileged-broker = lib.mkIf admit {
      description = "Single root-controlled Grabowski action broker socket";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = "/run/grabowski/privileged-broker.sock";
        Accept = true;
        SocketMode = "0660";
        SocketGroup = "grabowski";
        DirectoryMode = "0750";
        RemoveOnStop = true;
      };
    };

    systemd.services."grabowski-privileged-broker@" = lib.mkIf admit {
      description = "Grabowski per-request root-owned action broker";
      serviceConfig = {
        Type = "oneshot";
        User = "root";
        Group = "root";
        ExecStart = "${cfg.brokerPackage}/bin/grabowski-privileged-broker";
        StandardInput = "socket";
        StandardOutput = "socket";
        StandardError = "journal";
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = "tmpfs";
        ProtectSystem = "strict";
        # No direct mount, kernel module, raw-I/O or reboot capability in the
        # request broker. Actions requiring broader authority must be reviewed
        # and delegated explicitly; NoNewPrivileges alone is insufficient.
        CapabilityBoundingSet =
          "~CAP_SYS_ADMIN CAP_SYS_MODULE CAP_SYS_RAWIO CAP_SYS_PTRACE CAP_SYS_BOOT CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_TIME CAP_SYS_TTY_CONFIG";
        SystemCallFilter = "~@mount @module @reboot @swap";
        SystemCallErrorNumber = "EPERM";
        RestrictNamespaces = true;
        BindReadOnlyPaths = [
          "-/home/alex/repos"
          "-/home/alex/.local/state/grabowski/recovery/last-server-recovery.json"
          "-/home/alex/.local/state/grabowski/operator-kill-switch"
        ];
        # The broker itself requires a root-owned 0700 state directory.
        # Systemd creates it before executing the trusted request instance.
        StateDirectory = "grabowski/privileged-broker";
        StateDirectoryMode = "0700";
        ReadWritePaths = [ "/var/lib/grabowski/privileged-broker" "/run/grabowski" ];
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_NETLINK" ];
        TimeoutStartSec = "3700";
      };
    };

    systemd.services.grabowski-operator = lib.mkIf admit {
      description = "Full Grabowski operator, headless system scope";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network.target" ];
      requires = [ "grabowski-privileged-broker.socket" ];
      after = [ "network.target" "grabowski-privileged-broker.socket" ];
      serviceConfig = {
        Type = "simple";
        User = "alex";
        Group = "alex";
        SupplementaryGroups = [ "grabowski" ];
        WorkingDirectory = "/home/alex";
        ExecStart = "${cfg.operatorPackage}/bin/grabowski-operator";
        Restart = "on-failure";
        RestartSec = "2s";
        TimeoutStartSec = "20s";
        TimeoutStopSec = "20s";
        KillMode = "mixed";
        UMask = "0077";
        Environment = [ "HOME=/home/alex" "PYTHONUNBUFFERED=1" ];
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        ReadWritePaths = [
          "-/home/alex/.local/state/grabowski"
          "-/home/alex/.local/state/bureau"
          "-/home/alex/repos"
          "-/home/alex/grabowski-workspace"
          "-/home/alex/worktrees"
        ];
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;
        LimitCORE = 0;
        SystemCallArchitectures = "native";
      };
    };
  };
}