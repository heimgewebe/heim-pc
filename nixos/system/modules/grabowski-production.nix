{ config, lib, pkgs, ... }:
let
  cfg = config.heimPc.grabowskiProduction;
  packagesPresent = cfg.operatorPackage != null && cfg.brokerPackage != null;
  # Use exactly the derivations created by the reviewed, hash-bound Nix
  # definitions. Matching self-declared passthru values alone is insufficient:
  # a synthetic or substitute binary can lie about source and release IDs.
  canonicalOperator = import ./grabowski-operator-package.nix { inherit pkgs; };
  canonicalBroker = import ./grabowski-broker-package.nix {
    inherit lib pkgs;
    packageOnly = true;
  };
  expectedReleaseId = "6a6360a92be1-srcset8a29601ce885-lock264e747ad05a-contract8414018c4b85";
  expectedRevision = "6a6360a92be11d24d85e9b002bb34ac2b07672d5";
  expectedLockSha256 = "264e747ad05a536e9ca7639c6cba5a45636b93df0fe3153b4ae040ec14d456e3";
  releaseBound = packagesPresent
    && cfg.releaseId == expectedReleaseId
    && cfg.operatorPackage.outPath == canonicalOperator.outPath
    && cfg.brokerPackage.outPath == canonicalBroker.outPath
    && cfg.operatorPackage.passthru.releaseId == expectedReleaseId
    && cfg.brokerPackage.passthru.releaseId == expectedReleaseId
    && cfg.operatorPackage.passthru.sourceRevision == expectedRevision
    && cfg.brokerPackage.passthru.sourceRevision == expectedRevision
    && cfg.operatorPackage.passthru.lockSha256 == expectedLockSha256
    && cfg.brokerPackage.passthru.lockSha256 == expectedLockSha256;
  # SHA-gate the exact fail-closed candidate script bytes from Grabowski.
  # This is not R3/Captain release approval. A newer operator cannot silently
  # inherit retention authority without another byte-level gate and review.
  retentionTool = "${cfg.operatorPackage}/share/grabowski/tools/maintain_runtime_state.py";
  retentionToolSha256 = "32d061ec9b405f20ae6a4456ef53b5c1dbdaa8c1f66606bb23096a5230202cb7";

  retentionAdmit = admit && cfg.retentionEnable;
  # The root broker remains gated until real NixOS peer authorization and
  # private policy runtime acceptance. Evaluation is NOT activation approval.
  admit = cfg.enable && packagesPresent && releaseBound;
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
    retentionEnable = lib.mkEnableOption
      "five-minute Grabowski job retention using only the pinned and reviewed NixOS runtime tool";
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
        assertion = !cfg.enable || releaseBound;
        message = "Grabowski rejects mismatched operator/broker derivations, release IDs, source and runtime lock";
      }
      {
        assertion = !cfg.enable || config.services.getty.autologinUser == null;
        message = "production Grabowski must not depend on auto-login";
      }
      {
        assertion = !cfg.retentionEnable || admit;
        message = "Grabowski retention requires the admitted immutable production operator";
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

    # This service contains no policy payload: the root-owned 0600 source on
    # the *existing* Seagate @persist volume is copied atomically to /etc.
    # No Nix derivation or generated configuration ever contains policy bytes.
    # Missing/unsafe policy fails the service, preventing the socket and
    # headless operator from starting; never substitute a sample allowlist.
    systemd.services.grabowski-private-policy-install = lib.mkIf admit {
      description = "Install private root-controlled Grabowski Rootbroker policy";
      after = [ "local-fs.target" ];
      unitConfig = {
        RequiresMountsFor = "/persist";
        AssertPathIsMountPoint = "/persist";
      };
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        User = "root";
        Group = "root";
        ExecStart = "${pkgs.python3}/bin/python3 -B ${./grabowski-private-policy-install.py}";
        ConfigurationDirectory = "grabowski";
        ConfigurationDirectoryMode = "0755";
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateNetwork = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ReadOnlyPaths = [ "/persist/secrets/grabowski" ];
        ReadWritePaths = [ "/etc/grabowski" ];
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        SystemCallArchitectures = "native";
        SystemCallFilter = "~@mount @module @reboot @swap";
        SystemCallErrorNumber = "EPERM";
        CapabilityBoundingSet =
          "~CAP_SYS_ADMIN CAP_SYS_MODULE CAP_SYS_RAWIO CAP_SYS_PTRACE CAP_SYS_BOOT CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_TIME";
      };
    };

    systemd.sockets.grabowski-privileged-broker = lib.mkIf admit {
      description = "Single root-controlled Grabowski action broker socket";
      # A socket with systemd's default Before=sockets.target cannot also
      # depend on an ordinary service (which starts After=basic.target):
      # sockets.target -> basic.target -> policy.service -> this socket is a
      # boot transaction cycle. Start this privileged socket only in the
      # headless multi-user phase, after the root-only policy is installed.
      wantedBy = [ "multi-user.target" ];
      requires = [ "grabowski-private-policy-install.service" ];
      after = [ "basic.target" "grabowski-private-policy-install.service" ];
      before = [ "shutdown.target" ];
      conflicts = [ "shutdown.target" ];
      unitConfig.DefaultDependencies = false;
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
        # Only PID 1 defines this for the root-owned per-request broker.
        # The original peer check still requires exact UID/MainPID/cgroup/argv.
        Environment = [
          "GRABOWSKI_NIXOS_OPERATOR_ENTRYPOINT=${cfg.operatorPackage}/bin/grabowski-operator"
        ];
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
        # Recovery publication creates the canonical file and its sibling .lock
        # below this parent. Rootbroker policy still restricts allowed actions.
        ReadWritePaths = [ "/var/lib/grabowski" "/run/grabowski" ];
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

    # Only the canonical Nix-built runtime tool may run periodically. The
    # reviewed receipt-preflight implementation is SHA-256 gated: older
    # package pins cannot perform a reset before the receipt capacity check.
    # No worktree hygiene: the legacy canonical checkout is absent on NixOS.
    systemd.user.services.grabowski-runtime-retention = lib.mkIf retentionAdmit {
      description = "Apply bounded, receipt-audited Grabowski runtime retention";
      after = [ "default.target" ];
      unitConfig.ConditionUser = "alex";
      serviceConfig = {
        Type = "oneshot";
        ExecStartPre = [
          "${pkgs.python3}/bin/python3 -I -B -c 'import hashlib, pathlib, sys; sys.exit(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest() != sys.argv[2])' ${retentionTool} ${retentionToolSha256}"
          "${cfg.operatorPackage}/bin/python3 ${retentionTool} --provision-receipt-root"
        ];
        ExecStart = "${cfg.operatorPackage}/bin/python3 ${retentionTool} --periodic-apply --minimum-job-age-seconds 86400 --max-archive-jobs 128";
        WorkingDirectory = "%h";
        Environment = [
          "PYTHONDONTWRITEBYTECODE=1"
          "PATH=${pkgs.systemd}/bin:${pkgs.coreutils}/bin:${pkgs.git}/bin"
        ];
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        ReadWritePaths = [ "%h/.local/state/grabowski" ];
        InaccessiblePaths = [ "-%h/.ssh" "-%h/.gnupg" "-%h/.local/share/keyrings" ];
        RestrictAddressFamilies = [ "AF_UNIX" ];
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        UMask = "0077";
        MemoryMax = "512M";
        TasksMax = 50;
        TimeoutStartSec = "180s";
      };
    };
    systemd.user.timers.grabowski-runtime-retention = lib.mkIf retentionAdmit {
      description = "Run bounded Grabowski runtime retention every five minutes";
      wantedBy = [ "timers.target" ];
      unitConfig.ConditionUser = "alex";
      timerConfig = {
        OnBootSec = "3min";
        OnUnitActiveSec = "5min";
        AccuracySec = "30s";
        RandomizedDelaySec = "30s";
        Persistent = true;
        Unit = "grabowski-runtime-retention.service";
      };
    };
    systemd.services.grabowski-operator = lib.mkIf admit {
      description = "Full Grabowski operator, headless system scope";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network.target" ];
      requires = [ "grabowski-privileged-broker.socket" "grabowski-private-policy-install.service" "user@1000.service" ];
      after = [ "network.target" "user@1000.service" "grabowski-private-policy-install.service" "grabowski-privileged-broker.socket" ];
      serviceConfig = {
        Type = "simple";
        User = "alex";
        Group = "users";
        SupplementaryGroups = [ "grabowski" ];
        WorkingDirectory = "/home/alex";
        ExecStart = "${cfg.operatorPackage}/bin/grabowski-operator";
        Restart = "on-failure";
        RestartSec = "2s";
        TimeoutStartSec = "20s";
        TimeoutStopSec = "20s";
        KillMode = "mixed";
        UMask = "0077";
        # The original operator's ready-status verifies a root-owned regular
        # broker binary, root-owned private policy, protected socket AND its
        # original CLI on PATH. NixOS must supply the real immutable package.
        Environment = [
          "HOME=/home/alex"
          "XDG_RUNTIME_DIR=/run/user/1000"
          "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"
          "PYTHONUNBUFFERED=1"
          "GRABOWSKI_PRIVILEGED_BROKER=${cfg.brokerPackage}/bin/grabowski-privileged-broker"
          # Root-owned immutable Nix-store tools for the existing exact-route
          # independent R3 reviewer sandbox. Host /usr/bin does not exist on
          # NixOS; user-writable PATH shims cannot establish review provenance.
          "GRABOWSKI_BWRAP_BIN=${pkgs.bubblewrap}/bin/bwrap"
          "GRABOWSKI_CODEX_BIN=${pkgs.codex}/bin/codex"
          "PATH=${cfg.brokerPackage}/bin:${pkgs.coreutils}/bin:${pkgs.git}/bin:${pkgs.systemd}/bin:${pkgs.openssh}/bin:${pkgs.tailscale}/bin:${pkgs.procps}/bin:${pkgs.iproute2}/bin:${pkgs.tmux}/bin:/run/current-system/sw/bin"
        ];
        # The native NixOS Restic restore probe uses the existing setuid sudo
        # wrapper. NoNewPrivileges blocks it even for a passwordless operator.
        # This is the sole operator-unit override; rootbroker remains unchanged.
        NoNewPrivileges = false;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        # A native Restic check/restore needs repository locks: otherwise
        # ProtectSystem=strict remounts the HEIM_BACKUP ext4 submount read-only.
        # Optional path keeps the operator available if the backup disk is absent.
        # Nix flake evaluation also needs a writable SQLite fetcher cache.
        ReadWritePaths = [
          "-/var/lib/heim-pc-backup"
          "-/home/alex/.cache/nix"
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