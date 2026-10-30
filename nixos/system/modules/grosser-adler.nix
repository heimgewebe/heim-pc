{ config, lib, pkgs, ... }:
let
  cfg = config.heimPc.grosserAdler;
  # Reuse the exact already-pinned MCP 1.30 Python runtime used on heim-pc.
  # The system Python 3.13 cannot import this Python 3.12 extension stack.
  adlerPython = "${import ./grabowski-operator-package.nix { inherit pkgs; }}/bin/python3";
in
{
  options.heimPc.grosserAdler.enable =
    lib.mkEnableOption "independent Großer Adler observer and ChatGPT tunnel";

  config = lib.mkIf cfg.enable {
    # The fixed read-only laboratory and append-only observer state must
    # exist even on a new, persistent NixOS home.
    systemd.tmpfiles.rules = [
      "d /home/alex/labs 0700 alex users -"
      "d /home/alex/.local/state/grosser-adler 0700 alex users -"
    ];

    # NixOS owns the unit definitions; the existing user-local unit files
    # must be retired during the controlled cutover or they shadow /etc.
    systemd.user.services."grosser-adler-mcp" = {
      description = "Großer Adler independent observer MCP";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "default.target" ];
      unitConfig.ConditionUser = "alex";
      serviceConfig = {
        Type = "simple";
        WorkingDirectory = "/home/alex/repos/grosser-adler";
        Environment = [
          "GROSSER_ADLER_STATE_ROOT=/home/alex/.local/state/grosser-adler"
          "GROSSER_ADLER_WORK_LANES_ROOT=/home/alex/.local/state/grabowski/work-lanes"
          "GROSSER_ADLER_WORKTREE_ROOT=/home/alex/repos/.grabowski-worktrees"
        ];
        EnvironmentFile = "-/home/alex/.config/grosser-adler/github.env";
        ExecStart = "${adlerPython} -B /home/alex/repos/grosser-adler/server.py --transport streamable-http --host 127.0.0.1 --port 18186";
        Restart = "on-failure";
        RestartSec = 3;
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        ReadOnlyPaths = [
          "/home/alex/repos"
          "/home/alex/.local/state/grabowski/work-lanes"
          "-/home/alex/labs"
        ];
        ReadWritePaths = [ "/home/alex/.local/state/grosser-adler" ];
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ];
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
      };
    };

    systemd.user.services."tunnel-client-grosser-adler" = {
      description = "Großer Adler MCP Tunnel";
      after = [ "network-online.target" "grosser-adler-mcp.service" ];
      wants = [ "network-online.target" "grosser-adler-mcp.service" ];
      partOf = [ "grosser-adler-mcp.service" ];
      wantedBy = [ "default.target" ];
      unitConfig = {
        ConditionUser = "alex";
        StartLimitIntervalSec = "5min";
        StartLimitBurst = 3;
      };
      serviceConfig = {
        Type = "simple";
        EnvironmentFile = "/home/alex/.config/tunnel-client/grabowski-runtime.env";
        WorkingDirectory = "/home/alex";
        ExecStartPre = "${pkgs.curl}/bin/curl --fail --silent --show-error --retry 12 --retry-delay 3 --retry-connrefused --connect-timeout 2 --max-time 55 http://127.0.0.1:18186/healthz";
        # Dedicated tunnel profile/binary remains first-party managed outside Nix.
        ExecStart = "/home/alex/.local/bin/tunnel-client run --profile grosser-adler";
        Restart = "on-failure";
        RestartSec = 5;
        TimeoutStartSec = 90;
        TimeoutStopSec = 20;
        KillMode = "mixed";
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
        RestrictSUIDSGID = true;
        LockPersonality = true;
      };
    };
  };
}
