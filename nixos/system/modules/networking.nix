{ config, lib, pkgs, ... }:
let
  # Real day-2 physical hosts only, not headless proof instances.
  physicalHost = lib.attrByPath [ "heimPc" "day2Activation" "enable" ] false config;
in
{
  networking.networkmanager.enable = true;

  # The physical wired desktop must not wait for NetworkManager's startup-complete
  # check before starting Tailscale, Nixer and graphical.target. These services
  # reconnect or retry independently when the link becomes available.
  # Measured boot critical path (2026-11-09): nm-online held it for 3.082 s.
  systemd.services.NetworkManager-wait-online.wantedBy = lib.mkForce [ ];
  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ ];
    allowedUDPPorts = [ ];
  };

  # Restore Pop!_OS's unattended Taildrop inbox without an additional file
  # transfer stack.  Keep the service user-scoped and restricted to alex:
  # the separate XRDP account must not consume his Taildrop messages.
  systemd.user.services.heim-taildrop-inbox = lib.mkIf config.services.tailscale.enable {
    description = "Receive Tailscale Taildrop files into Incoming/Taildrop";
    wantedBy = [ "default.target" ];
    unitConfig.ConditionUser = "alex";
    serviceConfig = {
      Type = "simple";
      ExecStartPre = "${pkgs.coreutils}/bin/mkdir -p %h/Incoming/Taildrop";
      ExecStart = "${pkgs.tailscale}/bin/tailscale file get --wait --loop --conflict=rename %h/Incoming/Taildrop";
      Restart = "on-failure";
      RestartSec = "10s";
    };
  };

  # Heimberry may wake the real wired host without touching VM network.
  networking.interfaces.enp7s0.wakeOnLan.enable =
    lib.mkIf physicalHost true;

  # Keep the NixOS hardware watchdog under systemd PID 1.
  systemd.settings.Manager.RuntimeWatchdogSec =
    lib.mkIf physicalHost "2min";

  # Small independent system-timer probe, not another long-running daemon.
  # This host remains able to check Heimberry when no graphical session runs.
  systemd.services.heimberry-deadman = lib.mkIf physicalHost {
    description = "Independent Heimberry watcher heartbeat check";
    after = [ "network.target" ];
    serviceConfig = {
      Type = "oneshot";
      User = "alex";
      Group = "users";
      StateDirectory = "heimberry-deadman";
      StateDirectoryMode = "0700";
      Environment = [
        "HOME=/home/alex"
        "PATH=${lib.makeBinPath [ pkgs.openssh pkgs.coreutils ]}"
      ];
      ExecStart = "${pkgs.python3}/bin/python3 -B ${../../../scripts/heimberry_deadman.py}";
      TimeoutStartSec = "45s";
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = "read-only";
      PrivateTmp = true;
      RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
      UMask = "0077";
    };
  };
  systemd.timers.heimberry-deadman = lib.mkIf physicalHost {
    description = "Check independent Heimberry heartbeat every five minutes";
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnBootSec = "5min";
      OnUnitInactiveSec = "5min";
      AccuracySec = "30s";
      Unit = "heimberry-deadman.service";
    };
  };
}
