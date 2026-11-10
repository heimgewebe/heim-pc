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
}
