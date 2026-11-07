{ config, lib, pkgs, ... }:
{
  networking.networkmanager.enable = true;
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
}
