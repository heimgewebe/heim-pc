{ config, lib, ... }:
{
  networking.networkmanager.enable = true;
  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ ];
    allowedUDPPorts = [ ];
  };

  # Enabled only on the actual physical host, not on proof/VM profiles.
  # The independent heimberry host sends LAN magic packets.
  networking.interfaces.enp7s0.wakeOnLan.enable =
    lib.mkIf config.heimPc.hostProtection.enable true;

  # PID 1 feeds the physical SP5100 TCO hardware watchdog.
  systemd.settings.Manager.RuntimeWatchdogSec =
    lib.mkIf config.heimPc.hostProtection.enable "2min";
}
