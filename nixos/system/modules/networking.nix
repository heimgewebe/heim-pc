{ lib, heimPcProfile ? { }, ... }:
{
  networking.networkmanager.enable = true;
  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ ];
    allowedUDPPorts = [ ];
  };

  # The physical workstation must remain wakeable after a clean shutdown.
  # WoL packets are emitted on the LAN by the independent heimberry host.
  networking.interfaces.enp7s0.wakeOnLan.enable =
    lib.mkIf (heimPcProfile.physical or false) true;

  # The ASUS B550-F exposes an SP5100 TCO hardware watchdog at /dev/watchdog0.
  # PID 1 feeds it; a complete OS hang triggers a hardware reset.
  systemd.settings.Manager.RuntimeWatchdogSec =
    lib.mkIf (heimPcProfile.physical or false) "2min";
}
