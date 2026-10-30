{ config, lib, ... }:
let
  # Some flake proof variants intentionally omit host protection entirely.
  # Those profiles must not acquire physical NIC or watchdog policy.
  physicalHost = lib.attrByPath [ "heimPc" "hostProtection" "enable" ] false config;
in
{
  networking.networkmanager.enable = true;
  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ ];
    allowedUDPPorts = [ ];
  };

  # Enabled only on the real physical host; heimberry emits magic packets.
  networking.interfaces.enp7s0.wakeOnLan.enable =
    lib.mkIf physicalHost true;

  # PID 1 feeds the SP5100 TCO hardware watchdog.
  systemd.settings.Manager.RuntimeWatchdogSec =
    lib.mkIf physicalHost "2min";
}
