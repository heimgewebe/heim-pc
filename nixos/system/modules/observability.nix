{ options, pkgs, ... }:
let
  journalLimits = {
    SystemMaxUse = "1G";
    MaxRetentionSec = "30day";
  };
in
{
  environment.systemPackages = [ pkgs.btop ];

  # NixOS 26.11 replaces extraConfig with RFC42-style settings.Journal.
  # Keep the exact values on 26.05 without changing the running generation.
  services.journald =
    if options.services.journald ? settings then {
      settings.Journal = journalLimits;
    } else {
      extraConfig = "SystemMaxUse=${journalLimits.SystemMaxUse}\nMaxRetentionSec=${journalLimits.MaxRetentionSec}";
    };
}
