{ pkgs, ... }:
{ environment.systemPackages = [ pkgs.btop ]; services.journald.extraConfig = ''SystemMaxUse=1G
MaxRetentionSec=30day''; }
