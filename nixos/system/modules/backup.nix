{ pkgs, ... }:
{ environment.systemPackages = [ pkgs.restic ]; systemd.tmpfiles.rules = [ "d /var/lib/heim-pc/backup 0700 root root -" ]; }
