{ config, lib, pkgs, ... }:

# Restore the canonical cross-device workspace from the pre-NixOS host.
# The OAuth configuration is mutable user data, never a Nix store input.
{
  config = lib.mkIf config.heimPc.desktop.enable {
    users.users.alex.packages = [ pkgs.rclone ];

    systemd.user.services.google-drive-rclone = {
      description = "Google Drive shared workspace (rclone)";
      wantedBy = [ "default.target" ];
      unitConfig = {
        ConditionUser = "alex";
        ConditionPathExists = "%h/.config/rclone/rclone.conf";
      };
      serviceConfig = {
        Type = "notify";
        UMask = "0077";
        # NixOS provides privileged FUSE helpers via its wrapper directory.
        Environment = "PATH=/run/wrappers/bin:${lib.makeBinPath [ pkgs.coreutils pkgs.fuse3 ]}";
        ExecStartPre = "${pkgs.coreutils}/bin/mkdir -p %h/GDrive";
        ExecStart = lib.concatStringsSep " " [
          "${pkgs.rclone}/bin/rclone mount gdrive: %h/GDrive"
          "--config %h/.config/rclone/rclone.conf"
          "--cache-dir %h/.cache/rclone"
          "--vfs-cache-mode full"
          "--vfs-cache-max-size 20G"
          "--vfs-cache-min-free-space 10G"
          "--vfs-cache-max-age 24h"
        ];
        Restart = "on-failure";
        RestartSec = "60s";
        TimeoutStartSec = "120s";
        TimeoutStopSec = "120s";
      };
    };
  };
}
