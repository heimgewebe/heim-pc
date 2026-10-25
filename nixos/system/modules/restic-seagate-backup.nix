{ pkgs, ... }:
{
  # The Seagate host boots without the external backup disk. The mount is
  # mounted on demand and released after idle; a missing disk must never
  # redirect backups into the root filesystem.
  fileSystems."/var/lib/heim-pc-backup" = {
    device = "/dev/disk/by-uuid/9b626294-7913-4be0-88fa-96b314e96ee5";
    fsType = "ext4";
    options = [
      "nofail"
      "x-systemd.automount"
      "x-systemd.idle-timeout=60s"
      "nosuid"
      "nodev"
      "noexec"
      "noatime"
      "x-systemd.device-timeout=15s"
    ];
  };

  environment.systemPackages = [ pkgs.restic ];

  # NixOS' own Restic service replaces Pop's session-bound backup runner.
  # Credentials remain root-owned on @persist and never enter the Nix store.
  services.restic.backups."heim-pc" = {
    repository = "/var/lib/heim-pc-backup/restic/heim-pc";
    passwordFile = "/persist/secrets/restic/heim-pc-password";
    paths = [ "/home/alex" "/persist" "/etc" ];
    extraBackupArgs = [
      "--host=heim-pc-nixos"
      "--tag=nixos-seagate"
      "--exclude-file=/persist/secrets/restic/heim-pc-excludes"
    ];
    # stat(2) triggers the automount; never back up to an empty host path.
    backupPrepareCommand = ''
      test -f /var/lib/heim-pc-backup/restic/heim-pc/config
    '';
    timerConfig = {
      OnCalendar = "19:30";
      Persistent = true;
      RandomizedDelaySec = "10m";
    };
    initialize = false;
    pruneOpts = [ ];
    inhibitsSleep = true;
  };

  systemd.services."restic-backups-heim-pc" = {
    unitConfig.RequiresMountsFor = [ "/var/lib/heim-pc-backup" ];
    serviceConfig.TimeoutStartSec = "0";
  };
}