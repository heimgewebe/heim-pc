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
    # Preserve enrolled VPN identity, network state and host recovery metadata.
    # Do not include systemd coredumps or disposable root caches.
    paths = [
      "/home/alex" "/persist" "/etc"
      "/var/lib/tailscale" "/var/lib/NetworkManager"
      "/var/lib/nixos" "/var/lib/grabowski"
    ];
    extraBackupArgs = [
      "--host=heim-pc-nixos"
      "--tag=nixos-seagate"
      # A concurrent verified Restic repository check can hold the exclusive lock.
      # Without a bounded wait the 19:30 backup fails immediately with code 11.
      "--retry-lock=30m"
      "--exclude-file=/persist/secrets/restic/heim-pc-excludes"
      # XRDP drive redirection can be a user-only FUSE mount that root cannot
      # stat. Never turn one unreadable transient session mount into backup
      # exit 3; exclude only this path, not the rest of /home/alex.
      # A private exclude file may contain negations, so this hard rule
      # must follow it. The plaintext-dump rule must remain LAST.
      "--exclude-file=${pkgs.writeText "heim-pc-restic-hard-xrdp-excludes" "/home/alex/thinclient_drives\n"}"
      # Even a dump created after backupPrepareCommand must never enter Restic.
      # The owner-private exclude file can contain negations; this immutable
      # rule therefore comes LAST and protects the snapshot itself.
      "--exclude-file=${pkgs.writeText "heim-pc-restic-hard-plaintext-excludes" "**/*.sql.gz\n"}"
    ];
    # stat(2) triggers the automount; never back up to an empty host path.
    backupPrepareCommand = ''
      test -f /var/lib/heim-pc-backup/restic/heim-pc/config
    '';
    timerConfig = {
      # Two daily opportunities leave margin below the 24h recovery-freshness
      # threshold even with the bounded randomized trigger delay.
      OnCalendar = "*-*-* 07,19:30:00";
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