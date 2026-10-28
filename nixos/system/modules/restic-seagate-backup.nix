{ lib, pkgs, ... }:
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

  # No Polkit grant for alex: even a fixed root-owned unit must only be
  # started by the authenticated and tightly scoped Grabowski Rootbroker.

  # Fixed, root-owned restore evidence. The operator can trigger exactly this
  # systemd oneshot, not choose privileged Restic argv or a writable restore dir.
  systemd.services."heim-pc-restic-recovery-probe" = {
    description = "Root-owned NixOS Restic restore and repository-integrity proof";
    unitConfig.RequiresMountsFor = [ "/var/lib/heim-pc-backup" "/persist" ];
    serviceConfig = {
      Type = "oneshot";
      User = "root";
      Group = "root";
      ExecStart = "${pkgs.python3}/bin/python3 -I -B ${./heim-pc-restic-recovery-probe.py}";
      Environment = [
        "PATH=${lib.makeBinPath [ pkgs.restic pkgs.util-linux pkgs.systemd pkgs.coreutils ]}"
        "LC_ALL=C"
        "RESTIC_CACHE_DIR=/var/cache/heim-pc-restic-recovery-probe"
      ];
      CacheDirectory = "heim-pc-restic-recovery-probe";
      CacheDirectoryMode = "0700";
      StateDirectory = "heim-pc-restic-recovery-probe";
      StateDirectoryMode = "0755";
      UMask = "0022";
      # Allows restore and a 1/10 repository check without outliving the caller.
      TimeoutStartSec = "75min";
      NoNewPrivileges = true;
      RestrictSUIDSGID = true;
      RestrictRealtime = true;
      ProtectClock = true;
      ProtectHostname = true;
      ProtectProc = "invisible";
      CapabilityBoundingSet = [
        "CAP_CHOWN" "CAP_DAC_OVERRIDE" "CAP_DAC_READ_SEARCH"
        "CAP_FOWNER" "CAP_FSETID" "CAP_SETUID" "CAP_SETGID"
      ];
      PrivateTmp = true;
      PrivateNetwork = true;
      ProtectSystem = "strict";
      ProtectHome = "read-only";
      ReadWritePaths = [ "/var/lib/heim-pc-backup" "/var/lib/heim-pc-restic-recovery-probe" ];
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectKernelLogs = true;
      ProtectControlGroups = true;
      RestrictNamespaces = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      RestrictAddressFamilies = [ "AF_UNIX" "AF_NETLINK" ];
      SystemCallArchitectures = "native";
    };
  };

}