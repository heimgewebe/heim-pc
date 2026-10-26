{ lib, pkgs, ... }:
let
  # Fotoatelier's private runtime stays on the Windows host FOTOLABOR.
  # These are the two existing, tested heim-pc-side transport services only.
  home = "/home/alex";
  source = "${home}/repos/fotoatelier";
  publicRepo = "${home}/repos/fotoatelier-public";
  stateRoot = "${home}/.local/state/fotoatelier-public-sync";
  sshConfig = "${home}/.ssh/config";
  python = "${pkgs.python3}/bin/python3";
  tools = lib.makeBinPath [ pkgs.openssh pkgs.git pkgs.python3 pkgs.coreutils ];
in
{
  # Provision the exact writable roots before the user manager starts the
  # sandboxed jobs. Scripts cannot create a missing ReadWritePaths mountpoint.
  # No original photo source or public Git checkout is created here.
  systemd.tmpfiles.rules = [
    "d ${home}/.local 0700 alex users -"
    "d ${home}/.local/share 0700 alex users -"
    "d ${home}/.local/share/fotoatelier 0700 alex users -"
    "d ${home}/.local/share/fotoatelier/backups 0700 alex users -"
    "d ${home}/.local/share/fotoatelier/backups/current 0700 alex users -"
    "d ${home}/.local/state 0700 alex users -"
    "d ${stateRoot} 0700 alex users -"
  ];

  systemd.user.services.fotoatelier-backup = {
    description = "Fotoatelier off-machine backup";
    after = [ "network-online.target" ];
    unitConfig.ConditionUser = "alex";
    serviceConfig = {
      Type = "oneshot";
      Environment = [ "PATH=${tools}" ];
      ExecStart = "${python} ${source}/ops/fotoatelier-backup-sync.py";
      TimeoutStartSec = "6min";
      NoNewPrivileges = true;
      PrivateTmp = true;
      ProtectSystem = "strict";
      ProtectHome = "read-only";
      ReadWritePaths = [ "${home}/.local/share/fotoatelier/backups" ];
      RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
      UMask = "0077";
    };
  };

  systemd.user.timers.fotoatelier-backup = {
    description = "Fotoatelier off-machine backup retry timer";
    wantedBy = [ "timers.target" ];
    unitConfig.ConditionUser = "alex";
    timerConfig = {
      OnCalendar = "*-*-* 08,12,16,20:20:00";
      RandomizedDelaySec = "20min";
      Persistent = true;
      Unit = "fotoatelier-backup.service";
    };
  };

  systemd.user.services.fotoatelier-public-sync = {
    description = "Fotoatelier public GitHub Pages sync";
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    unitConfig.ConditionUser = "alex";
    # No auto-created empty Git checkout: missing publisher source is a skip.
    unitConfig.ConditionPathExists = "${publicRepo}/.git";
    serviceConfig = {
      Type = "oneshot";
      WorkingDirectory = source;
      Environment = [
        "HOME=${home}"
        "PATH=${tools}"
        "FOTOATELIER_SSH_CONFIG=${sshConfig}"
        "GIT_SSH_COMMAND=${pkgs.openssh}/bin/ssh -F ${sshConfig}"
      ];
      ExecStart = "${python} ${source}/ops/public-sync.py";
      TimeoutStartSec = "6min";
      NoNewPrivileges = true;
      PrivateTmp = true;
      ProtectSystem = "full";
      ProtectHome = "read-only";
      ReadWritePaths = [ publicRepo stateRoot ];
      RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
      LockPersonality = true;
      UMask = "0077";
    };
  };

  systemd.user.timers.fotoatelier-public-sync = {
    description = "Periodically sync Fotoatelier public projection";
    wantedBy = [ "timers.target" ];
    unitConfig.ConditionUser = "alex";
    timerConfig = {
      # Calendar re-arms even when ConditionPathExists skips the first start.
      OnCalendar = "*-*-* *:00/5:00";
      AccuracySec = "30s";
      Persistent = true;
      Unit = "fotoatelier-public-sync.service";
    };
  };
}
