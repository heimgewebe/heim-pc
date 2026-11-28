{ config, lib, pkgs, ... }:
let
  source = ./ssh-cockpit-autocopy;
  watcher = pkgs.writeShellScriptBin "tmux-autocopy-watch" ''
    exec ${pkgs.python3}/bin/python3 ${source}/watch.py "$@"
  '';
  omnicopy = pkgs.writeShellScriptBin "omnicopy" ''
    export PATH="$PATH:${lib.makeBinPath [ pkgs.tmux ]}"
    exec ${pkgs.python3}/bin/python3 ${source}/omnicopy.py "$@"
  '';
  copyOff = pkgs.writeShellScriptBin "copy-off" ''
    export PATH="$PATH:${lib.makeBinPath [ pkgs.tmux pkgs.coreutils ]}"
    exec ${pkgs.bash}/bin/bash ${source}/copy-off.sh "$@"
  '';
  managedConfig = builtins.replaceStrings
    [ "@setsid@" "@watcher@" "@omnicopy@" ]
    [ "${pkgs.util-linux}/bin/setsid" "${watcher}/bin/tmux-autocopy-watch" "${omnicopy}/bin/omnicopy" ]
    (builtins.readFile (source + "/tmux.conf.in"));
in
{
  config = lib.mkIf config.heimPc.desktop.enable {
    environment.systemPackages = [ pkgs.tmux watcher omnicopy copyOff ];
    environment.etc."heim-pc/tmux-autocopy.conf".text = managedConfig;
    # A fresh home needs no local bootstrap. Other workstation accounts do not
    # inherit automatic clipboard capture.
    environment.etc."tmux.conf".text = ''
      if-shell 'test "$(${pkgs.coreutils}/bin/id -un)" = alex' 'source-file /etc/heim-pc/tmux-autocopy.conf'
    '';
    # A known older ~/.tmux.conf overrides global hooks. Migrate only that
    # exact file as its owner, preserve custom configurations and rollback.
    # This noncritical user unit never blocks boot or kills existing sessions.
    systemd.user.services.heim-pc-tmux-autocopy-migration = {
      description = "Migrate the known SSH cockpit tmux configuration";
      wantedBy = [ "default.target" ];
      unitConfig.ConditionUser = "alex";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.python3}/bin/python3 ${source}/migrate.py %h";
      };
    };
  };
}
