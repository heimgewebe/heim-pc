# Generation-bound NABU source. User-level application remains transactional;
# do not restart persistent HA or rewrite private configuration during a system switch.
nabu: { config, lib, pkgs, ... }:
let
  release = builtins.toFile "nabu-release.json" (builtins.toJSON {
    revision = nabu.rev;
    source = toString nabu.outPath;
  });
  deploy = pkgs.writeShellScriptBin "nabu-deploy" ''
    export PATH=${lib.makeBinPath [ pkgs.podman pkgs.systemd ]}:$PATH
    exec ${pkgs.python3}/bin/python3 -B ${nabu.outPath}/scripts/nabu_deploy.py "$@" --pinned-release ${release}
  '';
  installSender = pkgs.writeShellScriptBin "nabu-install-sender" ''
    if [ "$#" -ne 0 ]; then
      echo "Usage: nabu-install-sender" >&2
      exit 2
    fi
    exec ${pkgs.python3}/bin/python3 -B ${nabu.outPath}/nixos/system/nabu/setup_chatgpt_sender.py
  '';
in {
  config = lib.mkIf config.heimPc.desktop.enable {
    environment.systemPackages = [ deploy installSender ];
    environment.etc."heim-pc/nabu-release.json".source = release;
    environment.etc."heim-pc/nabu-source".source = nabu.outPath;
  };
}
