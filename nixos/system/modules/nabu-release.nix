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
in {
  config = lib.mkIf config.heimPc.desktop.enable {
    environment.systemPackages = [ deploy ];
    environment.etc."heim-pc/nabu-release.json".source = release;
  };
}
