{ lib, pkgs, heimPcProfile ? { }, ... }:
let
  enableNixer =
    (heimPcProfile.physical or false)
    && (heimPcProfile.desktop or false);

  pinnedImageId =
    "sha256:98edc6813218e179ce84587373e0b52d4aa58babae2d26b51fb01e7fdacf815f";
  pinnedImageRef =
    "nixos/nix@sha256:7a007c766426c1877758ddc5cb87a965ac131fc78c582ce0083d922d51ae945c";

  prepareImage = pkgs.writeShellApplication {
    name = "heim-pc-nixer-prepare-image";
    runtimeInputs = [ pkgs.podman ];
    text = ''
      set -eu

      if ! podman image inspect ${lib.escapeShellArg pinnedImageId} >/dev/null 2>&1; then
        podman pull ${lib.escapeShellArg pinnedImageRef} >/dev/null
      fi

      actual="$(podman image inspect --format '{{.Id}}' ${lib.escapeShellArg pinnedImageId})"
      if [ "$actual" != ${lib.escapeShellArg pinnedImageId} ]; then
        printf 'Nixer pinned image identity mismatch: expected %s, got %s\n' \
          ${lib.escapeShellArg pinnedImageId} "$actual" >&2
        exit 1
      fi
    '';
  };
in
{
  config = lib.mkIf enableNixer {
    services.nixer = {
      enable = true;
      port = 18187;
      containerCli = "${pkgs.podman}/bin/podman";
    };

    # Host-owned runtime preparation: Nixer itself never pulls or updates its
    # execution image. The user service only starts after the exact digest is
    # present in the same rootless Podman store it will later use.
    systemd.user.services.nixer-image = {
      description = "Prepare Nixer pinned Nix image";
      before = [ "nixer.service" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${prepareImage}/bin/heim-pc-nixer-prepare-image";
        RemainAfterExit = true;
        NoNewPrivileges = true;
        PrivateTmp = true;
        UMask = "0077";
      };
    };

    systemd.user.services.nixer = {
      requires = [ "nixer-image.service" ];
      after = [ "nixer-image.service" ];
      serviceConfig = {
        CPUWeight = 50;
        IOWeight = 50;
        MemoryMax = "4G";
      };
    };
  };
}
