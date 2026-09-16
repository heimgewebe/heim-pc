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
    runtimeInputs = [ pkgs.coreutils pkgs.podman ];
    text = ''
      set -eu

      if ! podman image inspect ${lib.escapeShellArg pinnedImageId} >/dev/null 2>&1; then
        max_attempts=6
        attempt=1
        while ! podman pull ${lib.escapeShellArg pinnedImageRef} >/dev/null; do
          if [ "$attempt" -ge "$max_attempts" ]; then
            printf 'Nixer pinned image pull failed after %s attempts\n' "$max_attempts" >&2
            exit 1
          fi

          delay=$((attempt * 5))
          printf 'Nixer pinned image pull attempt %s/%s failed; retrying in %ss\n' \
            "$attempt" "$max_attempts" "$delay" >&2
          sleep "$delay"
          attempt=$((attempt + 1))
        done
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
    # execution image. The helper owns bounded retries because a user-manager
    # network-online target is not a reliable host-connectivity signal.
    systemd.user.services.nixer-image = {
      description = "Prepare Nixer pinned Nix image";
      before = [ "nixer.service" ];
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
      # Replace the generic module's user-level network ordering with the
      # concrete prerequisite that actually owns image availability.
      wants = lib.mkForce [ ];
      requires = [ "nixer-image.service" ];
      after = lib.mkForce [ "nixer-image.service" ];
      serviceConfig = {
        CPUWeight = 50;
        IOWeight = 50;
        MemoryMax = "4G";
      };
    };
  };
}
