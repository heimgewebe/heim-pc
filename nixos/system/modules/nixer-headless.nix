{ config, lib, pkgs, ... }:
let
  cfg = config.heimPc.nixerHeadless;
  nixerPackage = config.services.nixer.package;
  # Exact image ID from the already reviewed Nixer runtime contract.
  pinnedImageId =
    "sha256:98edc6813218e179ce84587373e0b52d4aa58babae2d26b51fb01e7fdacf815f";

  # The MCP service NEVER pulls images or tags a mutable ref. A missing or
  # mismatched image is an observable start failure, not an implicit mutation.
  checkImage = pkgs.writeShellApplication {
    name = "heim-pc-nixer-check-image";
    runtimeInputs = [ pkgs.coreutils pkgs.podman ];
    text = ''
      set -eu
      # NixOS rootless Podman requires the host's setuid ID-map wrappers.
      export PATH="/run/wrappers/bin:$PATH"
      # Podman reports .Id as 64 hex characters, normally without sha256:.
      expected=${lib.escapeShellArg (lib.removePrefix "sha256:" pinnedImageId)}
      observed="$(podman image inspect --format '{{.Id}}' ${lib.escapeShellArg pinnedImageId})"
      if [ "$observed" != "$expected" ] && [ "$observed" != "sha256:$expected" ]; then
        echo "Nixer immutable container image identity mismatch" >&2
        exit 1
      fi
    '';
  };
in
{
  options.heimPc.nixerHeadless.enable = lib.mkEnableOption
    "Nixer as a system-owned, login-independent, unprivileged specialist";

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = config.virtualisation.podman.enable;
        message = "Nixer headless requires the rootless Podman host runtime";
      }
      {
        assertion = !config.services.nixer.enable;
        message = "Nixer headless must not also create its session-bound user service";
      }
      {
        assertion = !config.users.users.alex.linger;
        message = "Nixer headless must not depend on enabling all alex user units";
      }
      {
        assertion = !(builtins.elem "grabowski" config.users.users.alex.extraGroups);
        message = "Nixer must not grant interactive alex rootbroker socket membership";
      }
    ];

    # Scope is system, execution identity remains unprivileged. The /run
    # RuntimeDirectory exists without systemd --user, linger or a local login,
    # and belongs only to this service account for rootless Podman state.
    systemd.services.nixer-headless = {
      description = "Nixer Nix specialist (headless system scope)";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      unitConfig = {
        StartLimitIntervalSec = "600s";
        StartLimitBurst = 3;
      };
      environment = {
        HOME = "/home/alex";
        PYTHONDONTWRITEBYTECODE = "1";
        NIXER_REPO_ROOT = "/home/alex/repos";
        NIXER_DOCKER_BIN = "${pkgs.podman}/bin/podman";
        NIXER_CONTAINER_HOME = "/home/alex";
        NIXER_CONTAINER_PATH = "/run/wrappers/bin:${pkgs.podman}/bin";
        NIXER_CONTAINER_XDG_RUNTIME_DIR = "/run/nixer-headless";
      };
      serviceConfig = {
        Type = "simple";
        User = "alex";
        Group = "alex";
        WorkingDirectory = "/home/alex";
        RuntimeDirectory = "nixer-headless";
        RuntimeDirectoryMode = "0700";
        ExecStartPre = "${checkImage}/bin/heim-pc-nixer-check-image";
        ExecStart =
          "${nixerPackage}/bin/nixer --transport streamable-http --host 127.0.0.1 --port 18187";
        Restart = "on-failure";
        RestartSec = "5s";
        UMask = "0077";
        LimitCORE = 0;
        CPUWeight = 50;
        IOWeight = 50;
        MemoryMax = "4G";
        # Do not mount/seccomp-sandbox the parent rootless Podman caller:
        # newuidmap/newgidmap may need the NixOS privileged wrapper path.
        # The pinned Nixer backend confines the child container, binds repo
        # mounts read-only, and never accepts arbitrary shell commands.
      };
    };
  };
}
