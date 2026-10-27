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
  # Rootless Podman needs setuid newuidmap/newgidmap exactly once on a cold
  # runtime. Keep that fixed bootstrap in a separate user-owned system unit;
  # never relax NoNewPrivileges on the network-facing Nixer MCP process.
  holdNamespace = pkgs.writeShellApplication {
    name = "heim-pc-nixer-hold-namespace";
    runtimeInputs = [ pkgs.coreutils pkgs.podman ];
    text = ''
      set -eu
      export PATH="/run/wrappers/bin:$PATH"
      exec podman unshare sleep infinity
    '';
  };
  checkNamespace = pkgs.writeShellApplication {
    name = "heim-pc-nixer-check-namespace";
    runtimeInputs = [ pkgs.coreutils pkgs.podman pkgs.util-linux ];
    text = ''
      set -eu
      export PATH="/run/wrappers/bin:$PATH"
      # Type=exec starts ExecStartPost before the holder has completed
      # rootless Podman's pause namespace initialization. Wait for readiness
      # instead of racing newuidmap and killing an otherwise valid holder.
      # Do not accept mere process liveness as proof of NNP compatibility.
      attempt=1
      while [ "$attempt" -le 60 ]; do
        if setpriv --no-new-privs -- podman unshare true >/dev/null 2>&1; then
          exit 0
        fi
        sleep 0.5
        attempt=$((attempt + 1))
      done
      echo "Nixer Podman namespace did not become NNP-usable" >&2
      exit 1
    '';
  };
in
{
  options.heimPc.nixerHeadless.enable = lib.mkEnableOption
    "Nixer as a system-owned, login-independent, unprivileged specialist";

  config = lib.mkIf cfg.enable {
    # Preserve the host-verified subordinate-ID ranges under NixOS rebuilds.
    # They are required by rootless Podman and match /etc/subuid/subgid.
    users.users.alex.subUidRanges = [{ startUid = 100000; count = 65536; }];
    users.users.alex.subGidRanges = [{ startGid = 100000; count = 65536; }];

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
        assertion = !(builtins.elem "grabowski" config.users.users.alex.extraGroups);
        message = "Nixer must not grant interactive alex rootbroker socket membership";
      }
      {
        assertion = config.systemd.services.nixer-headless.serviceConfig.NoNewPrivileges;
        message = "Nixer MCP requires NoNewPrivileges to close alex sudo escalation";
      }
    ];

    # Scope is system, execution identity remains unprivileged. The /run
    # RuntimeDirectory exists without systemd --user, linger or a local login,
    # and belongs only to this service account for rootless Podman state.
    # The holder is a fixed local command, with no network listener or MCP
    # tools. Its private, short-lived runtime is shared only with Nixer.
    systemd.services.nixer-podman-namespace = {
      description = "Initialize and hold rootless Podman user namespace for Nixer";
      wantedBy = [ "multi-user.target" ];
      unitConfig.Upholds = "nixer-headless.service";
      environment = {
        HOME = "/home/alex";
        XDG_RUNTIME_DIR = "/run/nixer-headless";
      };
      serviceConfig = {
        Type = "exec";
        User = "alex";
        Group = "users";
        WorkingDirectory = "/home/alex";
        RuntimeDirectory = "nixer-headless";
        RuntimeDirectoryMode = "0700";
        RuntimeDirectoryPreserve = "yes";
        ExecStart = "${holdNamespace}/bin/heim-pc-nixer-hold-namespace";
        ExecStartPost = "${checkNamespace}/bin/heim-pc-nixer-check-namespace";
        NoNewPrivileges = false;
        Restart = "on-failure";
        RestartSec = "2s";
        UMask = "0077";
      };
    };
    systemd.services.nixer-headless = {
      description = "Nixer Nix specialist (headless system scope)";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      bindsTo = [ "nixer-podman-namespace.service" ];
      after = [ "network-online.target" "nixer-podman-namespace.service" ];
      unitConfig = {
        StartLimitIntervalSec = "600s";
        StartLimitBurst = 3;
      };
      environment = {
        HOME = "/home/alex";
        XDG_RUNTIME_DIR = "/run/nixer-headless";
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
        Group = "users";
        # Prevent sudo/setuid privilege gain from this unprivileged specialist.
        # Real pinned Podman flake metadata and nixos_options batch evaluations
        # succeed under NoNewPrivileges, while a sudo root attempt is denied.
        NoNewPrivileges = true;
        WorkingDirectory = "/home/alex";
        RuntimeDirectory = "nixer-headless";
        RuntimeDirectoryMode = "0700";
        RuntimeDirectoryPreserve = "yes";
        ExecStartPre = "${checkImage}/bin/heim-pc-nixer-check-image";
        ExecStart =
          "${nixerPackage}/bin/nixer --transport streamable-http --host 127.0.0.1 --port 18187";
        Restart = "on-failure";
        RestartSec = "5s";
        UMask = "0077";
        LimitCORE = 0;
        CPUWeight = 50;
        IOWeight = 50;
        # Full flake checks exceeded 8 GiB on this 62 GiB host.
        # Do not impose an artificial cgroup memory limit on Nixer.
        # Keep the working parent filesystem/sandbox unchanged: rootless
        # Podman still needs its namespace helpers and read-only repo mounts.
        # The pinned Nixer child container has its own no-new-privileges gate
        # and never accepts arbitrary shell commands.
      };
    };
  };
}