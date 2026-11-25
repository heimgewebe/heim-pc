{ config, pkgs, ... }:
let
  diagnostics = ./netdata-diagnostics.py;
  # Netdata 2.10.3's first-match default excludes user.slice. Preserve the
  # stock filters and admit only Alex's actual rootless Podman payload
  # cgroups (both Quadlet and libpod scope/container layouts).
  # Keep raw IDs: the daemon cannot resolve another user's Podman names
  # without management access. Recheck these pinned defaults on upgrade.
  operatorUid = toString config.users.users.alex.uid;
  rootlessPrefix = "/user.slice/user-${operatorUid}.slice/user@${operatorUid}.service";
  podmanPayload = "${rootlessPrefix}/*/libpod-payload-*";
  podmanScope = "${rootlessPrefix}/*/libpod-*.scope/container";
  cgroupSelection = builtins.concatStringsSep " " [
    "!*/init.scope" "!/system.slice/run-*.scope" "*user.slice/docker-*"
    "!${podmanPayload}/*" podmanPayload podmanScope
    "!*user.slice*" "*.scope"
    "!/machine.slice/*/.control" "!/machine.slice/*/payload*"
    "!/machine.slice/*/supervisor" "/machine.slice/*.service"
    "*/kubepods/pod*/*" "*/kubepods/*/pod*/*" "*/*-kubepods-pod*/*"
    "*/*-kubepods-*-pod*/*" "!*kubepods*" "!*kubelet*"
    "!*/vcpu*" "!*/emulator" "!*.mount" "!*.partition"
    "!*.service" "!*.service/udev" "!*.socket" "!*.slice"
    "!*.swap" "!*.user" "!/" "!/docker" "!*/libvirt" "!/lxc"
    "!/lxc/*/*" "!/lxc.monitor*" "!/lxc.pivot" "!/lxc.payload"
    "!*lxcfs.service/.control" "!/machine" "!/qemu" "!/system"
    "!/systemd" "!/user" "*"
  ];
  cgroupRenameSelection = builtins.concatStringsSep " " [
    "!${podmanPayload}" "!${podmanScope}"
    "!/" "!*.mount" "!*.socket" "!*.partition" "/machine.slice/*.service"
    "!*.service" "!*.slice" "!*.swap" "!*.user" "!init.scope"
    "!*.scope/vcpu*" "!*.scope/emulator" "*.scope" "*docker*" "*lxc*" "*qemu*"
    "*/kubepods/pod*/*" "*/kubepods/*/pod*/*" "*/*-kubepods-pod*/*"
    "*/*-kubepods-*-pod*/*" "!*kubepods*" "!*kubelet*" "*.libvirt-qemu" "*"
  ];
  command = pkgs.writeShellApplication {
    name = "heim-pc-netdata";
    runtimeInputs = [ pkgs.podman pkgs.systemd ];
    text = ''
      exec ${config.heimPc.grabowskiProduction.operatorPackage}/bin/python3 -I -B ${diagnostics} "$@"
    '';
  };
in
{
  # Host-local technical telemetry and history. Bureau, Grabowski and Git
  # context remain owned by the existing Heim-PC dashboard.
  # REST: http://127.0.0.1:19999/api/v1/charts
  # Native MCP: http://127.0.0.1:19999/mcp
  services.netdata = {
    enable = true;
    enableAnalyticsReporting = false;
    claimTokenFile = null;
    config = {
      web."bind to" = "127.0.0.1";
      "plugin:cgroups" = {
        "enable by default cgroups matching" = cgroupSelection;
        "run script to rename cgroups matching" = cgroupRenameSelection;
      };
      db = {
        db = "dbengine";
        "update every" = 2;
        "storage tiers" = 2;
        # Time and disk size are soft retention targets, not filesystem quotas.
        # Observed baseline growth plus additional container series: provision
        # headroom without changing the 2s resolution or the 14d time goal.
        "dbengine tier 0 retention size" = "4GiB";
        "dbengine tier 0 retention time" = "14d";
        "dbengine tier 1 retention size" = "1GiB";
        "dbengine tier 1 retention time" = "14d";
      };
    };
    # The service PATH is not the interactive desktop PATH. Bind the
    # NVIDIA CLI to the same package as the configured driver.
    configDir."go.d/nvidia_smi.conf" = pkgs.writeText "netdata-nvidia-smi.conf" ''
      jobs:
        - name: nvidia_smi
          binary_path: ${config.hardware.nvidia.package.bin}/bin/nvidia-smi
          update_every: 5
    '';
  };
  environment.systemPackages = [ command ];

  # A single session-bound oneshot reuses the existing Grabowski ntfy outbox.
  # No Podman management socket, extra daemon, or automatic remediation.
  systemd.user.services.heim-pc-netdata-watch = {
    description = "Check actionable Heim-PC Netdata conditions";
    unitConfig.ConditionUser = "alex";
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${command}/bin/heim-pc-netdata watch";
      TimeoutStartSec = "60s";
      UMask = "0077";
    };
  };
  systemd.user.timers.heim-pc-netdata-watch = {
    description = "Check actionable Netdata conditions every five minutes";
    wantedBy = [ "timers.target" ];
    unitConfig.ConditionUser = "alex";
    timerConfig = {
      OnBootSec = "5min";
      OnUnitActiveSec = "5min";
      AccuracySec = "30s";
    };
  };
}
