{ config, pkgs, ... }:
let
  diagnostics = ./netdata-diagnostics.py;
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
      db = {
        db = "dbengine";
        "update every" = 2;
        "storage tiers" = 2;
        # Time and disk size are soft retention targets, not filesystem quotas.
        "dbengine tier 0 retention size" = "512MiB";
        "dbengine tier 0 retention time" = "14d";
        "dbengine tier 1 retention size" = "256MiB";
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
