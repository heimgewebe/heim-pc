{ config, lib, pkgs, ... }:
let
  program = "${pkgs.python3}/bin/python3 ${./thermal-mitigation.py}";
  state = "/run/heim-pc-thermal-mitigation/original.json";
in
{
  # Proven on the physical ASUS B550-F / Ryzen 5900XT on 2026-11-24.
  # No force_id, ACPI resource override, fan manual mode or background polling.
  # This is a reversible mitigation, not a substitute for checking cooler
  # contact and sustained high-load thermal reserve. Re-evaluate after service.
  boot.kernelModules = [ "nct6775" ];

  systemd.services.heim-pc-thermal-mitigation = {
    description = "Apply measured Heim-PC CPU and automatic fan mitigation";
    wantedBy = [ "multi-user.target" ];
    # PPD is ordered after multi-user.target by its upstream unit. A target's
    # implicit Before= edge from this WantedBy would form a boot cycle and
    # systemd would discard the thermal start job. Start asynchronously after
    # multi-user instead, without making Netdata (a multi-user dependency)
    # wait on this late oneshot. Keep the normal shutdown stop ordering.
    unitConfig.DefaultDependencies = false;
    after = [ "multi-user.target" "systemd-modules-load.service" "power-profiles-daemon.service" ];
    wants = lib.optional config.services.power-profiles-daemon.enable "power-profiles-daemon.service";
    before = [ "shutdown.target" ];
    conflicts = [ "shutdown.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      RuntimeDirectory = "heim-pc-thermal-mitigation";
      RuntimeDirectoryMode = "0700";
      ExecStart = "${program} apply --state ${state}";
      ExecStop = "${program} restore --state ${state}";
      TimeoutStartSec = "20s";
      TimeoutStopSec = "20s";
    };
  };
}
