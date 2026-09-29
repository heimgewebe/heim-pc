{ pkgs, ... }:
let
  recovery = builtins.fromJSON (builtins.readFile ../../production/recovery-contract-v1.json);
in
{
  assertions = [
    {
      assertion =
        recovery.schema_version == 1
        && recovery.kind == "heim_pc.nixos_recovery_readiness_contract"
        && recovery.admission.point_of_no_return_blocked_without_complete_evidence
        && recovery.admission.production_storage_mutation_blocked_without_complete_evidence;
      message = "backup module requires fail-closed NixOS recovery contract v1";
    }
  ];

  environment.systemPackages = [ pkgs.restic ];
  environment.etc."heim-pc/recovery-contract.json".source =
    ../../production/recovery-contract-v1.json;
  systemd.tmpfiles.rules = [ "d /var/lib/heim-pc/backup 0700 root root -" ];
}
