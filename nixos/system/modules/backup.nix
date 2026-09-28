{ pkgs, ... }:
let
  recoveryPath = ../../production/recovery-contract-v1.json;
  criticalUserDataPath = ../../production/critical-user-data-contract-v1.json;
  criticalUserHomePath = ../../production/critical-user-home-data-contract-v1.json;
  criticalDockerVolumesPath = ../../production/critical-docker-volume-data-contract-v1.json;
  recovery = builtins.fromJSON (builtins.readFile recoveryPath);
  criticalUserData = builtins.fromJSON (builtins.readFile criticalUserDataPath);
  criticalUserHome = builtins.fromJSON (builtins.readFile criticalUserHomePath);
  criticalDockerVolumes = builtins.fromJSON (builtins.readFile criticalDockerVolumesPath);
  criticalUserDataSha256 = builtins.hashFile "sha256" criticalUserDataPath;
  criticalUserHomeSha256 = builtins.hashFile "sha256" criticalUserHomePath;
  criticalDockerVolumesSha256 = builtins.hashFile "sha256" criticalDockerVolumesPath;
  homeMember = builtins.elemAt criticalUserData.members 0;
  dockerVolumesMember = builtins.elemAt criticalUserData.members 1;
in
{
  assertions = [
    {
      assertion =
        recovery.schema_version == 1
        && recovery.kind == "heim_pc.nixos_recovery_readiness_contract"
        && recovery.admission.point_of_no_return_blocked_without_complete_evidence
        && recovery.admission.production_storage_mutation_blocked_without_complete_evidence
        && recovery.critical_user_data_scope.contract_kind == "heim_pc.critical_user_data_scope_contract"
        && recovery.critical_user_data_scope.scope == "critical-user-data"
        && recovery.critical_user_data_scope.sha256 == criticalUserDataSha256
        && recovery.critical_user_data_scope.off_host_restore_critical_scope_sha256_bound
        && recovery.critical_user_data_scope.aggregate_member_contracts_bound
        && criticalUserData.schema_version == 1
        && criticalUserData.kind == "heim_pc.critical_user_data_scope_contract"
        && criticalUserData.scope == "critical-user-data"
        && criticalUserData.scope_semantics == "explicit-root-set-default-include"
        && builtins.length criticalUserData.members == 2
        && homeMember.id == "home"
        && homeMember.contract_file == "critical-user-home-data-contract-v1.json"
        && homeMember.contract_sha256 == criticalUserHomeSha256
        && homeMember.destination.nixos_storage_domain == "@home"
        && dockerVolumesMember.id == "docker-volumes"
        && dockerVolumesMember.contract_file == "critical-docker-volume-data-contract-v1.json"
        && dockerVolumesMember.contract_sha256 == criticalDockerVolumesSha256
        && dockerVolumesMember.destination.nixos_storage_domain == "@data"
        && criticalUserHome.scope == "critical-user-data-home"
        && criticalUserHome.scope_semantics == "whole-home-by-default"
        && criticalUserHome.root == "/home/alex"
        && criticalDockerVolumes.scope == "critical-user-data-docker-volumes"
        && criticalDockerVolumes.scope_semantics == "whole-root-by-default"
        && criticalDockerVolumes.root == "/var/lib/docker/volumes"
        && criticalDockerVolumes.source_consistency.full_authoritative_inventory_requires_docker_quiesced
        && !criticalDockerVolumes.destination_policy.direct_restore_into_new_docker_volume_store;
      message = "backup module requires fail-closed aggregate critical-data contracts";
    }
  ];

  environment.systemPackages = [ pkgs.restic ];
  environment.etc."heim-pc/recovery-contract.json".source = recoveryPath;
  environment.etc."heim-pc/critical-user-data-contract.json".source =
    criticalUserDataPath;
  environment.etc."heim-pc/critical-user-home-data-contract.json".source =
    criticalUserHomePath;
  environment.etc."heim-pc/critical-docker-volume-data-contract.json".source =
    criticalDockerVolumesPath;
  systemd.tmpfiles.rules = [ "d /var/lib/heim-pc/backup 0700 root root -" ];
}
