{ pkgs, ... }:
let
  recoveryPath = ../../production/recovery-contract-v1.json;
  criticalUserDataPath = ../../production/critical-user-data-contract-v1.json;
  criticalUserHomePath = ../../production/critical-user-home-data-contract-v1.json;
  recovery = builtins.fromJSON (builtins.readFile recoveryPath);
  criticalUserData = builtins.fromJSON (builtins.readFile criticalUserDataPath);
  criticalUserHome = builtins.fromJSON (builtins.readFile criticalUserHomePath);
  criticalUserDataSha256 = builtins.hashFile "sha256" criticalUserDataPath;
  criticalUserHomeSha256 = builtins.hashFile "sha256" criticalUserHomePath;
  homeMember = builtins.elemAt criticalUserData.members 0;
  materialization = criticalUserHome.materialization_policy;
  bootstrapRole = builtins.getAttr "bootstrap-direct" materialization.roles;
  authorityRole = builtins.getAttr "authority-reconcile" materialization.roles;
  coldRole = builtins.getAttr "cold-preservation" materialization.roles;
  coldImportRoot = "/var/lib/heim-pc-data/import/legacy-2026";
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
        && recovery.critical_user_data_scope.off_host_restore_source_inventory_sha256_bound
        && recovery.critical_user_data_scope.off_host_restore_restored_inventory_sha256_bound
        && recovery.critical_user_data_scope.off_host_restore_inventory_sha256_equality_required
        && recovery.critical_user_data_scope.aggregate_member_contracts_bound
        && recovery.readiness_bundle.critical_user_data_contract_sha256_bound
        && criticalUserData.schema_version == 1
        && criticalUserData.kind == "heim_pc.critical_user_data_scope_contract"
        && criticalUserData.scope == "critical-user-data"
        && criticalUserData.scope_semantics == "explicit-positive-selection"
        && criticalUserData.inventory_implementation.algorithm == "member-inventory-sha256-v1"
        && criticalUserData.inventory_implementation.root_inventory_script == "scripts/nixos_critical_user_data_inventory.py"
        && criticalUserData.inventory_implementation.aggregate_inventory_script == "scripts/nixos_critical_data_inventory.py"
        && criticalUserData.inventory_implementation.aggregate_execution_mode == "external-verified-payload-exec-v1"
        && criticalUserData.inventory_implementation.authoritative_member_source_stability == "kernel-local-pci-nvme-readonly-mountinfo-v3"
        && builtins.length criticalUserData.members == 1
        && homeMember.id == "home"
        && homeMember.contract_file == "critical-user-home-data-contract-v1.json"
        && homeMember.contract_sha256 == criticalUserHomeSha256
        && homeMember.destination.nixos_storage_domain == "per-entry-policy"
        && homeMember.destination.logical_path == "materialization-policy"
        && homeMember.restore_mode == "source-scope-with-role-specific-materialization"
        && criticalUserHome.scope == "critical-user-data-home"
        && criticalUserHome.scope_semantics == "explicit-path-set"
        && criticalUserHome.root == "/home/alex"
        && criticalUserHome.inventory.algorithm == "canonical-record-stream-sha256-v7"
        && criticalUserHome.inventory.uid_gid_bound
        && criticalUserHome.inventory.explicit_ancestor_metadata_bound
        && criticalUserHome.inventory.xattrs_sha256_bound
        && criticalUserHome.selection_policy.default == "exclude"
        && !criticalUserHome.selection_policy.unlisted_paths_are_migration_data
        && materialization.schema_version == 1
        && materialization.kind == "heim_pc.critical_user_data_materialization_policy"
        && materialization.source_scope_and_nixos_target_layout_are_separate
        && materialization.source_equivalent_disposable_restore_required
        && materialization.cold_import_root == coldImportRoot
        && !materialization.first_productive_boot_requires_cold_import_completion
        && bootstrapRole.nixos_storage_domain == "@home"
        && bootstrapRole.target_mapping == "same-absolute-path"
        && bootstrapRole.source_path_is_live_target_path
        && authorityRole.nixos_storage_domain == "@data"
        && authorityRole.staging_root == "${coldImportRoot}/authority"
        && !authorityRole.source_path_is_live_target_path
        && authorityRole.direct_activation_forbidden
        && coldRole.nixos_storage_domain == "@data"
        && coldRole.staging_root == coldImportRoot
        && !coldRole.source_path_is_live_target_path
        && !coldRole.required_before_first_productive_boot
        && criticalUserData.migration_policy.selection_model == "explicit-positive-allowlist"
        && !criticalUserData.migration_policy.unlisted_data_migrated
        && criticalUserData.migration_policy.remote_reproducible_repositories_excluded
        && criticalUserData.migration_policy.operator_state_restored_via_authority_reconcile
        && !criticalUserData.migration_policy.legacy_docker_volume_tree_migrated
        && !criticalUserData.migration_policy.root_owned_grabowski_runtime_state_migrated
        && criticalUserData.migration_policy.root_owned_grabowski_runtime_state_reinitialized_from_verified_deploy
        && !criticalUserData.migration_policy.source_paths_define_nixos_target_layout
        && criticalUserData.migration_policy.cold_preservation_storage_domain == "@data"
        && criticalUserData.migration_policy.cold_preservation_import_root == coldImportRoot
        && !criticalUserData.migration_policy.cold_preservation_required_before_first_productive_boot
        && !criticalUserData.migration_policy.local_only_repository_auto_checkout
        && !criticalUserData.migration_policy.legacy_library_source_path_restored
        && criticalUserData.migration_policy.operator_state_direct_restore_forbidden;
      message = "backup module requires fail-closed positive-selection and materialization contracts";
    }
  ];

  environment.systemPackages = [ pkgs.restic ];
  environment.etc."heim-pc/recovery-contract.json".source = recoveryPath;
  environment.etc."heim-pc/critical-user-data-contract.json".source =
    criticalUserDataPath;
  environment.etc."heim-pc/critical-user-home-data-contract.json".source =
    criticalUserHomePath;

  systemd.tmpfiles.rules = [
    "d /var/lib/heim-pc/backup 0700 root root -"
    "d /var/lib/heim-pc-data/import 0700 root root -"
    "d ${coldImportRoot} 0700 root root -"
    "d ${coldImportRoot}/authority 0700 root root -"
    "d ${coldImportRoot}/repos 0700 root root -"
  ];
}
