{ lib, ... }:
let
  contract = builtins.fromJSON (builtins.readFile ../../production/trust-contract-v1.json);
in
{
  assertions = [
    {
      assertion =
        contract.schema_version == 1
        && contract.kind == "heim_pc.nixos_supply_chain_trust_contract";
      message = "Nix trust module requires supply-chain trust contract v1";
    }
    {
      assertion =
        contract.nix.additional_substituters_policy == "deny-unless-reviewed-in-contract"
        && contract.nix.trusted_users == [ "root" ]
        && contract.nix.require_sigs
        && !contract.nix.accept_flake_config
        && contract.nix.experimental_features == [ "nix-command" "flakes" ]
        && !contract.nix.trust_tarballs_from_git_forges;
      message = "Nix trust contract must remain fail-closed and root-only";
    }
  ];

  nix.settings = {
    substituters = lib.mkForce contract.nix.substituters;
    trusted-substituters = lib.mkForce contract.nix.trusted_substituters;
    trusted-public-keys = lib.mkForce contract.nix.trusted_public_keys;
    trusted-users = lib.mkForce contract.nix.trusted_users;
    require-sigs = lib.mkForce contract.nix.require_sigs;
    accept-flake-config = lib.mkForce contract.nix.accept_flake_config;
    experimental-features = lib.mkForce contract.nix.experimental_features;
    trust-tarballs-from-git-forges = lib.mkForce contract.nix.trust_tarballs_from_git_forges;
  };

  environment.etc."heim-pc/nix-trust-contract.json".source =
    ../../production/trust-contract-v1.json;
}
