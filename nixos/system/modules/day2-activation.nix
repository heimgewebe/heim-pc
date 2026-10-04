{ config, lib, pkgs, ... }:
let
  cfg = config.heimPc.day2Activation;
  managedNixSource = ../../../scripts/managed_nix.py;
  executorSource = ../../../scripts/nixos_day2_activation.py;
  deploymentContractSource = ../../deployment/contract-v1.json;
  persistentPromotionContractSource = ../../deployment/persistent-promotion-v2.json;
  runtimeExecutorContractSource = ../../deployment/runtime-executor-v1.json;
  bundle = pkgs.runCommand "heim-pc-nixos-day2-activation-executor" {
    nativeBuildInputs = [ pkgs.makeWrapper ];
  } ''
    set -eu
    bundle_root="$out/libexec/heim-pc-nixos-day2"
    mkdir -p "$bundle_root/scripts" "$bundle_root/nixos/deployment" "$out/bin"
    cp ${managedNixSource} "$bundle_root/scripts/managed_nix.py"
    cp ${executorSource} "$bundle_root/scripts/nixos_day2_activation.py"
    cp ${deploymentContractSource} "$bundle_root/nixos/deployment/contract-v1.json"
    cp ${persistentPromotionContractSource} "$bundle_root/nixos/deployment/persistent-promotion-v2.json"
    cp ${runtimeExecutorContractSource} "$bundle_root/nixos/deployment/runtime-executor-v1.json"
    chmod 0555 "$bundle_root/scripts/managed_nix.py" "$bundle_root/scripts/nixos_day2_activation.py"
    chmod 0444 "$bundle_root/nixos/deployment/"*.json
    makeWrapper ${pkgs.python3}/bin/python3 "$out/bin/heim-pc-nixos-activation-executor" \
      --add-flags "-I" \
      --add-flags "$bundle_root/scripts/nixos_day2_activation.py"
  '';
in
{
  options.heimPc.day2Activation.enable = lib.mkEnableOption
    "narrow closure-bound NixOS Day-2 activation executor";

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ bundle ];

    environment.etc."heim-pc/nixos-day2-runtime-executor-contract.json".source =
      runtimeExecutorContractSource;

    # This directory is intentionally root-only. The future capability broker may
    # stage exact hash-bound requests here, but this module grants no caller the
    # ability to do so and exposes no systemd service or broad root command.
    systemd.tmpfiles.rules = [
      "d /run/heim-pc/nixos-activation 0700 root root -"
      "d /run/heim-pc/nixos-activation/requests 0700 root root -"
    ];
  };
}
