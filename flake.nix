{
  description = "Isolated heim-pc-as-code prototype for NixOS 26.05";

  # Root flake.lock is authoritative. The nested lock is generated with
  # scripts/ci/check_flake_lock.py --sync; outputs reject any projection drift.
  # Flake metadata and inputs are literal; only outputs may evaluate imports.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    microvm = {
      url = "github:microvm-nix/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixer.url = "github:heimgewebe/nixer/b229f81de906cc28b3e9cf8d29bf757232b6ed97";
    nabu = {
      url = "github:heimgewebe/nabu/fd2a2649177bcff2a98bd6f400b0d8e1d3e9a0ca";
      flake = false;
    };
  };

  outputs = inputs@{ self, nixpkgs, microvm, nixer, nabu }:
    (import ./nixos/system/flake.nix).outputs inputs;
}
