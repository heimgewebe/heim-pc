{
  description = "Isolated heim-pc-as-code prototype for NixOS 26.05";

  # Flake metadata and inputs are literal; only outputs may evaluate imports.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    microvm = {
      url = "github:microvm-nix/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixer.url = "github:heimgewebe/nixer/6c1fae3936e441c43d19a7924f2f26f3539fb1d3";
  };

  outputs = inputs@{ self, nixpkgs, microvm, nixer }:
    (import ./nixos/system/flake.nix).outputs inputs;
}
