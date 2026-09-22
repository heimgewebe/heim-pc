{
  description = "Isolated heim-pc-as-code prototype for NixOS 26.05";

  # Flake metadata and inputs are literal; only outputs may evaluate imports.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    microvm = {
      url = "github:microvm-nix/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixer.url = "github:heimgewebe/nixer/0a1805a6fcff3f01c0005d450157baab27b7dbfc";
  };

  outputs = inputs@{ self, nixpkgs, microvm, nixer }:
    (import ./nixos/system/flake.nix).outputs inputs;
}
