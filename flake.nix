{
  description = "Isolated heim-pc-as-code prototype for NixOS 26.05";

  # Flake metadata and inputs are literal; only outputs may evaluate imports.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    microvm = {
      url = "github:microvm-nix/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixer.url = "github:heimgewebe/nixer/c0b75cfd580c221f8a5095fbf802c4f6386a017e";
  };

  outputs = inputs@{ self, nixpkgs, microvm, nixer }:
    (import ./nixos/system/flake.nix).outputs inputs;
}
