{
  description = "Isolated heim-pc-as-code prototype for NixOS 26.05";

  # Flake metadata and inputs are literal; only outputs may evaluate imports.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    microvm = {
      url = "github:microvm-nix/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixer.url = "github:heimgewebe/nixer/2e457e533517c379395e11d8ab3d4e6687c4c6e2";
  };

  outputs = inputs@{ self, nixpkgs, microvm, nixer }:
    (import ./nixos/system/flake.nix).outputs inputs;
}
