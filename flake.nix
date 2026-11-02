{
  description = "Isolated heim-pc-as-code prototype for NixOS 26.05";

  # Flake metadata and inputs are literal; only outputs may evaluate imports.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    microvm = {
      url = "github:microvm-nix/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixer.url = "github:heimgewebe/nixer/c252b62b0fcd0bd5442681bb68d809a4b5984c61";
  };

  outputs = inputs@{ self, nixpkgs, microvm, nixer }:
    (import ./nixos/system/flake.nix).outputs inputs;
}
