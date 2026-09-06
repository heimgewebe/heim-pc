{
  description = (import ./nixos/system/flake.nix).description;
  inputs = (import ./nixos/system/flake.nix).inputs;
  outputs = (import ./nixos/system/flake.nix).outputs;
}
