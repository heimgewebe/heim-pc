#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
expression="let flake = builtins.getFlake \"path:$root\"; pkgs = import flake.inputs.nixpkgs { system = \"x86_64-linux\"; config.allowUnfree = true; }; in import $root/runtime/krdp-ipad/package.nix { inherit pkgs; }"
exec nix build --impure --no-link --print-out-paths --expr "$expression"
