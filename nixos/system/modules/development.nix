{ pkgs, ... }:
{
 environment.systemPackages = with pkgs; [ git gh nodejs python3 rustc cargo clang cmake pkg-config jq ripgrep fd curl wget file patchelf appimage-run distrobox ];
 # Foreign dynamically-linked Linux binaries are a known NixOS friction point.
 programs.nix-ld.enable = true;
 programs.appimage.enable = true;
 programs.appimage.binfmt = true;
}
