{ config, lib, pkgs, ... }:
{
  environment.systemPackages = with pkgs; [
    git gh nodejs python3 rustc cargo clang cmake pkg-config jq
    ripgrep fd curl wget file patchelf appimage-run distrobox
  ] ++ lib.optionals config.heimPc.desktop.enable (with pkgs; [
    # Pop!_OS day-to-day document workflow, without a permanent PDF server.
    ocrmypdf qpdf tesseract pdfarranger
    # LAN peer-to-peer transfer on demand; Taildrop handles remote transfers.
    localsend
  ]);
  # Foreign dynamically-linked Linux binaries are a known NixOS friction point.
  programs.nix-ld.enable = true;
  programs.appimage.enable = true;
  programs.appimage.binfmt = true;
}
