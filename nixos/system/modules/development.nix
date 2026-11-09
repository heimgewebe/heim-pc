{ config, lib, pkgs, ... }:
{
  environment.systemPackages = with pkgs; [
    git gh nodejs python3 rustc cargo clang cmake pkg-config jq
    ripgrep fd curl wget file patchelf appimage-run distrobox
  ] ++ lib.optionals config.heimPc.desktop.enable (with pkgs; [
    # Documents stay local: no permanent PDF server or unmaintained containers.
    ocrmypdf qpdf tesseract pdfarranger
  ]);

  # Keep GitHub HTTPS authentication valid across gh updates and Nix store GC.
  # gh auth setup-git writes a versioned store path into ~/.gitconfig, whereas
  # the active system profile always provides this stable wrapper.
  programs.git = {
    enable = true;
    config.credential = {
      "https://github.com".helper = [ "" "!/run/current-system/sw/bin/gh auth git-credential" ];
      "https://gist.github.com".helper = [ "" "!/run/current-system/sw/bin/gh auth git-credential" ];
    };
  };

  # NixOS' native program module installs LocalSend and configures its
  # discovery/transfer firewall ports; only the desktop profile enables it.
  programs.localsend = lib.mkIf config.heimPc.desktop.enable {
    enable = true;
    openFirewall = true;
  };

  # Keep the user's existing Espanso snippets.  The NixOS Wayland package
  # handles uinput/wrapper requirements; do not revive the Pop!_OS Snap.
  services.espanso = lib.mkIf config.heimPc.desktop.enable {
    enable = true;
    package = pkgs.espanso-wayland;
  };
  # Only the physical desktop owner's user manager may expand snippets.
  systemd.user.services.espanso.unitConfig.ConditionUser =
    lib.mkIf config.heimPc.desktop.enable "alex";

  # Foreign dynamically-linked Linux binaries are a known NixOS friction point.
  programs.nix-ld.enable = true;
  programs.appimage.enable = true;
  programs.appimage.binfmt = true;
}
