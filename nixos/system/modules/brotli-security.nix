{ lib, ... }:
{
  # CVE-2026-111497: share this decoder patch across the workstation and
  # Seagate successor profiles; keep the nixpkgs lock and other packages pinned.
  # The 1.2.1 source hash is the reviewed nixos-26.05 backport.
  nixpkgs.overlays = lib.mkDefault [
    (_final: prev: {
      brotli = prev.brotli.overrideAttrs (_: {
        version = "1.2.1";
        src = prev.fetchFromGitHub {
          owner = "google";
          repo = "brotli";
          tag = "v1.2.1";
          hash = "sha256-llY72cYffDv0ugsH0p89xIPEbElV4L8u7U/Fe8hT3gI=";
        };
      });
    })
  ];
}
