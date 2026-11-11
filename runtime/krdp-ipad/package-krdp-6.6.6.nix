{ pkgs }:
# Derive from the nixpkgs KDE package pinned by the heim-pc flake.
pkgs.kdePackages.krdp.overrideAttrs (old: {
  patches = (old.patches or []) ++ [
    ./patches/krdp-6.6.6-vm-size-v1.patch
    ./patches/krdp-6.6.6-wl-fixed-pointer-v1.patch
    ./patches/krdp-6.6.6-fakeinput-auth-v1.patch
    ./patches/krdp-6.6.6-virtual-output-pointer-offset-v1.patch
    ./patches/krdp-6.6.6-embedded-pointer-v3.patch
    ./patches/krdp-6.6.6-disable-ext-security-v1.patch
  ];
})
