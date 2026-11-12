{ pkgs }:
# Official KRDP 6.7.0 progressive/RDPGFX, pinned to a fixed upstream commit.
# Keep Nixpkgs/Qt/KWin from the locked heim-pc flake (Plasma 6.6.6).
# Regression proofs: grabowski-job-357c92300f38 (both codecs, GUI and DP-2 restore)
# and grabowski-job-26ab282b1dab (PipeWire close on QObject owner thread).
pkgs.kdePackages.krdp.overrideAttrs (old: {
  version = "6.7.0";
  src = pkgs.fetchFromGitHub {
    owner = "KDE";
    repo = "krdp";
    rev = "b1a49644aed95132ac0d2eee19780040c061fdaa"; # v6.7.0
    hash = "sha256-PLOOAIKz3YVPFipC0gndLaeLk2Sq6nNmJsyLiut7+8s=";
  };
  patches = [
    ./patches/krdp-6.6.6-disable-ext-security-v1.patch
    ./patches/krdp-6.6.6-fakeinput-auth-v1.patch
    ./patches/krdp-6.7.0-guard-unbound-fakeinput-v1.patch
    ./patches/krdp-6.6.6-vm-size-v1.patch
    ./patches/krdp-6.6.6-wl-fixed-pointer-v1.patch
    ./patches/krdp-6.7.0-virtual-output-pointer-offset-v1.patch
    ./patches/krdp-6.7.0-physical-output-size-v1.patch
    ./patches/krdp-6.7.0-embedded-pointer-v1.patch
    ./patches/krdp-6.7.0-close-videostream-on-qt-thread-v1.patch
    ./patches/krdp-6.7.0-position-before-mouse-button-v1.patch
    ./patches/krdp-6.7.0-rdpei-touch-input-v1.patch
    ./patches/krdp-6.7.0-physical-output-pointer-coordinates-v1.patch
    ./patches/krdp-6.7.0-suspended-frame-ack-v1.patch
    ./patches/krdp-6.7.0-input-diag-v1.patch
    ./patches/krdp-6.7.0-monitor-name-v1.patch
  ];
  buildInputs = (old.buildInputs or []) ++ [ pkgs.kdePackages.kirigami-addons ];
})