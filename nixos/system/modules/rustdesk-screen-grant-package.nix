{ pkgs }:
pkgs.stdenv.mkDerivation {
    pname = "rustdesk-kde-screen-grant-sync";
    version = "1";
    src = ./rustdesk-screen-grant-hotplug.cpp;
    dontUnpack = true;
  # The user unit explicitly supplies the KDE Wayland platform plugin.
  dontWrapQtApps = true;
    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = [ pkgs.qt6.qtbase ];
    buildPhase = ''
      runHook preBuild
      "$CXX" -std=c++20 -fPIC "$src" -o rustdesk-kde-screen-grant-sync         $(pkg-config --cflags --libs Qt6Core Qt6DBus Qt6Gui)
      runHook postBuild
    '';
    installPhase = ''
      runHook preInstall
      install -Dm755 rustdesk-kde-screen-grant-sync         "$out/bin/rustdesk-kde-screen-grant-sync"
      runHook postInstall
    '';
  }
