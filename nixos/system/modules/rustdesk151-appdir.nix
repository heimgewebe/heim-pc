{ pkgs }:
let
  lib = pkgs.lib;
  version = "1.5.1";
  src = pkgs.fetchurl {
    url = "https://github.com/rustdesk/rustdesk/releases/download/${version}/rustdesk-${version}-x86_64.AppImage";
    hash = "sha256-u4t8yz9QogHczcibRjhc/5DzPmC0cw+u2p+lUErE3OY=";
  };

  # All capture plugins and GStreamer libraries must share the host ABI.
  gstLibraries = lib.makeLibraryPath [
    # libspa-videoconvert needs vaMapBuffer2 (bundled libva.so.2 lacks it).
    # libva-minimal defaults to the dev output; force its runtime output.
    pkgs.libva-minimal.out
    pkgs.libayatana-appindicator
    pkgs.glib
    pkgs.gst_all_1.gstreamer
    pkgs.gst_all_1.gst-plugins-base
    pkgs.pipewire
  ];
  gstPlugins = lib.concatStringsSep ":" [
    "${pkgs.pipewire}/lib/gstreamer-1.0"
    "${pkgs.gst_all_1.gst-plugins-base}/lib/gstreamer-1.0"
    "${pkgs.gst_all_1.gst-plugins-good}/lib/gstreamer-1.0"
    "${pkgs.gst_all_1.gst-plugins-bad}/lib/gstreamer-1.0"
  ];

  # AppRun's execvp hook is unsafe on NixOS's long PATH. Keep that hook
  # disabled, but retain an opt-in, GstPipeWireSrc-only fd interceptor so
  # independent GStreamer capture pipelines do not share the same portal socket.
  safeAppRunHooks = pkgs.runCommandCC "rustdesk-151-safe-apprun-hooks" { } ''
    mkdir -p "$out/lib"
    cp ${./rustdesk151-pipewire-fd-hook.c} pipewire-hook.c
    chmod u+w pipewire-hook.c
    printf 'void rustdesk_empty_apprun_hooks(void) {}\n' >> pipewire-hook.c
    "$CC" -shared -fPIC -O2 -Wall -Wextra pipewire-hook.c \
      -o "$out/lib/libapprun_hooks.so" -ldl -pthread
  '';

  # Root --service must be able to start its UID1000 Wayland --server child.
  # The generic AppImage FHS has no sudo PAM service. Use a strictly scoped
  # UID drop instead of adding a password gate or disabling RustDesk IPC auth.
  userLaunch = pkgs.replaceVars ./rustdesk151-sudo-adapter.sh.in {
    inherit (pkgs) bash;
  };
in
pkgs.appimageTools.extractType2 {
  pname = "rustdesk-heimpc";
  inherit version src;
  postExtract = ''
    install -m755 ${safeAppRunHooks}/lib/libapprun_hooks.so \
      "$out/lib/x86_64/libapprun_hooks.so"

    # The bundled systemd loginctl cannot read the current NixOS seat0.
    rm -f "$out/bin/loginctl"
    ln -s ${pkgs.systemd}/bin/loginctl "$out/bin/loginctl"
    install -m755 ${userLaunch} "$out/bin/sudo"

    # RustDesk chooses ScreenCast rather than RemoteDesktop only if its
    # startup process probe can see the running --server executable.
    # The AppImage FHS PATH lacks the ps command and reports a false negative.
    test ! -e "$out/bin/ps"
    ln -s ${pkgs.procps}/bin/ps "$out/bin/ps"

    substituteInPlace "$out/AppRun.env" \
      --replace-fail 'APPDIR_LIBRARY_PATH=' 'APPDIR_LIBRARY_PATH=${gstLibraries}:'

    grep -q '^GST_PLUGIN_PATH=' "$out/AppRun.env"
    grep -q '^GST_PLUGIN_SYSTEM_PATH=' "$out/AppRun.env"
    grep -q '^GST_PLUGIN_SCANNER=' "$out/AppRun.env"
    sed -i "s|^GST_PLUGIN_PATH=.*|GST_PLUGIN_PATH=${gstPlugins}|" "$out/AppRun.env"
    sed -i "s|^GST_PLUGIN_SYSTEM_PATH=.*|GST_PLUGIN_SYSTEM_PATH=${gstPlugins}|" "$out/AppRun.env"
    sed -i 's|^GST_PLUGIN_SCANNER=.*|GST_PLUGIN_SCANNER=${pkgs.gst_all_1.gstreamer.out}/libexec/gstreamer-1.0/gst-plugin-scanner|' "$out/AppRun.env"

    # The RustDesk AppRun server runs without HOME and expands $HOME to empty.
    # Use the fixed UID1000 KDE user's writable registry path, not /.cache.
    printf '\nGST_REGISTRY=/home/alex/.cache/gstreamer-1.0/registry-rustdesk-native151.bin\nSPA_PLUGIN_DIR=${pkgs.pipewire}/lib/spa-0.2\n' >> "$out/AppRun.env"
    test -x "$out/bin/sudo"
    test -x "$out/bin/loginctl"
    test -x "$out/bin/ps"
  '';
}
