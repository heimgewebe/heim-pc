{ config, lib, pkgs, ... }:
let
  cfg = config.heimPc.desktop;
  rustdesk151AppDir = import ./rustdesk151-appdir.nix { inherit pkgs; };
  rustdeskGrantSync = import ./rustdesk-screen-grant-package.nix { inherit pkgs; };
  # DrKonqi 6.6.6's startup --pickup stays idle when stale crash metadata
  # has no retained core file. Quit when the journal replay reaches EOF.
  drkonqiPickup = pkgs.kdePackages.drkonqi.overrideAttrs (old: {
    patches = (old.patches or []) ++ [
      ./patches/drkonqi-6.6.6-pickup-at-log-end.patch
    ];
  });
in {
  options.heimPc.desktop.enable = lib.mkEnableOption "KDE Plasma/Wayland workstation profile";
  config = lib.mkIf cfg.enable {
    services.xserver.enable = true;
    services.displayManager.sddm.enable = true;
    services.displayManager.sddm.wayland.enable = true;

    # The real alex KDE/Wayland session must exist after unattended reboot
    # so the current desktop remains reachable through the native KRDP service.
    # SDDM autologin is local-only; remote RDP is still bound to Tailscale.
    services.displayManager.autoLogin.enable = true;
    services.displayManager.autoLogin.user = "alex";
    services.displayManager.sddm.settings.Autologin.Relogin = true;
    services.desktopManager.plasma6.enable = true;

    # Plasma enables the KDE native host, but Chrome only receives its manifest
    # when the Chromium-based browser policy module is enabled as well.
    programs.chromium.enable = true;
    # Auto-install Plasma Integration while retaining the user's ability to
    # disable it. Unlike programs.chromium.extensions this is not force-installed.
    programs.chromium.extraOpts.ExtensionSettings."cimiefiiaegbelhefglklhhakcgmhkai" = {
      installation_mode = "normal_installed";
      update_url = "https://clients2.google.com/service/update2/crx";
    };

    # The local dual-monitor workstation remains Plasma/Wayland.
    # Xfce supplies a lightweight, independent X11 session for iPad XRDP.
    services.xserver.desktopManager.xfce.enable = true;
    services.displayManager.defaultSession = "plasma";

    # A separate UID is required: concurrent graphical sessions of the same
    # systemd user share the session bus, clipboard services, and focus state.
    # Never put a password into this public NixOS source or the Nix store.
    users.users.ander = {
      isNormalUser = true;
      uid = 1001;
      description = "Independent remote desktop (ander)";
      packages = [ pkgs.google-chrome ]; # Browser only in the remote user profile.
    };

    # Retain the active Gen19 XRDP password-login KWallet unlock.
    security.pam.services.xrdp-sesman.kwallet = lib.mkIf config.services.xrdp.enable {
      enable = true;
      forceRun = true;
    };

    # Alex's standalone Plasma/X11 fallback must not compete with his live
    # Wayland session for shared KDE user services and org.kde.KWin on D-Bus.
    # Concurrent remote control of the real alex desktop uses KRDP instead.
    # The separate ander account keeps its independent Xfce desktop.
    # Do not expose RDP outside the Tailscale overlay network.
    services.xrdp = lib.mkIf config.services.tailscale.enable {
      enable = true;
      defaultWindowManager = "${pkgs.writeShellScript "xrdp-window-manager-by-user" ''
        if [ "$(${pkgs.coreutils}/bin/id -un)" = alex ]; then
          if [ -S "/run/user/$(${pkgs.coreutils}/bin/id -u)/wayland-0" ]; then
            printf '%s\n' 'XRDP Plasma/X11 unavailable while alex Wayland is active; use KRDP for the live desktop.' >&2
            exit 1
          fi
          exec ${pkgs.kdePackages.plasma-workspace}/bin/startplasma-x11
        else
          exec ${pkgs.xfce4-session}/bin/startxfce4
        fi
      ''}";
      openFirewall = false;
    };
    networking.firewall.interfaces."tailscale0".allowedTCPPorts =
      lib.optionals config.services.tailscale.enable [ 3389 ];

    # Root RustDesk 1.5.1 owns its one Wayland UID1000 --server child.
    # The AppImage is hash-verified, with the native PipeWire/GStreamer
    # plugin set, safe AppRun hook, NixOS loginctl and a limited UID drop.
    # The old per-user rustdesk-session.service must not be enabled.
    systemd.services.rustdesk-host = {
      description = "RustDesk 1.5.1 host helper for KDE Wayland";
      wantedBy = [ "multi-user.target" ];
      conflicts = [ "rustdesk-host-test.service" ];
      after = [ "network.target" ];
      serviceConfig = {
        Type = "exec";
        ExecStart = "${pkgs.appimage-run}/bin/appimage-run -w ${rustdesk151AppDir} -- --service";
        # Keep each PipeWire capture stream on its own independent connection.
        Environment = [ "RUSTDESK_PIPEWIRE_SYSTEM_SOCKET=1" ];
        Restart = "on-failure";
        RestartSec = "3s";
      };
    };

    # RustDesk ScreenCast restoration must survive DP-1 hotplug. This is a
    # session-scoped watcher, not an additional RustDesk server.
    systemd.user.services.rustdesk-screen-grant-sync = {
      description = "Keep RustDesk ScreenCast grant aligned to KDE Wayland outputs";
      # kscreen-doctor is launched by QProcess and systemd's user PATH is minimal.
      path = [ pkgs.kdePackages.kscreen ];
      wantedBy = [ "graphical-session.target" ];
      after = [ "plasma-kwin_wayland.service" ];
      partOf = [ "graphical-session.target" ];
      unitConfig.ConditionUser = "alex";
      serviceConfig = {
        Type = "simple";
        ExecStart = "${rustdeskGrantSync}/bin/rustdesk-kde-screen-grant-sync --watch";
        Environment = [
          "QT_QPA_PLATFORM=wayland"
          "QT_QPA_PLATFORM_PLUGIN_PATH=${pkgs.qt6.qtwayland}/lib/qt-6/plugins/platforms"
          "WAYLAND_DISPLAY=wayland-0"
          "XDG_RUNTIME_DIR=/run/user/1000"
          "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"
        ];
        Restart = "on-failure";
        RestartSec = "3s";
      };
    };

    # Repair only the finite login-time replay: if all historical core
    # files have expired, DrKonqi must terminate at journal EOF rather than
    # idle until KDE's 30-minute RuntimeMaxSec failure. The socket-activated
    # per-crash launcher and normal KDE crash reporting stay unchanged.
    systemd.user.services."drkonqi-coredump-pickup" = {
      overrideStrategy = "asDropin";
      serviceConfig.ExecStart = lib.mkForce [
        ""
        "${drkonqiPickup}/libexec/drkonqi-coredump-processor --settle-first --pickup --uid %U"
      ];
    };

    # A headless systemd --user manager has no Qt display. Without this guard,
    # one Node crash recursively launched 3600 aborting DrKonqi instances.
    # Preserve graphical DrKonqi when Plasma imports its display environment.
    systemd.user.services."drkonqi-coredump-launcher@" = {
      overrideStrategy = "asDropin";
      unitConfig.ConditionEnvironment = [ "|DISPLAY" "|WAYLAND_DISPLAY" ];
      # Non-KDE crashes can leave GUI reporters open indefinitely and exhaust
      # the socket's 16 slots. Keep interactive reporting, but bound its lifetime.
      serviceConfig.RuntimeMaxSec = "15min";
    };

    # Prevent idle-triggered sleep/shutdown while preserving explicit suspend.
    # Manual suspend is required by the physical GPU/audio acceptance gates.
    services.logind.settings.Login.IdleAction = "ignore";

    # Plasma 6 PowerDevil owns its own idle action. Lock only that automatic
    # action to "none" in the system-wide KConfig cascade; explicit power-menu
    # suspend remains available for requested/manual operation and gate proofs.
    environment.etc."xdg/powerdevilrc".text = ''
      [AC][SuspendAndShutdown]
      AutoSuspendAction[$i]=0
      [Battery][SuspendAndShutdown]
      AutoSuspendAction[$i]=0
      [LowBattery][SuspendAndShutdown]
      AutoSuspendAction[$i]=0
    '';
  };
}