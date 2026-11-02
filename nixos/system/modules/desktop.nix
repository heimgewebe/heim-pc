{ config, lib, pkgs, ... }:
let cfg = config.heimPc.desktop; in {
  options.heimPc.desktop.enable = lib.mkEnableOption "KDE Plasma/Wayland workstation profile";
  config = lib.mkIf cfg.enable {
    services.xserver.enable = true;
    services.displayManager.sddm.enable = true;
    services.displayManager.sddm.wayland.enable = true;
    services.desktopManager.plasma6.enable = true;

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

    # Run an Xfce X11 desktop under the dedicated ipad UID; leave local Plasma untouched.
    # Do not expose RDP outside the Tailscale overlay network.
    services.xrdp = lib.mkIf config.services.tailscale.enable {
      enable = true;
      defaultWindowManager = "${pkgs.xfce4-session}/bin/startxfce4";
      openFirewall = false;
    };
    networking.firewall.interfaces."tailscale0".allowedTCPPorts =
      lib.optionals config.services.tailscale.enable [ 3389 ];

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