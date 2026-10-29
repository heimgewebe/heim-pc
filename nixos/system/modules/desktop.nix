{ config, lib, pkgs, ... }:
let cfg = config.heimPc.desktop; in {
  options.heimPc.desktop.enable = lib.mkEnableOption "KDE Plasma/Wayland workstation profile";
  config = lib.mkIf cfg.enable {
    services.xserver.enable = true;
    services.displayManager.sddm.enable = true;
    services.displayManager.sddm.wayland.enable = true;
    services.desktopManager.plasma6.enable = true;

    # Retain the active Gen19 XRDP password-login KWallet unlock.
    security.pam.services.xrdp-sesman.kwallet = lib.mkIf config.services.xrdp.enable {
      enable = true;
      forceRun = true;
    };

    # Start a separate Plasma X11 desktop through XRDP; keep local Wayland.
    # Do not expose RDP outside the Tailscale overlay network.
    services.xrdp = lib.mkIf config.services.tailscale.enable {
      enable = true;
      defaultWindowManager = "${pkgs.kdePackages.plasma-workspace}/bin/startplasma-x11";
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