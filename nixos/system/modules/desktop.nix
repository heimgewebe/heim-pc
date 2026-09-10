{ config, lib, ... }:
let cfg = config.heimPc.desktop; in {
  options.heimPc.desktop.enable = lib.mkEnableOption "KDE Plasma/Wayland workstation profile";
  config = lib.mkIf cfg.enable {
    services.xserver.enable = true;
    services.displayManager.sddm.enable = true;
    services.displayManager.sddm.wayland.enable = true;
    services.desktopManager.plasma6.enable = true;

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
