{ config, lib, ... }:
let cfg = config.heimPc.desktop; in {
 options.heimPc.desktop.enable = lib.mkEnableOption "KDE Plasma/Wayland workstation profile";
 config = lib.mkIf cfg.enable { services.xserver.enable = true; services.displayManager.sddm.enable = true; services.displayManager.sddm.wayland.enable = true; services.desktopManager.plasma6.enable = true; };
}
