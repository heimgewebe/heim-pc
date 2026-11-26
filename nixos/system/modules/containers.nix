{ lib, pkgs, ... }:
{
  virtualisation.podman = {
    enable = true;
    dockerCompat = true;
    defaultNetwork.settings.dns_enabled = true;

    # Podman 5.8.9 sends conmon MAINPID/READY without waiting for systemd.
    # Keep this backport scoped to the verified version; recheck on upgrade.
    package = pkgs.podman.overrideAttrs (old: {
      patches = (old.patches or [ ]) ++ lib.optional
        (old.version == "5.8.9")
        ./patches/notify-barrier.patch;
    });
  };
}
