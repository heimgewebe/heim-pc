{ config, lib, pkgs, ... }:
let
  physicalHost = lib.attrByPath [ "heimPc" "day2Activation" "enable" ] false config;
  production = lib.attrByPath [ "heimPc" "grabowskiProduction" "enable" ] false config;

  # Pasta 2025_09_19.623dbf6 can reject an explicit IPv4 loopback
  # forwarding rule while its selected external network has no IPv4 address.
  # network-online.target alone is not sufficient on the fast-boot desktop.
  waitForPodmanIPv4 = pkgs.writeShellScript "podman-wait-ipv4" ''
    set -eu

    ipv4_ready() {
      local devices device type
      devices=$(LC_ALL=C ${pkgs.networkmanager}/bin/nmcli -t --escape no -f DEVICE,TYPE device status) || return 1
      while IFS=: read -r device type; do
        case "$type" in
          ethernet|wifi)
            if ${pkgs.iproute2}/bin/ip -4 -o address show dev "$device" scope global up |
                ${pkgs.gnugrep}/bin/grep -q ' inet '; then
              return 0
            fi
            ;;
        esac
      done <<< "$devices"
      return 1
    }

    # Do not require Internet access or a default route. A configured IPv4
    # address on an up external interface suffices for the reproduced case.
    # The existing Podman oneshot's 90-second TimeoutStartSec bounds this wait.
    # On a disconnected host the unit fails visibly rather than claiming ready.
    echo "Waiting for physical IPv4 address for rootless Podman"
    until ipv4_ready; do
      ${pkgs.coreutils}/bin/sleep 0.5
    done
    echo "Physical IPv4 address available"
  '';
in
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

  # Extend Podman's existing Quadlet dependency, not the global boot target.
  # Preserve its original ExecStart, timeout and activation ownership.
  systemd.user.services.podman-user-wait-network-online =
    lib.mkIf (physicalHost && production && config.networking.networkmanager.enable) {
      overrideStrategy = "asDropin";
      serviceConfig.ExecStartPost = waitForPodmanIPv4;
    };
}
