{ pkgs, ... }:
let
  readback = pkgs.writeShellApplication {
    name = "grabowski-demo-readback";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      set -eu
      generation="$(readlink -f /run/current-system)"
      if [ -r /etc/heim-pc/source-revision ]; then
        source_revision="$(cat /etc/heim-pc/source-revision)"
      else
        source_revision="prototype-unbound"
      fi
      printf '{"service":"grabowski-demo","source_revision":"%s","generation":"%s"}\n' \
        "$source_revision" "$generation" > "$RUNTIME_DIRECTORY/readback.json"
      printf 'HEIM_PC_RUNTIME_IDENTITY source_revision=%s generation=%s\n' \
        "$source_revision" "$generation"
    '';
  };
  operator = pkgs.writeShellApplication {
    name = "grabowski-demo-operator";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      set -eu
      if [ "$#" -ne 1 ]; then
        echo "exactly one action is required" >&2
        exit 64
      fi
      case "$1" in
        status) cat /run/grabowski-demo/readback.json ;;
        *) echo "action rejected by exact argv contract" >&2; exit 64 ;;
      esac
    '';
  };
in
{
  environment.systemPackages = [ operator ];
  systemd.services.grabowski-demo = {
    description = "Declarative Grabowski runtime-readback prototype";
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${readback}/bin/grabowski-demo-readback";
      DynamicUser = true;
      RuntimeDirectory = "grabowski-demo";
      RuntimeDirectoryMode = "0750";
      NoNewPrivileges = true;
      PrivateTmp = true;
      PrivateDevices = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectControlGroups = true;
      ProtectClock = true;
      RestrictAddressFamilies = [ "AF_UNIX" ];
      RestrictNamespaces = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      SystemCallArchitectures = "native";
      SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
      UMask = "0077";
      StandardOutput = "journal+console";
    };
  };
}