{ pkgs, ... }:
{
  # Test-only proof that the no-IP agent zone can still use its single declared
  # host capability transport. The production zone does not depend on a broker
  # being present at boot; this module is instantiated only by the proof build.
  systemd.services.agent-zone-vsock-proof = {
    description = "Prove the agent-zone VSOCK capability broker path";
    wantedBy = [ "multi-user.target" ];
    after = [ "agent-zone-contract-proof.service" ];
    requires = [ "agent-zone-contract-proof.service" ];
    serviceConfig = {
      Type = "oneshot";
      DynamicUser = true;
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateDevices = true;
      PrivateTmp = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectControlGroups = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      RestrictAddressFamilies = [ "AF_UNIX" "AF_VSOCK" ];
      ExecStart = pkgs.writeShellScript "agent-zone-vsock-proof" ''
        set -eu
        response="$(${pkgs.bash}/bin/bash -c 'printf "broker.status\\n" | ${pkgs.socat}/bin/socat -T 5 - VSOCK-CONNECT:2:18446')"
        test "$response" = "broker-ok"
      '';
    };
  };
}
