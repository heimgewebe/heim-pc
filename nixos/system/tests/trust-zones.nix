{ pkgs }:
pkgs.testers.runNixOSTest {
  name = "heim-pc-trust-zones";
  nodes = {
    control = { pkgs, ... }: {
      networking.firewall.enable = true;
      networking.firewall.allowedTCPPorts = [ 18444 ];
      environment.etc."control-plane-secret".text = "CONTROL_PLANE_ONLY";
      systemd.services.grabowski-broker-boundary = {
        description = "Minimal broker surface for the untrusted agent zone";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig = {
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
          RestrictRealtime = true;
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          ExecStart = "${pkgs.python3}/bin/python -m http.server 18444 --bind 0.0.0.0 --directory ${pkgs.writeTextDir "index.html" "broker-ok"}";
        };
      };
    };
    agent = { pkgs, ... }: {
      networking.firewall.enable = true;
      environment.systemPackages = [ pkgs.curl ];
    };
  };
  testScript = ''
    start_all()
    control.wait_for_unit("grabowski-broker-boundary.service")
    control.wait_for_open_port(18444)

    # Model the worst case inside the agent compartment: attacker has guest root.
    agent.succeed("test $(id -u) -eq 0")

    # Only the deliberately exposed broker protocol is reachable.
    agent.succeed("curl --fail --silent --max-time 3 http://control:18444/ | grep -q broker-ok")
    agent.fail("curl --fail --silent --max-time 2 http://control:22/")

    # Guest root has no filesystem view of the control-plane secret.
    control.succeed("grep -q CONTROL_PLANE_ONLY /etc/control-plane-secret")
    agent.fail("test -e /etc/control-plane-secret")

    control.succeed("test $(systemctl show grabowski-broker-boundary.service -p NoNewPrivileges --value) = yes")
    control.succeed("test $(systemctl show grabowski-broker-boundary.service -p ProtectSystem --value) = strict")
    control.succeed("test $(systemctl show grabowski-broker-boundary.service -p PrivateDevices --value) = yes")
  '';
}
