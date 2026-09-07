{ pkgs }:
pkgs.testers.runNixOSTest {
  name = "heim-pc-grabowski-bureau";

  nodes.machine = { ... }: {
    # This proof is deliberately narrow: it validates only the Grabowski
    # readback boundary and Bureau authority marker. Development, container,
    # audio, backup and observability closures belong to their own checks.
    imports = [
      ../modules/grabowski.nix
      ../modules/bureau.nix
    ];

    networking.hostName = "heim-pc-test";
    system.stateVersion = "26.05";
    users.users.alex.isNormalUser = true;
    virtualisation.memorySize = 1024;
    virtualisation.cores = 1;
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("systemctl is-active grabowski-demo.service")
    machine.succeed("test -s /run/grabowski-demo/readback.json")
    machine.succeed("grep -q grabowski-demo /run/grabowski-demo/readback.json")
    machine.succeed("test $(stat -c %a /run/grabowski-demo) = 755")
    machine.succeed("test $(stat -c %a /run/grabowski-demo/readback.json) = 644")
    machine.succeed("su -s /bin/sh -c 'grabowski-demo-operator status' alex")
    machine.fail("grabowski-demo-operator definitely-not-allowed")
    machine.succeed("test $(systemctl show grabowski-demo.service -p NoNewPrivileges --value) = yes")
    machine.succeed("test $(systemctl show grabowski-demo.service -p ProtectSystem --value) = strict")
    machine.succeed("test -f /etc/heim-pc/bureau-authority-boundary")
  '';
}
