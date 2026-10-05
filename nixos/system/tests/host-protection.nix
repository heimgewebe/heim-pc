{ pkgs }:
pkgs.testers.runNixOSTest {
  name = "heim-pc-host-protection";

  nodes.machine = { lib, ... }: {
    imports = [ ../modules/host-protection.nix ];

    networking.hostName = "heim-pc-host-protection-test";
    system.stateVersion = "26.05";
    users.users.alex = {
      isNormalUser = true;
      uid = 1000;
    };
    heimPc.hostProtection.enable = true;

    # This runtime regression is about user/group resolution and session-bound
    # scheduling. Keep unrelated zram/oomd kernel behavior out of the VM proof.
    zramSwap.enable = lib.mkForce false;
    systemd.oomd.enable = lib.mkForce false;

    virtualisation.memorySize = 1024;
    virtualisation.cores = 1;
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    machine.succeed("getent group users")
    machine.succeed(
        "test $(systemctl show heim-pc-pytest-temp-gc.service -p Group --value) = users"
    )
    machine.succeed("systemctl start heim-pc-pytest-temp-gc.service")
    machine.succeed(
        "systemctl show heim-pc-pytest-temp-gc.service -p Result --value | grep -x success"
    )

    # The two user timers are installed globally but intentionally do not gain
    # unattended boot authority through a lingering alex user manager.
    machine.succeed("test -f /etc/systemd/user/heim-pc-storage-pressure-watch.timer")
    machine.succeed("test -f /etc/systemd/user/heim-pc-home-hygiene.timer")
    machine.succeed("test ! -e /var/lib/systemd/linger/alex")
    machine.fail("systemctl is-active user@1000.service")
  '';
}
