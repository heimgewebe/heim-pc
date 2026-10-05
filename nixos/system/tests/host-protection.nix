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

    # Exercise service credentials and the real sandboxed collector, without
    # coupling this regression to zram sizing or oomd victim-selection policy.
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

    # Root cgroups normally have no memory.events file. The actual service,
    # including its sandbox, must still produce complete core observations.
    machine.fail("test -e /sys/fs/cgroup/memory.events")
    machine.succeed("systemctl start heim-pc-memory-pressure-snapshot.service")
    machine.succeed(
        "${pkgs.python3}/bin/python3 -c '"
        'import json; '
        'p = json.load(open("/var/lib/heim-pc/memory-pressure/latest.json")); '
        'assert p["observation_complete"], p["observation_errors"]; '
        'assert p["root_memory_events_available"] is False; '
        'assert p["severity"] != "unknown"'
        "'"
    )

    # The two user timers are installed globally but intentionally do not gain
    # unattended boot authority through a lingering alex user manager.
    machine.succeed("test -f /etc/systemd/user/heim-pc-storage-pressure-watch.timer")
    machine.succeed("test -f /etc/systemd/user/heim-pc-home-hygiene.timer")
    machine.succeed("test ! -e /var/lib/systemd/linger/alex")
    machine.fail("systemctl is-active user@1000.service")
  '';
}
