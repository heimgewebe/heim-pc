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
    machine.succeed(
        "test -f /etc/systemd/user/heim-pc-storage-pressure-watch.service.d/zz-heim-pc-host-protection.conf"
    )
    machine.succeed(
        "test -f /etc/systemd/user/heim-pc-storage-pressure-watch.timer.d/zz-heim-pc-host-protection.conf"
    )
    machine.succeed("test ! -e /var/lib/systemd/linger/alex")
    machine.fail("systemctl is-active user@1000.service")

    # Reproduce exactly the pre-NixOS installer state: a per-user service and
    # timer main unit. Their presence must block execution without deleting
    # either file; after deliberate fixture cleanup the NixOS unit takes over.
    machine.succeed("install -d -m 0700 -o alex -g users /home/alex/.config/systemd/user")
    machine.succeed(
        "printf '%s\\n' '[Unit]' 'Description=Legacy storage pressure' "
        "'[Service]' 'Type=oneshot' 'ExecStart=${pkgs.coreutils}/bin/false' "
        "> /home/alex/.config/systemd/user/heim-pc-storage-pressure-watch.service"
    )
    machine.succeed(
        "printf '%s\\n' '[Unit]' 'Description=Legacy storage pressure timer' "
        "'[Timer]' 'OnBootSec=1h' 'Unit=heim-pc-storage-pressure-watch.service' "
        "'[Install]' 'WantedBy=timers.target' "
        "> /home/alex/.config/systemd/user/heim-pc-storage-pressure-watch.timer"
    )
    machine.succeed("chown alex:users /home/alex/.config/systemd/user/heim-pc-storage-pressure-watch.service")
    machine.succeed("chown alex:users /home/alex/.config/systemd/user/heim-pc-storage-pressure-watch.timer")
    machine.succeed("chmod 0644 /home/alex/.config/systemd/user/heim-pc-storage-pressure-watch.service")
    machine.succeed("chmod 0644 /home/alex/.config/systemd/user/heim-pc-storage-pressure-watch.timer")

    machine.succeed("systemctl start user@1000.service")
    machine.succeed("systemctl --user --machine=alex@.host daemon-reload")
    machine.succeed(
        "systemctl --user --machine=alex@.host show "
        "heim-pc-storage-pressure-watch.service -p FragmentPath --value "
        "| grep -Fx /home/alex/.config/systemd/user/heim-pc-storage-pressure-watch.service"
    )
    machine.succeed(
        "systemctl --user --machine=alex@.host show "
        "heim-pc-storage-pressure-watch.service -p DropInPaths --value "
        "| grep -F zz-heim-pc-host-protection.conf"
    )
    machine.succeed(
        "systemctl --user --machine=alex@.host start heim-pc-storage-pressure-watch.service"
    )
    machine.succeed(
        "test $(systemctl --user --machine=alex@.host show "
        "heim-pc-storage-pressure-watch.service -p ConditionResult --value) = no"
    )
    machine.fail("test -e /home/alex/.local/state/heim-pc/storage-pressure-watch/latest.json")
    machine.succeed(
        "systemctl --user --machine=alex@.host start heim-pc-storage-pressure-watch.timer"
    )
    machine.succeed(
        "test $(systemctl --user --machine=alex@.host show "
        "heim-pc-storage-pressure-watch.timer -p ConditionResult --value) = no"
    )

    machine.succeed(
        "rm /home/alex/.config/systemd/user/heim-pc-storage-pressure-watch.service "
        "/home/alex/.config/systemd/user/heim-pc-storage-pressure-watch.timer"
    )
    machine.succeed("systemctl --user --machine=alex@.host daemon-reload")
    machine.succeed(
        "systemctl --user --machine=alex@.host show "
        "heim-pc-storage-pressure-watch.service -p ExecStart --value "
        "| grep -F -- --observe-only"
    )
    machine.succeed(
        "systemctl --user --machine=alex@.host start heim-pc-storage-pressure-watch.service"
    )
    machine.succeed(
        "${pkgs.python3}/bin/python3 -c '"
        'import json; '
        'p = json.load(open("/home/alex/.local/state/heim-pc/storage-pressure-watch/latest.json")); '
        'assert p["maintenance_requests_enabled"] is False'
        "'"
    )
  '';
}
